import Foundation
#if canImport(Darwin)
import Darwin
#endif

public struct AssuanIOError: Error, Equatable {
    public let message: String
    public let errnoValue: Int32
    public init(_ message: String, errno: Int32 = 0) {
        self.message = message
        self.errnoValue = errno
    }
}

/// A connected Assuan endpoint over a blocking stream socket fd.
///
/// One connection per handler: I/O is blocking, EINTR/EAGAIN are retried, and
/// lines split across `recv` boundaries are reassembled by an internal buffer.
/// Concurrency is expected to live a layer up (one GCD/thread per connection).
public final class AssuanConnection {
    public let fd: Int32
    private var ownsFD: Bool
    private var inbuf: [UInt8] = []
    private var scanned = 0 // how far into inbuf we've searched for '\n'
    private var closed = false

    /// Largest accepted line *content*, terminator excluded.
    ///
    /// Defaults to libassuan's own ceiling (``AssuanLimits/maxLineContent``,
    /// 1001 = `ASSUAN_LINELENGTH - 1`): a peer that sends more than this has
    /// already lost sync, and libassuan on the other side would have refused it
    /// too. Raise it only when deliberately talking to a non-conforming peer.
    public var maxLineLength = AssuanLimits.maxLineContent

    public init(fd: Int32, ownsFD: Bool = true) {
        self.fd = fd
        self.ownsFD = ownsFD
    }

    deinit { close() }

    public func close() {
        guard !closed else { return }
        closed = true
        if ownsFD { _ = Darwin.close(fd) }
    }

    // MARK: Connecting

    /// Connect to an existing Unix-domain stream socket (e.g. gpg-agent's
    /// `S.gpg-agent`). The fd is left in blocking mode.
    public static func connect(toUnixSocket path: String) throws -> AssuanConnection {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw AssuanIOError("socket() failed", errno: errno) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            _ = Darwin.close(fd)
            throw AssuanIOError("socket path too long")
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { p in
            p.withMemoryRebound(to: UInt8.self, capacity: pathBytes.count) { dst in
                for (i, b) in pathBytes.enumerated() { dst[i] = b }
                dst[pathBytes.count] = 0
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, len)
            }
        }
        guard rc == 0 else {
            let e = errno
            _ = Darwin.close(fd)
            throw AssuanIOError("connect() to \(path) failed", errno: e)
        }
        AssuanListener.suppressSIGPIPE(fd)
        return AssuanConnection(fd: fd)
    }

    /// A connected pair of endpoints over `socketpair(2)`, handy for tests and
    /// for wiring an in-process client to an in-process server.
    public static func makePair() throws -> (AssuanConnection, AssuanConnection) {
        var fds: [Int32] = [0, 0]
        let rc = socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
        guard rc == 0 else { throw AssuanIOError("socketpair() failed", errno: errno) }
        fds.forEach(AssuanListener.suppressSIGPIPE)
        return (AssuanConnection(fd: fds[0]), AssuanConnection(fd: fds[1]))
    }

    // MARK: Reading

    /// Read the next line's raw bytes (newline stripped, plus a trailing CR if
    /// present). Returns nil at clean EOF. Throws on I/O error or overlength.
    public func readRawLine() throws -> [UInt8]? {
        while true {
            if let nl = indexOfNewline() {
                let line = Array(inbuf[0..<nl])
                inbuf.removeSubrange(0...nl) // drop line + '\n'
                scanned = 0
                guard line.count <= maxLineLength else {
                    throw AssuanIOError("line of \(line.count) bytes exceeds \(maxLineLength)")
                }
                return stripCR(line)
            }
            // No terminator yet. libassuan gives up once its whole line buffer
            // is full without an LF, and so do we.
            if inbuf.count > maxLineLength {
                throw AssuanIOError("line exceeds \(maxLineLength) bytes with no terminator")
            }
            let got = try fillBuffer()
            if got == 0 {
                // EOF. Return any trailing unterminated bytes once, then nil.
                if inbuf.isEmpty { return nil }
                let line = inbuf
                inbuf = []
                scanned = 0
                return stripCR(line)
            }
        }
    }

    /// Read + parse the next line as a server response (client-side use).
    public func readResponseLine() throws -> AssuanLine? {
        guard let raw = try readRawLine() else { return nil }
        return try AssuanLine.parseResponse(raw)
    }

    /// Read + parse the next line as a client command (server-side use).
    public func readCommandLine() throws -> AssuanLine? {
        guard let raw = try readRawLine() else { return nil }
        return try AssuanLine.parseCommand(raw)
    }

    private func indexOfNewline() -> Int? {
        var i = scanned
        while i < inbuf.count {
            if inbuf[i] == 0x0A { return i }
            i += 1
        }
        scanned = inbuf.count
        return nil
    }

    private func stripCR(_ line: [UInt8]) -> [UInt8] {
        if line.last == 0x0D { return Array(line.dropLast()) }
        return line
    }

    private func fillBuffer() throws -> Int {
        var chunk = [UInt8](repeating: 0, count: 8192)
        while true {
            let n = chunk.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
            if n < 0 {
                if errno == EINTR { continue }
                throw AssuanIOError("recv() failed", errno: errno)
            }
            if n > 0 { inbuf.append(contentsOf: chunk[0..<n]) }
            return n
        }
    }

    // MARK: Writing

    /// Write raw bytes followed by a single `\n`, retrying short writes.
    ///
    /// libassuan only ever emits a bare LF, never CRLF, even though it accepts
    /// both — so we do the same. An embedded CR or LF would split the line and
    /// desynchronise the peer, and a line past ``maxLineLength`` would be
    /// rejected by a libassuan peer, so both are refused here rather than sent.
    public func writeLineBytes(_ payload: Data) throws {
        guard payload.count <= maxLineLength else {
            throw AssuanIOError("outbound line of \(payload.count) bytes exceeds \(maxLineLength)")
        }
        guard !payload.contains(0x0A), !payload.contains(0x0D) else {
            throw AssuanIOError("outbound line contains CR or LF")
        }
        var out = [UInt8](payload)
        out.append(0x0A)
        try writeAll(out)
    }

    /// Serialize and write an `AssuanLine` with its terminating newline.
    public func write(_ line: AssuanLine) throws {
        try writeLineBytes(line.serialize())
    }

    private func writeAll(_ bytes: [UInt8]) throws {
        var offset = 0
        try bytes.withUnsafeBytes { buf in
            let base = buf.baseAddress!
            while offset < bytes.count {
                let n = send(fd, base + offset, bytes.count - offset, 0)
                if n < 0 {
                    if errno == EINTR || errno == EAGAIN { continue }
                    throw AssuanIOError("send() failed", errno: errno)
                }
                offset += n
            }
        }
    }
}
