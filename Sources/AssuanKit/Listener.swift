import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// A listening Unix-domain socket for an Assuan server.
///
/// BSD sockets rather than Network.framework: `NWListener` cannot bind a
/// caller-chosen `AF_UNIX` path in the way gpg's clients require, and we need
/// `SOL_LOCAL` peer credentials anyway.
///
/// The path limit is the real constraint on macOS: `sockaddr_un.sun_path` is
/// 104 bytes, and `$TMPDIR` under a sandboxed process routinely eats 60 of
/// them. When a path does not fit, put the socket somewhere short and drop an
/// ``AssuanSocketRedirection`` file at the advertised location.
public final class AssuanListener {
    /// Size of `sockaddr_un.sun_path` on this platform, NUL included (104).
    public static let maxPathLength = MemoryLayout.size(ofValue: sockaddr_un().sun_path)

    public let path: String
    public private(set) var fd: Int32
    private var closed = false
    private var unlinked = false
    private let lock = NSLock()

    /// Bind and listen on `path`.
    ///
    /// - Parameters:
    ///   - path: the socket path; must be shorter than ``maxPathLength``.
    ///   - permissions: mode applied to the socket inode. `0o600` matches what
    ///     gpg-agent ends up with, and keeps other users out regardless of the
    ///     directory's mode.
    ///   - replaceStale: unlink an existing socket at `path` first. Only an
    ///     inode that really is a socket is removed, so a mistyped path can
    ///     never destroy a regular file.
    ///   - backlog: `listen(2)` backlog.
    public init(
        path: String,
        permissions: mode_t = 0o600,
        replaceStale: Bool = true,
        backlog: Int32 = 64
    ) throws {
        self.path = path
        var addr = try Self.makeAddress(path: path)

        if replaceStale {
            var st = stat()
            if lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFSOCK {
                unlink(path)
            }
        }

        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { throw AssuanIOError("socket() failed", errno: errno) }
        self.fd = sock
        AssuanListener.suppressSIGPIPE(sock)

        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(sock, $0, len) }
        }
        guard bound == 0 else {
            let e = errno
            _ = Darwin.close(sock)
            closed = true
            throw AssuanIOError("bind(\(path)) failed", errno: e)
        }
        guard chmod(path, permissions) == 0 else {
            let e = errno
            closeAndUnlink()
            throw AssuanIOError("chmod(\(path)) failed", errno: e)
        }
        guard listen(sock, backlog) == 0 else {
            let e = errno
            closeAndUnlink()
            throw AssuanIOError("listen(\(path)) failed", errno: e)
        }
    }

    deinit { closeAndUnlink() }

    /// Accept one connection, or `nil` once the listener has been closed.
    public func accept() throws -> AssuanConnection? {
        while true {
            let conn = Darwin.accept(fd, nil, nil)
            if conn >= 0 {
                AssuanListener.suppressSIGPIPE(conn)
                return AssuanConnection(fd: conn)
            }
            switch errno {
            case EINTR, ECONNABORTED:
                continue
            case EBADF, EINVAL, ENOTSOCK:
                return nil // closed underneath us: a normal shutdown
            default:
                throw AssuanIOError("accept() failed", errno: errno)
            }
        }
    }

    /// Accept in a loop, running `handler` for each connection on its own
    /// thread. Blocks until the listener is closed.
    ///
    /// One thread per connection is what gpg-agent does, and it is what the
    /// proxy needs: a Secure Enclave signature can block for as long as the
    /// user takes to touch Touch ID, and that must not stall other clients.
    public func serveForever(_ handler: @escaping (AssuanConnection) -> Void) throws {
        while let conn = try accept() {
            let thread = Thread { handler(conn) }
            thread.name = "assuan-connection"
            thread.stackSize = 512 * 1024
            thread.start()
        }
    }

    /// Close the listening fd and remove the socket from the filesystem.
    /// A thread blocked in ``accept()`` returns `nil` shortly after.
    public func closeAndUnlink() {
        lock.lock()
        defer { lock.unlock() }
        if !closed {
            closed = true
            _ = Darwin.close(fd)
        }
        if !unlinked {
            unlinked = true
            var st = stat()
            if lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFSOCK {
                unlink(path)
            }
        }
    }

    static func makeAddress(path: String) throws -> sockaddr_un {
        let bytes = Array(path.utf8)
        guard bytes.count < maxPathLength else {
            throw AssuanIOError(
                "socket path is \(bytes.count) bytes, limit is \(maxPathLength - 1): \(path)")
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        return addr
    }

    /// Writing to a socket whose peer has gone away raises SIGPIPE, which kills
    /// the default-disposition process. A long-lived agent must never die that
    /// way, so every socket we own gets `SO_NOSIGPIPE`.
    static func suppressSIGPIPE(_ fd: Int32) {
        var on: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    }
}

extension AssuanConnection {
    /// The peer's process ID (`SOL_LOCAL` / `LOCAL_PEERPID`).
    ///
    /// Note this is *not* the number in libassuan's greeting: `assuan_accept`
    /// uses `getpid()` there. This is genuinely the client's PID, which is what
    /// a policy layer wants when deciding whether to prompt for a signature.
    public var peerProcessID: pid_t? {
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0 else { return nil }
        return pid
    }

    /// The peer's effective UID (`LOCAL_PEERCRED` / `struct xucred`).
    ///
    /// The Assuan manual requires a server to verify this rather than trust
    /// socket permissions, which are not enforced uniformly across platforms.
    public var peerUserID: uid_t? {
        var cred = xucred()
        var size = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &cred, &size) == 0,
              cred.cr_version == XUCRED_VERSION
        else { return nil }
        return cred.cr_uid
    }

    /// True when the peer runs as this process's user, or when the kernel will
    /// not say (in which case the socket's mode is the only defence left).
    public var peerIsSameUser: Bool {
        guard let uid = peerUserID else { return true }
        return uid == getuid()
    }
}
