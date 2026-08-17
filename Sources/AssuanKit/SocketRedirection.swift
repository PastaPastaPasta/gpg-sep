import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// GnuPG's `%Assuan%` socket redirection files.
///
/// When the socket cannot live at the advertised path — on macOS almost always
/// because `sockaddr_un.sun_path` is a mere 104 bytes — GnuPG writes a plain
/// *file* there instead of a socket:
///
/// ```
/// %Assuan%
/// socket=/private/tmp/gpg-abc123/S.gpg-agent
/// ```
///
/// A client that opens `~/.gnupg/S.gpg-agent`, finds a regular file with that
/// magic, and connects to the named socket instead. Both lines end in a single
/// LF, there is no whitespace anywhere, extra lines are rejected, and `${VAR}`
/// in the name is expanded from the environment. The whole file is capped at
/// 511 bytes.
///
/// Transcribed from `eval_redirection` in libassuan's `assuan-socket.c`; the
/// proxy needs both halves, since it must *read* the file gpg wrote and may
/// have to *write* one of its own when it takes over `S.gpg-agent`.
public enum AssuanSocketRedirection {
    /// The magic header plus the `socket=` key, exactly as libassuan memcmps it.
    public static let magic = "%Assuan%\nsocket="
    /// libassuan reads at most 511 bytes of a redirection file.
    public static let maxFileLength = 511

    /// If `path` names a redirection file, the socket path it points at.
    ///
    /// Returns `nil` when `path` is not a regular file or lacks the magic —
    /// i.e. when it is an ordinary socket that should be connected to directly.
    ///
    /// - Throws: ``AssuanIOError`` if the magic is present but the rest is
    ///   malformed.
    public static func target(ofFileAt path: String) throws -> String? {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        let bytes = [UInt8](handle.readData(ofLength: maxFileLength))
        let magicBytes = Array(magic.utf8)
        // libassuan requires at least 17 bytes: the 16-byte header plus one
        // byte of name.
        guard bytes.count >= magicBytes.count + 1, bytes.starts(with: magicBytes) else {
            return nil
        }
        guard bytes.last == 0x0A else {
            throw AssuanIOError("redirection file \(path) does not end with LF")
        }
        guard bytes[magicBytes.count] != 0x0A else {
            throw AssuanIOError("redirection file \(path) has an empty socket name")
        }
        let name = String(decoding: bytes[magicBytes.count..<(bytes.count - 1)], as: UTF8.self)
        guard !name.contains("\n") else {
            throw AssuanIOError("redirection file \(path) has extra lines")
        }
        let expanded = try expandEnvironment(in: name, source: path)
        guard expanded.utf8.count < AssuanListener.maxPathLength else {
            throw AssuanIOError(
                "redirection target is \(expanded.utf8.count) bytes, too long for sun_path")
        }
        return expanded
    }

    /// Resolve `path` to the socket that should actually be connected to:
    /// the redirection target if there is one, otherwise `path` itself.
    public static func resolve(_ path: String) throws -> String {
        try target(ofFileAt: path) ?? path
    }

    /// Write a redirection file at `path` pointing at `socketPath`.
    ///
    /// Created with mode `0o600`, replacing whatever was there (including a
    /// live socket, which cannot simply be written over).
    public static func write(at path: String, socketPath: String) throws {
        guard !socketPath.contains("\n") else {
            throw AssuanIOError("socket name must not contain LF")
        }
        guard !socketPath.isEmpty else {
            throw AssuanIOError("socket name must not be empty")
        }
        let contents = Data("\(magic)\(socketPath)\n".utf8)
        guard contents.count <= maxFileLength else {
            throw AssuanIOError(
                "redirection file would be \(contents.count) bytes, limit is \(maxFileLength)")
        }
        unlink(path)
        guard FileManager.default.createFile(
            atPath: path, contents: contents, attributes: [.posixPermissions: 0o600]
        ) else {
            throw AssuanIOError("could not create \(path)", errno: errno)
        }
    }

    private static func expandEnvironment(in name: String, source: String) throws -> String {
        guard name.contains("${") else { return name }
        var out = ""
        var rest = Substring(name)
        while let open = rest.range(of: "${") {
            out += rest[rest.startIndex..<open.lowerBound]
            let afterOpen = rest[open.upperBound...]
            guard let close = afterOpen.firstIndex(of: "}") else {
                throw AssuanIOError("redirection file \(source) has an unterminated ${...}")
            }
            let variable = String(afterOpen[afterOpen.startIndex..<close])
            if !variable.isEmpty, let value = ProcessInfo.processInfo.environment[variable] {
                out += value
            }
            rest = afterOpen[afterOpen.index(after: close)...]
        }
        return out + rest
    }
}

extension AssuanConnection {
    /// Connect to `path`, following a `%Assuan%` redirection file if that is
    /// what `path` turns out to be.
    ///
    /// This is what a client should use for `~/.gnupg/S.gpg-agent`: GnuPG puts
    /// a redirection file there whenever the home directory's path is too long
    /// for `sun_path`, which on macOS is common.
    public static func connectFollowingRedirection(to path: String) throws -> AssuanConnection {
        try connect(toUnixSocket: AssuanSocketRedirection.resolve(path))
    }
}
