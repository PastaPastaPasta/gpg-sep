import Foundation
#if canImport(Darwin)
import Darwin
#endif
import AssuanKit

/// Manages the stock `gpg-agent` the proxy forwards non-enclave traffic to.
///
/// The proxy owns `~/.gnupg/S.gpg-agent`, so the real agent has to live
/// somewhere else or the two would fight over the same socket path. We run it
/// under a *backend home* whose key material, config and smartcard access are
/// symlinks back into the real `~/.gnupg`, so passphrase/PIN caching and
/// scdaemon/YubiKey behaviour are exactly as before.
///
/// For tests, ``init(existingSocketPath:)`` skips lifecycle management entirely
/// and just points the proxy at an already-running agent socket.
public final class BackendAgent {
    /// The Unix socket the proxy connects to. Non-nil once ``start()`` has run
    /// (or immediately, for the injected-socket initializer).
    public private(set) var socketPath: String?

    private let backendHome: URL?
    private let realGnupgHome: URL?
    private let gpgAgentPath: String
    private let gpgconfPath: String
    private let managesLifecycle: Bool

    /// Files linked from the real home into the backend home so the backend
    /// agent sees the same keys, config, and smartcard setup.
    private static let linkedEntries = [
        "private-keys-v1.d",
        "gpg-agent.conf",
        "sshcontrol",
        "scdaemon.conf",
        "pubring.kbx",
        "trustdb.gpg",
    ]

    /// Test / advanced use: forward to an agent already listening at
    /// `socketPath`; ``start()`` and ``stop()`` are no-ops.
    public init(existingSocketPath socketPath: String) {
        self.socketPath = socketPath
        self.backendHome = nil
        self.realGnupgHome = nil
        self.gpgAgentPath = ""
        self.gpgconfPath = ""
        self.managesLifecycle = false
    }

    /// Manage a stock gpg-agent under `backendHome`, mirroring `realGnupgHome`.
    public init(
        backendHome: URL,
        realGnupgHome: URL,
        gpgAgentPath: String = "/opt/homebrew/bin/gpg-agent",
        gpgconfPath: String = "/opt/homebrew/bin/gpgconf"
    ) {
        self.socketPath = nil
        self.backendHome = backendHome
        self.realGnupgHome = realGnupgHome
        self.gpgAgentPath = gpgAgentPath
        self.gpgconfPath = gpgconfPath
        self.managesLifecycle = true
    }

    /// The default backend home: `$GPG_SEP_HOME/backend-home`, else
    /// `~/.local/share/gpg-sep/backend-home`.
    public static func defaultBackendHome() -> URL {
        if let override = ProcessInfo.processInfo.environment["GPG_SEP_HOME"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
                .appendingPathComponent("backend-home", isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/share/gpg-sep/backend-home", isDirectory: true)
    }

    /// The user's real GnuPG home (`$GNUPGHOME` or `~/.gnupg`).
    public static func defaultRealGnupgHome() -> URL {
        if let override = ProcessInfo.processInfo.environment["GNUPGHOME"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".gnupg", isDirectory: true)
    }

    /// Create/refresh the backend home, launch the agent, and discover its
    /// socket. Idempotent for the injected-socket case.
    public func start() throws {
        guard managesLifecycle, let backendHome, let realGnupgHome else { return }

        try FileManager.default.createDirectory(
            at: backendHome, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])

        for entry in Self.linkedEntries {
            let source = realGnupgHome.appendingPathComponent(entry)
            let dest = backendHome.appendingPathComponent(entry)
            guard FileManager.default.fileExists(atPath: source.path) else { continue }
            // Replace anything already at the destination that is not the link
            // we want, then (re)create the symlink.
            let existing = try? FileManager.default.destinationOfSymbolicLink(atPath: dest.path)
            if existing == source.path { continue }
            try? FileManager.default.removeItem(at: dest)
            try FileManager.default.createSymbolicLink(at: dest, withDestinationURL: source)
        }

        // Launch the daemon; it forks and exits, leaving the agent running.
        try runTool(gpgAgentPath, ["--homedir", backendHome.path, "--daemon"])

        // Discover the socket and wait for it to appear.
        let discovered = try discoverSocket()
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            var st = stat()
            if lstat(discovered, &st) == 0, (st.st_mode & S_IFMT) == S_IFSOCK {
                socketPath = discovered
                return
            }
            usleep(50_000)
        }
        throw BackendError("backend gpg-agent socket never appeared at \(discovered)")
    }

    /// Stop the managed backend agent. No-op for the injected-socket case.
    public func stop() {
        guard managesLifecycle, let backendHome else { return }
        _ = try? runTool(gpgconfPath, ["--homedir", backendHome.path, "--kill", "gpg-agent"])
    }

    private func discoverSocket() throws -> String {
        guard let backendHome else { throw BackendError("no backend home") }
        let out = try captureTool(
            gpgconfPath, ["--homedir", backendHome.path, "--list-dirs", "agent-socket"])
        let path = out.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty else { throw BackendError("gpgconf returned no agent-socket path") }
        return path
    }

    // MARK: - Subprocess helpers

    public struct BackendError: Error, CustomStringConvertible {
        public let message: String
        public init(_ message: String) { self.message = message }
        public var description: String { message }
    }

    @discardableResult
    private func runTool(_ path: String, _ args: [String]) throws -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        return p.terminationStatus
    }

    private func captureTool(_ path: String, _ args: [String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }
}
