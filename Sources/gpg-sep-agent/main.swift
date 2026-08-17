import Foundation
#if canImport(Darwin)
import Darwin
#endif
import AssuanKit
import SEPKit
import GPGSepDaemonCore

// gpg-sep-agent: the keygrip-routed gpg-agent proxy. All routing logic lives in
// GPGSepDaemonCore; this entry point only wires up the store, the backend
// agent, and the listener, then installs signal handlers.

func toolPath(_ name: String) -> String {
    for candidate in ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)", "/usr/bin/\(name)"]
    where FileManager.default.isExecutableFile(atPath: candidate) {
        return candidate
    }
    return "/usr/bin/\(name)"
}

func standardAgentSocket(gpgconf: String) -> String {
    // Allow an explicit override via argument for tests/installs.
    let args = CommandLine.arguments
    if let idx = args.firstIndex(of: "--socket"), idx + 1 < args.count {
        return args[idx + 1]
    }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: gpgconf)
    p.arguments = ["--list-dirs", "agent-socket"]
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    try? p.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}

func killStandardAgent(gpgconf: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: gpgconf)
    p.arguments = ["--kill", "gpg-agent"]
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    try? p.run()
    p.waitUntilExit()
}

let gpgconf = toolPath("gpgconf")
let gpgAgent = toolPath("gpg-agent")

let socketPath = standardAgentSocket(gpgconf: gpgconf)
guard !socketPath.isEmpty else {
    FileHandle.standardError.write(Data("gpg-sep-agent: could not determine agent socket\n".utf8))
    exit(1)
}

// Single-instance guard, taken BEFORE we kill the stock agent: two gpg-sep-agents
// racing here would have the second kill the first's freshly-started backend and
// clobber its socket. If another instance already holds the lock, bail out.
let instanceLock: InstanceLock
do {
    guard let lock = try InstanceLock.tryAcquire(path: socketPath + ".gpg-sep.lock") else {
        FileHandle.standardError.write(Data(
            "gpg-sep-agent: another instance is already running; exiting\n".utf8))
        exit(0)
    }
    instanceLock = lock
} catch {
    FileHandle.standardError.write(Data("gpg-sep-agent: \(error)\n".utf8))
    exit(1)
}

// Free the standard socket so we can bind it; gpg's autostart will then find our
// live socket and stay out of the way.
killStandardAgent(gpgconf: gpgconf)

let keyStore = KeyStore()
let config = (try? Config.load()) ?? Config()
let authSession = AuthSession(defaultGraceSeconds: config.defaultPolicy.graceSeconds)

let backend = BackendAgent(
    backendHome: BackendAgent.defaultBackendHome(),
    realGnupgHome: BackendAgent.defaultRealGnupgHome(),
    gpgAgentPath: gpgAgent,
    gpgconfPath: gpgconf
)

do {
    // Best-effort initial start; the serve path re-ensures the backend per
    // connection, so a transient failure here no longer bricks enclave signing.
    try? backend.start()
    let server = try SepAgentServer(
        standardSocketPath: socketPath,
        keyStore: keyStore,
        authSession: authSession,
        backend: backend
    )

    // Clean shutdown on SIGTERM/SIGINT: drop the socket and stop the backend.
    let shutdown: @convention(c) (Int32) -> Void = { _ in
        SignalContext.server?.stop()
        SignalContext.backend?.stop()
        exit(0)
    }
    SignalContext.server = server
    SignalContext.backend = backend
    SignalContext.instanceLock = instanceLock // keep the lock held for our lifetime
    signal(SIGTERM, shutdown)
    signal(SIGINT, shutdown)

    try server.run()
} catch {
    FileHandle.standardError.write(Data("gpg-sep-agent: \(error)\n".utf8))
    backend.stop()
    exit(1)
}

/// Holds references the C signal trampoline can reach (it cannot capture state).
enum SignalContext {
    static var server: SepAgentServer?
    static var backend: BackendAgent?
    static var instanceLock: InstanceLock?
}
