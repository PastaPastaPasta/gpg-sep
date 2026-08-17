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
    try backend.start()
    guard let backendSocket = backend.socketPath else {
        throw BackendAgent.BackendError("backend agent produced no socket")
    }
    let server = try SepAgentServer(
        standardSocketPath: socketPath,
        keyStore: keyStore,
        authSession: authSession,
        backendSocketPath: backendSocket
    )

    // Clean shutdown on SIGTERM/SIGINT: drop the socket and stop the backend.
    let shutdown: @convention(c) (Int32) -> Void = { _ in
        SignalContext.server?.stop()
        SignalContext.backend?.stop()
        exit(0)
    }
    SignalContext.server = server
    SignalContext.backend = backend
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
}
