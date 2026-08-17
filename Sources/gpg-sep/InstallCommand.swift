import Foundation
import SEPKit
import GPGSepDaemonCore

/// `gpg-sep install` / `uninstall` — take over (and hand back) the standard
/// gpg-agent socket via a launchd LaunchAgent.
///
/// The pieces are deliberately separable so tests can exercise the backend-home
/// setup, plist generation, and socket swap without launchd: `--no-launchd`
/// performs everything except the `launchctl` calls.
enum InstallCommand {
    static let spec = ArgSpec(
        value: ["agent-path", "launch-agents-dir"],
        flags: ["no-launchd", "force"])

    static let usage = """
    usage: gpg-sep install [options]
      --agent-path <path>        gpg-sep-agent executable (default: next to gpg-sep)
      --launch-agents-dir <dir>  override ~/Library/LaunchAgents (tests)
      --no-launchd               prepare everything but do not call launchctl
      --force                    overwrite an existing plist
    """

    static func run(_ argv: [String], context: CLIContext) throws {
        let args = try ArgParser.parse(argv, spec: spec)
        if args.has("help") { print(usage); return }

        let agentPath = try resolveAgentPath(args.string("agent-path"))
        let launchAgentsDir = args.string("launch-agents-dir").map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? LaunchAgentPlist.defaultLaunchAgentsDir()
        let plistURL = LaunchAgentPlist.plistURL(inLaunchAgents: launchAgentsDir)
        let useLaunchd = !args.has("no-launchd")

        var changes: [String] = []

        // 1. Backend mirror home: where the stock gpg-agent will live once we own
        //    the standard socket. Reuses BackendAgent's own linking logic.
        let backendHome = BackendAgent.defaultBackendHome()
        let realHome = BackendAgent.defaultRealGnupgHome()
        let backend = BackendAgent(
            backendHome: backendHome, realGnupgHome: realHome,
            gpgAgentPath: Tools.gpgAgent, gpgconfPath: Tools.gpgconf)
        try backend.start()
        changes.append("created/refreshed the backend home \(backendHome.path) "
            + "(symlinks into \(realHome.path))")
        // The daemon starts its own backend; stop the one we just probed with.
        backend.stop()

        // 2. Write the LaunchAgent plist.
        if FileManager.default.fileExists(atPath: plistURL.path), !args.has("force") {
            throw CLIError("\(plistURL.path) already exists — pass --force to overwrite, "
                + "or run `gpg-sep uninstall` first")
        }
        let logPath = KeyStore.defaultRoot().appendingPathComponent("agent.log").path
        let plist = LaunchAgentPlist(
            programPath: agentPath,
            gpgSepHome: KeyStore.defaultRoot().path,
            gnupgHome: ProcessInfo.processInfo.environment["GNUPGHOME"],
            logPath: logPath)
        try FileManager.default.createDirectory(at: launchAgentsDir, withIntermediateDirectories: true)
        try Data(plist.xml().utf8).write(to: plistURL, options: .atomic)
        changes.append("wrote \(plistURL.path)")

        // 3. Free the standard socket, then let launchd start our daemon on it.
        let socket = Tools.agentSocket()
        _ = Tools.run(Tools.gpgconf, ["--kill", "gpg-agent"])
        changes.append("killed the stock gpg-agent (gpgconf --kill gpg-agent)")

        if useLaunchd {
            let uid = getuid()
            _ = Tools.run("/bin/launchctl", ["bootout", "gui/\(uid)/\(LaunchAgentPlist.label)"])
            let boot = Tools.run("/bin/launchctl", ["bootstrap", "gui/\(uid)", plistURL.path])
            if boot.code != 0 {
                // Older/edge environments: fall back to the legacy verb.
                let load = Tools.run("/bin/launchctl", ["load", "-w", plistURL.path])
                guard load.code == 0 else {
                    throw CLIError("launchctl bootstrap failed (\(boot.code)): \(boot.outString)\(boot.err)\n"
                        + "launchctl load also failed: \(load.outString)\(load.err)")
                }
            }
            changes.append("bootstrapped \(LaunchAgentPlist.label) into gui/\(uid)")
        }

        print("gpg-sep install: changed")
        for c in changes { print("  - \(c)") }
        print("""

        To undo everything above:
          gpg-sep uninstall
        (which boots the job out, removes \(plistURL.path), drops our socket, and
        lets gpg autostart the stock agent again — SEP keys go inert, nothing else
        changes.)
        """)

        if useLaunchd {
            // Give launchd a moment, then report the socket state via doctor's check.
            print("")
            let status = DoctorCommand.socketStatus(socketPath: socket, waitSeconds: 5)
            print("Socket \(socket): \(status.describe())")
            if !status.isOurs {
                printErr("warning: the socket is not (yet) served by gpg-sep-agent. "
                    + "Run `gpg-sep doctor` for diagnostics; the log is at \(logPath).")
            }
        } else {
            print("\n(--no-launchd: the job was NOT bootstrapped; the socket is still stock.)")
        }
    }

    /// Locate `gpg-sep-agent`: explicit path, else the sibling of this binary.
    static func resolveAgentPath(_ explicit: String?) throws -> String {
        if let explicit {
            guard FileManager.default.isExecutableFile(atPath: explicit) else {
                throw CLIError("--agent-path \(explicit) is not an executable")
            }
            return explicit
        }
        let selfPath = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let sibling = selfPath.deletingLastPathComponent()
            .appendingPathComponent("gpg-sep-agent").path
        guard FileManager.default.isExecutableFile(atPath: sibling) else {
            throw CLIError("could not find gpg-sep-agent next to \(selfPath.path); pass --agent-path")
        }
        return sibling
    }
}

/// `gpg-sep uninstall` — undo `install`. Idempotent.
enum UninstallCommand {
    static let spec = ArgSpec(value: ["launch-agents-dir"], flags: ["no-launchd"])

    static let usage = """
    usage: gpg-sep uninstall [options]
      --launch-agents-dir <dir>  override ~/Library/LaunchAgents (tests)
      --no-launchd               skip the launchctl calls
    """

    static func run(_ argv: [String], context: CLIContext) throws {
        let args = try ArgParser.parse(argv, spec: spec)
        if args.has("help") { print(usage); return }

        let launchAgentsDir = args.string("launch-agents-dir").map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? LaunchAgentPlist.defaultLaunchAgentsDir()
        let plistURL = LaunchAgentPlist.plistURL(inLaunchAgents: launchAgentsDir)
        var changes: [String] = []

        if !args.has("no-launchd") {
            let uid = getuid()
            let bootout = Tools.run("/bin/launchctl", ["bootout", "gui/\(uid)/\(LaunchAgentPlist.label)"])
            if bootout.code == 0 {
                changes.append("booted \(LaunchAgentPlist.label) out of gui/\(uid)")
            } else {
                _ = Tools.run("/bin/launchctl", ["unload", "-w", plistURL.path])
                changes.append("no running \(LaunchAgentPlist.label) job (already stopped)")
            }
        }

        if FileManager.default.fileExists(atPath: plistURL.path) {
            try FileManager.default.removeItem(at: plistURL)
            changes.append("removed \(plistURL.path)")
        } else {
            changes.append("no plist at \(plistURL.path) (already removed)")
        }

        // Drop a socket we are still serving, and stop the backend agent, so gpg
        // autostarts the stock agent on the standard path again.
        let socket = Tools.agentSocket()
        let status = DoctorCommand.socketStatus(socketPath: socket, waitSeconds: 0)
        if status.isOurs {
            try? FileManager.default.removeItem(atPath: socket)
            changes.append("removed our socket at \(socket)")
        }
        let backendHome = BackendAgent.defaultBackendHome()
        if FileManager.default.fileExists(atPath: backendHome.path) {
            _ = Tools.run(Tools.gpgconf, ["--homedir", backendHome.path, "--kill", "gpg-agent"])
            changes.append("stopped the backend gpg-agent under \(backendHome.path) "
                + "(the directory is left in place; delete it manually if you want it gone)")
        }
        _ = Tools.run(Tools.gpgconf, ["--kill", "gpg-agent"])

        print("gpg-sep uninstall: changed")
        for c in changes { print("  - \(c)") }

        // Verify the stock agent comes back and can serve a request.
        Tools.launchAgent()
        let after = DoctorCommand.socketStatus(socketPath: socket, waitSeconds: 5)
        print("\nSocket \(socket): \(after.describe())")
        if after.isOurs {
            printErr("warning: gpg-sep still appears to own the socket. "
                + "Check for a stray gpg-sep-agent process.")
        }
    }
}
