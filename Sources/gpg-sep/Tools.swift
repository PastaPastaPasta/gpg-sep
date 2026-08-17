import Foundation

/// Locating and invoking the external GnuPG toolchain, plus small shared
/// utilities (hex, stderr printing).
enum Tools {
    /// First existing executable named `name` across the usual Homebrew/system
    /// locations. Falls back to `/usr/bin/<name>` so callers always get a path.
    static func path(_ name: String) -> String {
        for candidate in ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)", "/usr/bin/\(name)"]
        where FileManager.default.isExecutableFile(atPath: candidate) {
            return candidate
        }
        return "/usr/bin/\(name)"
    }

    static var gpg: String { path("gpg") }
    static var gpgconf: String { path("gpgconf") }
    static var gpgAgent: String { path("gpg-agent") }

    struct Result {
        let out: Data
        let err: String
        let code: Int32
        var outString: String { String(decoding: out, as: UTF8.self) }
    }

    /// Run `tool` with `args`, optionally feeding `input` on stdin. Captures
    /// stdout (binary-safe) and stderr. Never throws for a non-zero exit.
    @discardableResult
    static func run(_ tool: String, _ args: [String], input: Data? = nil,
                    env extraEnv: [String: String] = [:]) -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        if !extraEnv.isEmpty {
            var env = ProcessInfo.processInfo.environment
            for (k, v) in extraEnv { env[k] = v }
            p.environment = env
        }
        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe
        if let input {
            let inPipe = Pipe()
            p.standardInput = inPipe
            do { try p.run() } catch {
                return Result(out: Data(), err: "\(error)", code: -1)
            }
            inPipe.fileHandleForWriting.write(input)
            try? inPipe.fileHandleForWriting.close()
        } else {
            p.standardInput = FileHandle.nullDevice
            do { try p.run() } catch {
                return Result(out: Data(), err: "\(error)", code: -1)
            }
        }
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Result(out: outData, err: String(decoding: errData, as: UTF8.self), code: p.terminationStatus)
    }

    /// Common gpg invocation with `--batch --no-tty`, honoring `$GNUPGHOME`.
    @discardableResult
    static func gpgRun(_ args: [String], input: Data? = nil) -> Result {
        run(gpg, ["--batch", "--no-tty"] + args, input: input)
    }

    /// The agent socket path for the active `$GNUPGHOME`.
    static func agentSocket() -> String {
        run(gpgconf, ["--list-dirs", "agent-socket"]).outString
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Ensure a gpg-agent is listening for the active home (autostart it).
    static func launchAgent() {
        _ = run(gpgconf, ["--launch", "gpg-agent"])
    }
}

// MARK: - Output helpers

func printErr(_ s: String) {
    FileHandle.standardError.write(Data((s + "\n").utf8))
}

extension Data {
    /// Lowercase hex, no separators.
    var hexLower: String { map { String(format: "%02x", $0) }.joined() }
    /// Uppercase hex, no separators.
    var hexUpperString: String { map { String(format: "%02X", $0) }.joined() }
}
