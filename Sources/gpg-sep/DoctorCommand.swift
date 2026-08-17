import Foundation
import CryptoKit
import AssuanKit
import SEPKit
import OpenPGPKit
import GPGSepDaemonCore

/// `gpg-sep doctor` — diagnostics plus an end-to-end signing self-test.
///
/// Every check is reported green/red with the evidence that produced it; the
/// exit status is non-zero if any check failed, so `doctor` is usable in CI and
/// in scripts.
enum DoctorCommand {
    static let spec = ArgSpec(flags: ["hardware"])

    static let usage = """
    usage: gpg-sep doctor [--hardware]
      --hardware   require the self-test to use a real Secure Enclave key
                   (skips with a clear message when no SEP is present)
    """

    // MARK: Check reporting

    enum Status { case pass, fail, skip }

    struct Check {
        let name: String
        let status: Status
        let detail: String
    }

    static func run(_ argv: [String], context: CLIContext) throws {
        let args = try ArgParser.parse(argv, spec: spec)
        if args.has("help") { print(usage); return }

        var checks: [Check] = []
        checks.append(secureEnclaveCheck())
        let socket = Tools.agentSocket()
        let sockStatus = socketStatus(socketPath: socket, waitSeconds: 0)
        checks.append(socketCheck(socket: socket, status: sockStatus))
        checks.append(backendCheck())
        checks.append(contentsOf: storeCheck(store: context.store))
        checks.append(selfTest(context: context, requireHardware: args.has("hardware"),
                               socketIsOurs: sockStatus.isOurs))

        print("gpg-sep doctor")
        print("")
        for c in checks {
            let mark: String
            switch c.status {
            case .pass: mark = "[ OK ]"
            case .fail: mark = "[FAIL]"
            case .skip: mark = "[SKIP]"
            }
            print("\(mark) \(c.name)")
            for line in c.detail.split(separator: "\n") { print("       \(line)") }
        }

        let failures = checks.filter { $0.status == .fail }.count
        let skips = checks.filter { $0.status == .skip }.count
        print("")
        if failures == 0 {
            print("Summary: all \(checks.count - skips) checks passed"
                + (skips > 0 ? ", \(skips) skipped." : "."))
        } else {
            print("Summary: \(failures) check(s) FAILED, \(checks.count - failures - skips) passed"
                + (skips > 0 ? ", \(skips) skipped." : "."))
            throw ExitCode(1)
        }
    }

    // MARK: Individual checks

    static func secureEnclaveCheck() -> Check {
        if SecureEnclave.isAvailable {
            return Check(name: "Secure Enclave", status: .pass,
                         detail: "SecureEnclave.isAvailable == true")
        }
        return Check(name: "Secure Enclave", status: .skip,
                     detail: "no Secure Enclave on this machine (VM or unsupported hardware);\n"
                        + "only --force-software keys can be used here")
    }

    /// What is serving the standard agent socket.
    struct SocketStatus {
        var exists = false
        var connectable = false
        var servingPID: Int32?
        var servingProcess: String?
        var isOurs: Bool { servingProcess?.contains("gpg-sep-agent") ?? false }
        var isStock: Bool {
            guard let p = servingProcess else { return false }
            return p.contains("gpg-agent") && !p.contains("gpg-sep-agent")
        }

        func describe() -> String {
            guard exists else { return "absent (gpg will autostart the stock agent)" }
            guard connectable else { return "present but not answering" }
            let who = servingProcess ?? "unknown process"
            let pid = servingPID.map { " pid \($0)" } ?? ""
            if isOurs { return "served by gpg-sep-agent (\(who)\(pid)) — gpg-sep is active" }
            if isStock { return "served by the STOCK gpg-agent (\(who)\(pid)) — gpg-sep is not active" }
            return "served by \(who)\(pid)"
        }
    }

    /// Probe `socketPath`: does it exist, does it answer, and which executable is
    /// behind it? Identification uses the Assuan greeting, which reports the
    /// *server's* own pid (`OK … , process <pid>`), resolved through `ps`.
    static func socketStatus(socketPath: String, waitSeconds: Int) -> SocketStatus {
        var status = SocketStatus()
        guard !socketPath.isEmpty else { return status }

        let deadline = Date().addingTimeInterval(TimeInterval(max(waitSeconds, 0)))
        repeat {
            status.exists = FileManager.default.fileExists(atPath: socketPath)
            if status.exists,
               let client = try? AssuanClient.connect(toSocket: socketPath) {
                defer { client.connection.close() }
                status.connectable = true
                if let greeting = client.greeting,
                   let range = greeting.range(of: "process "),
                   let pid = Int32(greeting[range.upperBound...]
                    .prefix(while: { $0.isNumber })) {
                    status.servingPID = pid
                    let comm = Tools.run("/bin/ps", ["-p", "\(pid)", "-o", "comm="]).outString
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    status.servingProcess = comm.isEmpty ? nil : comm
                }
                return status
            }
            if waitSeconds > 0 { usleep(200_000) }
        } while Date() < deadline
        return status
    }

    static func socketCheck(socket: String, status: SocketStatus) -> Check {
        if socket.isEmpty {
            return Check(name: "Agent socket", status: .fail,
                         detail: "gpgconf --list-dirs agent-socket returned nothing")
        }
        if status.isOurs {
            return Check(name: "Agent socket ownership", status: .pass,
                         detail: "\(socket)\n\(status.describe())")
        }
        if status.connectable {
            return Check(name: "Agent socket ownership", status: .skip,
                         detail: "\(socket)\n\(status.describe())\n"
                            + "run `gpg-sep install` to have gpg-sep serve this socket")
        }
        return Check(name: "Agent socket ownership", status: .skip,
                     detail: "\(socket)\n\(status.describe())")
    }

    static func backendCheck() -> Check {
        let backendHome = BackendAgent.defaultBackendHome()
        guard FileManager.default.fileExists(atPath: backendHome.path) else {
            return Check(name: "Backend agent", status: .skip,
                         detail: "no backend home at \(backendHome.path) (not installed yet)")
        }
        let socket = Tools.run(Tools.gpgconf, ["--homedir", backendHome.path, "--list-dirs", "agent-socket"])
            .outString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !socket.isEmpty else {
            return Check(name: "Backend agent", status: .fail,
                         detail: "gpgconf reported no agent-socket for \(backendHome.path)")
        }
        guard FileManager.default.fileExists(atPath: socket),
              let client = try? AssuanClient.connect(toSocket: socket) else {
            return Check(name: "Backend agent", status: .skip,
                         detail: "backend home \(backendHome.path) exists but no agent is listening at\n"
                            + "\(socket) (it is started on demand by gpg-sep-agent)")
        }
        defer { client.connection.close() }
        let version = (try? client.transact("GETINFO version"))?.text ?? "?"
        return Check(name: "Backend agent", status: .pass,
                     detail: "stock gpg-agent \(version) alive at \(socket)")
    }

    /// Store integrity: every record must be readable, permissioned 0600, and
    /// have a keygrip that still matches its stored public point.
    static func storeCheck(store: KeyStore) -> [Check] {
        let records: [EnclaveKeyRecord]
        do { records = try store.allRecords() } catch {
            return [Check(name: "Key store", status: .fail, detail: "unreadable: \(error)")]
        }
        if records.isEmpty {
            return [Check(name: "Key store", status: .skip,
                          detail: "no keys in \(store.root.path) — run `gpg-sep keygen`")]
        }
        var problems: [String] = []
        let keysDir = store.root.appendingPathComponent("keys", isDirectory: true)
        for r in records {
            let expected = PGPPublicKeyPacket(
                creationTime: r.creationTime,
                algorithm: r.role == .signing ? .ecdsa : .ecdh,
                point: r.point).keygrip.hexUpperString
            if expected != r.keygripHex.uppercased() {
                problems.append("\(r.keygripHex): keygrip does not match the stored point")
            }
            if r.pointX.count != 32 || r.pointY.count != 32 {
                problems.append("\(r.keygripHex): public point is not a 32/32-byte P-256 point")
            }
            let url = keysDir.appendingPathComponent("\(r.keygripHex.uppercased()).json")
            if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
               let perms = attrs[.posixPermissions] as? NSNumber, perms.int16Value & 0o077 != 0 {
                problems.append("\(r.keygripHex): record is group/world accessible "
                    + "(\(String(perms.intValue, radix: 8)))")
            }
        }
        if problems.isEmpty {
            let enclave = records.filter { $0.backend == BackendKind.secureEnclave }.count
            let software = records.count - enclave
            return [Check(name: "Key store", status: .pass,
                          detail: "\(records.count) key(s) in \(store.root.path) "
                            + "(\(enclave) enclave, \(software) software)")]
        }
        return [Check(name: "Key store", status: .fail, detail: problems.joined(separator: "\n"))]
    }

    // MARK: End-to-end self-test

    /// Produce a detached signature with a store signing key *through the running
    /// agent* and verify it with `gpg --verify`. This is the check that proves the
    /// whole chain — gpg → socket → proxy → enclave → signature → verification.
    static func selfTest(context: CLIContext, requireHardware: Bool, socketIsOurs: Bool) -> Check {
        let name = "End-to-end sign/verify self-test"
        let records: [EnclaveKeyRecord]
        do { records = try context.store.allRecords() } catch {
            return Check(name: name, status: .fail, detail: "store unreadable: \(error)")
        }
        var candidates = records.filter { $0.role == .signing }
        if requireHardware {
            guard SecureEnclave.isAvailable else {
                return Check(name: name, status: .skip,
                             detail: "--hardware requested but this machine has no Secure Enclave")
            }
            candidates = candidates.filter { $0.backend == BackendKind.secureEnclave }
            if candidates.isEmpty {
                return Check(name: name, status: .skip,
                             detail: "--hardware requested but the store has no Secure-Enclave signing key;\n"
                                + "create one with `gpg-sep keygen --uid ...`")
            }
        }
        guard !candidates.isEmpty else {
            return Check(name: name, status: .skip,
                         detail: "no signing key in the store — run `gpg-sep keygen --uid ...`")
        }

        // The key must also be in gpg's public keyring, or gpg cannot select it.
        let visible = GpgKeyring.visibleKeygrips()
        guard let record = candidates.first(where: { visible.contains($0.keygripHex.uppercased()) }) else {
            return Check(name: name, status: .skip,
                         detail: "store signing keys are not present in the gpg public keyring;\n"
                            + "import one (keygen does this automatically) before self-testing")
        }
        guard socketIsOurs else {
            return Check(name: name, status: .skip,
                         detail: "gpg-sep does not currently own the agent socket, so a signature by\n"
                            + "\(record.keygripHex) cannot reach the enclave. Run `gpg-sep install` first.")
        }

        let fpr = PGPPublicKeyPacket(creationTime: record.creationTime, algorithm: .ecdsa,
                                     point: record.point).fingerprint.hexUpperString
        let dir = NSTemporaryDirectory() + "gpg-sep-doctor-" + UUID().uuidString.prefix(8)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        do {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let doc = dir + "/selftest.txt"
            let sig = dir + "/selftest.sig"
            try Data("gpg-sep doctor self-test\n".utf8).write(to: URL(fileURLWithPath: doc))

            // `FPR!` forces this exact key rather than a default subkey.
            let sign = Tools.gpgRun(["--yes", "-u", "\(fpr)!", "--detach-sign", "-o", sig, doc])
            guard sign.code == 0 else {
                return Check(name: name, status: .fail,
                             detail: "signing with \(fpr) failed:\n\(sign.err)")
            }
            let verify = Tools.gpgRun(["--verify", sig, doc])
            guard verify.err.contains("Good signature") else {
                return Check(name: name, status: .fail,
                             detail: "gpg --verify did not report a good signature:\n\(verify.err)")
            }
            return Check(name: name, status: .pass,
                         detail: "signed and verified with \(record.backend) key \(fpr)\n"
                            + "(keygrip \(record.keygripHex))")
        } catch {
            return Check(name: name, status: .fail, detail: "\(error)")
        }
    }
}

/// Thrown to end the process with a specific status without an error message.
struct ExitCode: Error {
    let code: Int32
    init(_ code: Int32) { self.code = code }
}
