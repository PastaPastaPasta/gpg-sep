import Foundation
import CryptoKit
import LocalAuthentication
import OpenPGPKit

/// Whether a key is used for signing (ECDSA, algo 19) or encryption (ECDH,
/// algo 18).
public enum KeyRole: String, Codable {
    case signing
    case encryption

    /// The OpenPGP public-key algorithm implied by the role.
    var algorithm: PGPPublicKeyAlgorithm {
        switch self {
        case .signing: return .ecdsa
        case .encryption: return .ecdh
        }
    }
}

/// Backend identifier strings persisted in records.
public enum BackendKind {
    public static let secureEnclave = "secure-enclave"
    public static let software = "software"
}

/// On-disk record for one gpg-sep key. Persisted as JSON under
/// `<root>/keys/<keygrip>.json`.
public struct EnclaveKeyRecord: Codable, Equatable {
    /// libgcrypt keygrip (hex, uppercase) — the routing key the agent matches on.
    public var keygripHex: String
    /// v4 fingerprint (hex). Filled once the OpenPGP key packet is formed; may be
    /// empty at raw-generation time because primary-vs-subkey is not yet known.
    public var fingerprintHex: String
    public var role: KeyRole
    public var creationTime: UInt32
    public var pointX: Data
    public var pointY: Data
    public var policy: KeyPolicy
    /// `"secure-enclave"` or `"software"`.
    public var backend: String
    /// CryptoKit `dataRepresentation` sealed blob (enclave) or raw key (software).
    public var sealedBlob: Data
    public var label: String

    public init(
        keygripHex: String,
        fingerprintHex: String,
        role: KeyRole,
        creationTime: UInt32,
        pointX: Data,
        pointY: Data,
        policy: KeyPolicy,
        backend: String,
        sealedBlob: Data,
        label: String
    ) {
        self.keygripHex = keygripHex
        self.fingerprintHex = fingerprintHex
        self.role = role
        self.creationTime = creationTime
        self.pointX = pointX
        self.pointY = pointY
        self.policy = policy
        self.backend = backend
        self.sealedBlob = sealedBlob
        self.label = label
    }

    /// The public point reconstructed from the stored coordinates.
    public var point: ECPoint { ECPoint(x: pointX, y: pointY) }
}

/// Persistent store of gpg-sep key records plus a factory for their backends.
///
/// Records live under `<root>/keys/<keygrip>.json` (files 0600, dirs 0700). The
/// root is `$GPG_SEP_HOME` when set, otherwise `~/.local/share/gpg-sep`.
public final class KeyStore {
    public let root: URL
    private let keysDir: URL

    public init(root: URL) {
        self.root = root
        self.keysDir = root.appendingPathComponent("keys", isDirectory: true)
    }

    /// Convenience initializer honoring `$GPG_SEP_HOME`.
    public convenience init() {
        self.init(root: KeyStore.defaultRoot())
    }

    /// The default store root (`$GPG_SEP_HOME` or `~/.local/share/gpg-sep`).
    public static func defaultRoot() -> URL {
        if let override = ProcessInfo.processInfo.environment["GPG_SEP_HOME"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".local/share/gpg-sep", isDirectory: true)
    }

    // MARK: Reading

    /// A keygrip is a 40-character hex string. Anything else is not one of our
    /// keys — and, critically, must never reach ``recordURL(keygripHex:)`` where a
    /// crafted value like `../../evil` would escape the keys directory. Returns
    /// the normalized (uppercase) grip, or nil if malformed.
    public static func normalizedKeygrip(_ raw: String) -> String? {
        guard raw.count == 40, raw.allSatisfy(\.isHexDigit) else { return nil }
        return raw.uppercased()
    }

    /// All stored records plus a human-readable message for each JSON file that
    /// could not be read or decoded, so callers (e.g. `doctor`) can surface
    /// corruption instead of silently ignoring it.
    public func loadRecords() throws -> (records: [EnclaveKeyRecord], errors: [String]) {
        guard FileManager.default.fileExists(atPath: keysDir.path) else { return ([], []) }
        let urls = try FileManager.default.contentsOfDirectory(
            at: keysDir, includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "json" }
        let decoder = JSONDecoder()
        var records: [EnclaveKeyRecord] = []
        var errors: [String] = []
        for url in urls {
            guard let data = try? Data(contentsOf: url) else {
                errors.append("\(url.lastPathComponent): unreadable")
                continue
            }
            do {
                records.append(try decoder.decode(EnclaveKeyRecord.self, from: data))
            } catch {
                errors.append("\(url.lastPathComponent): undecodable (\(error))")
            }
        }
        return (records, errors)
    }

    /// All stored records (unordered). Files that fail to read/decode are skipped
    /// but logged to stderr so the corruption is at least visible in the daemon
    /// log; use ``loadRecords()`` to inspect the errors programmatically.
    public func allRecords() throws -> [EnclaveKeyRecord] {
        let (records, errors) = try loadRecords()
        if !errors.isEmpty {
            FileHandle.standardError.write(Data(
                ("gpg-sep: skipped \(errors.count) unreadable key record(s): "
                 + errors.joined(separator: "; ") + "\n").utf8))
        }
        return records
    }

    /// The record for `keygripHex`, or nil if absent or if `keygripHex` is not a
    /// valid 40-hex keygrip. The lookup is case-insensitive on the hex.
    public func record(keygripHex: String) throws -> EnclaveKeyRecord? {
        guard let grip = Self.normalizedKeygrip(keygripHex) else { return nil }
        let url = recordURL(keygripHex: grip)
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try JSONDecoder().decode(EnclaveKeyRecord.self, from: data)
    }

    // MARK: Generation

    public func generateSigningKey(
        policy: KeyPolicy,
        label: String,
        creationTime: UInt32,
        forceSoftware: Bool
    ) throws -> EnclaveKeyRecord {
        try generate(role: .signing, policy: policy, label: label, creationTime: creationTime, forceSoftware: forceSoftware)
    }

    public func generateEncryptionKey(
        policy: KeyPolicy,
        label: String,
        creationTime: UInt32,
        forceSoftware: Bool
    ) throws -> EnclaveKeyRecord {
        try generate(role: .encryption, policy: policy, label: label, creationTime: creationTime, forceSoftware: forceSoftware)
    }

    private func generate(
        role: KeyRole,
        policy: KeyPolicy,
        label: String,
        creationTime: UInt32,
        forceSoftware: Bool
    ) throws -> EnclaveKeyRecord {
        let useEnclave = !forceSoftware && SecureEnclave.isAvailable
        let point: ECPoint
        let sealedBlob: Data
        let backend: String

        switch (role, useEnclave) {
        case (.signing, true):
            let (b, blob) = try SecureEnclaveBackend.generate(policy: policy.presence, context: nil)
            point = b.publicPoint; sealedBlob = blob; backend = BackendKind.secureEnclave
        case (.signing, false):
            let (b, blob) = try SoftwareSigningBackend.generate()
            point = b.publicPoint; sealedBlob = blob; backend = BackendKind.software
        case (.encryption, true):
            let (b, blob) = try SecureEnclaveAgreementBackend.generate(policy: policy.presence, context: nil)
            point = b.publicPoint; sealedBlob = blob; backend = BackendKind.secureEnclave
        case (.encryption, false):
            let (b, blob) = try SoftwareAgreementBackend.generate()
            point = b.publicPoint; sealedBlob = blob; backend = BackendKind.software
        }

        // Compute the keygrip via the OpenPGP key packet so the store key exactly
        // matches what the agent will route on. Keygrip is point-only, so it is
        // stable regardless of the eventual primary/subkey placement.
        let packet = PGPPublicKeyPacket(creationTime: creationTime, algorithm: role.algorithm, point: point)
        let keygripHex = packet.keygrip.hexUpper

        let record = EnclaveKeyRecord(
            keygripHex: keygripHex,
            fingerprintHex: "",
            role: role,
            creationTime: creationTime,
            pointX: point.x,
            pointY: point.y,
            policy: policy,
            backend: backend,
            sealedBlob: sealedBlob,
            label: label
        )
        try write(record)
        return record
    }

    // MARK: Backends

    public func signingBackend(keygripHex: String, context: LAContext?) throws -> SigningBackend {
        let record = try requireRecord(keygripHex: keygripHex)
        guard record.role == .signing else {
            throw SEPError.roleMismatch(expected: "signing", got: record.role.rawValue)
        }
        switch record.backend {
        case BackendKind.secureEnclave:
            return try SecureEnclaveBackend(dataRepresentation: record.sealedBlob, context: context)
        case BackendKind.software:
            return try SoftwareSigningBackend(rawRepresentation: record.sealedBlob)
        default:
            throw SEPError.unknownBackend(record.backend)
        }
    }

    public func agreementBackend(keygripHex: String, context: LAContext?) throws -> AgreementBackend {
        let record = try requireRecord(keygripHex: keygripHex)
        guard record.role == .encryption else {
            throw SEPError.roleMismatch(expected: "encryption", got: record.role.rawValue)
        }
        switch record.backend {
        case BackendKind.secureEnclave:
            return try SecureEnclaveAgreementBackend(dataRepresentation: record.sealedBlob, context: context)
        case BackendKind.software:
            return try SoftwareAgreementBackend(rawRepresentation: record.sealedBlob)
        default:
            throw SEPError.unknownBackend(record.backend)
        }
    }

    // MARK: Deletion

    /// Delete the record file for `keygripHex`. Note: this cannot erase the
    /// enclave-held private key itself (the OS owns that); it removes gpg-sep's
    /// ability to reference it, which for a non-exportable SEP key is equivalent
    /// to loss.
    public func delete(keygripHex: String) throws {
        guard let grip = Self.normalizedKeygrip(keygripHex) else { return }
        let url = recordURL(keygripHex: grip)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }

    // MARK: Private helpers

    private func requireRecord(keygripHex: String) throws -> EnclaveKeyRecord {
        guard let record = try record(keygripHex: keygripHex) else {
            throw SEPError.keyNotFound(keygripHex.uppercased())
        }
        return record
    }

    private func recordURL(keygripHex: String) -> URL {
        // Defensive: use only the final path component so a crafted keygrip that
        // somehow slipped validation (e.g. "../../evil") still cannot escape the
        // keys directory. Valid 40-hex grips have no separators, so this is a
        // no-op for them.
        let safe = (keygripHex.uppercased() as NSString).lastPathComponent
        return keysDir.appendingPathComponent("\(safe).json", isDirectory: false)
    }

    private func write(_ record: EnclaveKeyRecord) throws {
        try FileManager.default.createDirectory(
            at: keysDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        // Tighten the root too (createDirectory only applies perms to leaf dirs
        // it creates; ensure the store root is 0700 if we own it).
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: keysDir.path)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(record)
        let url = recordURL(keygripHex: record.keygripHex)
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

extension Data {
    /// Uppercase hex, no separators.
    var hexUpper: String {
        map { String(format: "%02X", $0) }.joined()
    }
}
