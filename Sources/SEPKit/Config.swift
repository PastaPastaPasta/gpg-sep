import Foundation

/// gpg-sep configuration, persisted as JSON (no external TOML dependency).
///
/// Loaded from `<config root>/config.json`. The config root is `$GPG_SEP_CONFIG`
/// when set, otherwise `~/.config/gpg-sep`. Missing files yield sane defaults.
public struct Config: Codable, Equatable {
    /// Default key policy applied to newly generated keys unless overridden.
    /// Default: presence with a 15-second grace window (the user's decision).
    public var defaultPolicy: KeyPolicy

    public init(defaultPolicy: KeyPolicy = KeyPolicy(presence: .presence, graceSeconds: 15)) {
        self.defaultPolicy = defaultPolicy
    }

    // MARK: Locations

    /// The configuration root directory (`$GPG_SEP_CONFIG` or `~/.config/gpg-sep`).
    public static func defaultConfigRoot() -> URL {
        if let override = ProcessInfo.processInfo.environment["GPG_SEP_CONFIG"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".config/gpg-sep", isDirectory: true)
    }

    private static func configURL(root: URL?) -> URL {
        (root ?? defaultConfigRoot()).appendingPathComponent("config.json", isDirectory: false)
    }

    // MARK: Load / save

    /// Load the config from `root` (default config root). Returns defaults if the
    /// file is absent.
    public static func load(root: URL? = nil) throws -> Config {
        let url = configURL(root: root)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return Config()
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Config.self, from: data)
    }

    /// Persist the config to `root` (default config root), creating the directory
    /// (0700) and writing the file 0600.
    public func save(root: URL? = nil) throws {
        let dir = root ?? Config.defaultConfigRoot()
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let url = Config.configURL(root: root)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
