import Foundation

/// Generation and placement of the `org.gpg-sep.agent` LaunchAgent plist.
///
/// Kept as a pure value type so the plist content can be unit-tested without
/// touching `~/Library/LaunchAgents` or launchd.
struct LaunchAgentPlist {
    static let label = "org.gpg-sep.agent"

    /// Absolute path to the `gpg-sep-agent` executable.
    let programPath: String
    /// `$GPG_SEP_HOME` for the daemon (store + backend home root).
    let gpgSepHome: String
    /// `$GNUPGHOME` for the daemon, when it must not use the default.
    let gnupgHome: String?
    /// Where stdout/stderr go.
    let logPath: String

    /// The plist file location for the current user (or a test root).
    static func plistURL(inLaunchAgents dir: URL) -> URL {
        dir.appendingPathComponent("\(label).plist", isDirectory: false)
    }

    static func defaultLaunchAgentsDir() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true)
    }

    /// The plist as XML. `KeepAlive` restarts the proxy if it dies (the socket
    /// must never be left dangling); `RunAtLoad` binds it at login.
    func xml() -> String {
        var env = "<key>GPG_SEP_HOME</key><string>\(Self.escape(gpgSepHome))</string>"
        if let gnupgHome {
            env += "\n            <key>GNUPGHOME</key><string>\(Self.escape(gnupgHome))</string>"
        }
        // PATH so the daemon can find gpgconf/gpg-agent under launchd's minimal env.
        env += "\n            <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>"

        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(Self.label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(Self.escape(programPath))</string>
            </array>
            <key>EnvironmentVariables</key>
            <dict>
                \(env)
            </dict>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>ProcessType</key>
            <string>Interactive</string>
            <key>StandardOutPath</key>
            <string>\(Self.escape(logPath))</string>
            <key>StandardErrorPath</key>
            <string>\(Self.escape(logPath))</string>
        </dict>
        </plist>

        """
    }

    /// Minimal XML text escaping for the values we interpolate (paths).
    static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}
