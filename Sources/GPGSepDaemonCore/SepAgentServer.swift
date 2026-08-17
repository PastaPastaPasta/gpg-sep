import Foundation
import AssuanKit
import SEPKit

/// Binds the standard gpg-agent socket and drives one ``SepProxyHandler`` per
/// client connection, each with its own fresh backend ``AssuanClient``.
///
/// This is the piece gpg talks to: it owns `~/.gnupg/S.gpg-agent` (or any path
/// given as `standardSocketPath`) and forwards non-enclave traffic to the
/// backend agent discovered by ``BackendAgent``.
public final class SepAgentServer {
    public let socketPath: String
    private let keyStore: KeyStore
    private let authSession: AuthSession
    private let backendSocketPath: String
    private let listener: AssuanListener
    private var serveThread: Thread?

    public init(
        standardSocketPath: String,
        keyStore: KeyStore,
        authSession: AuthSession,
        backendSocketPath: String
    ) throws {
        self.socketPath = standardSocketPath
        self.keyStore = keyStore
        self.authSession = authSession
        self.backendSocketPath = backendSocketPath
        self.listener = try AssuanListener(path: standardSocketPath)
    }

    /// Serve connections on the current thread until ``stop()`` is called.
    public func run() throws {
        try listener.serveForever { [weak self] conn in
            self?.serve(conn)
        }
    }

    /// Serve connections on a background thread; returns immediately. For tests
    /// and for a daemon that also wants to install signal handlers.
    public func startInBackground() {
        let thread = Thread { [weak self] in try? self?.run() }
        thread.name = "sep-agent-listener"
        thread.start()
        serveThread = thread
    }

    /// Stop accepting connections and remove the socket.
    public func stop() {
        listener.closeAndUnlink()
    }

    private func serve(_ conn: AssuanConnection) {
        // The Assuan manual requires verifying the peer's credentials rather
        // than trusting socket permissions. Refuse a different user outright.
        guard conn.peerIsSameUser else {
            conn.close()
            return
        }
        do {
            let resolved = try AssuanSocketRedirection.resolve(backendSocketPath)
            let backend = try AssuanClient.connect(toSocket: resolved)
            defer { backend.connection.close() }
            let handler = SepProxyHandler(
                keyStore: keyStore, authSession: authSession, backend: backend)
            let server = AssuanServer(
                client: conn, handler: handler, backend: backend.connection)
            try server.run()
        } catch {
            // A failed connection must never take the daemon down; just drop it.
            conn.close()
        }
    }
}
