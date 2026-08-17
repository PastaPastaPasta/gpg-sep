import Foundation
import LocalAuthentication

/// Manages a shared `LAContext` whose `touchIDAuthenticationAllowableReuseDuration`
/// implements the Touch ID grace window: within the window a single successful
/// authentication is reused, so a multi-commit rebase authenticates once.
///
/// The daemon holds one `AuthSession` and passes the context it returns into
/// `KeyStore.signingBackend(_:context:)`. A per-key `graceSeconds == 0` requests
/// a fresh context so authentication is forced on every signature.
public final class AuthSession {
    private let lock = NSLock()
    private var shared: LAContext?

    /// The default grace window (seconds) used when a call does not override it.
    public let defaultGraceSeconds: Int

    public init(defaultGraceSeconds: Int = 15) {
        self.defaultGraceSeconds = defaultGraceSeconds
    }

    /// Return an `LAContext` configured for the effective grace window.
    ///
    /// - `graceSeconds == 0` (or negative): a brand-new context is returned each
    ///   call so no prior authentication can be reused — per-signature Touch ID.
    /// - otherwise: a shared context is reused across calls, its reuse duration
    ///   set to the window, so authentications batch within it.
    public func context(graceSeconds: Int? = nil) -> LAContext {
        let grace = graceSeconds ?? defaultGraceSeconds
        lock.lock()
        defer { lock.unlock() }

        if grace <= 0 {
            let ctx = LAContext()
            ctx.touchIDAuthenticationAllowableReuseDuration = 0
            return ctx
        }

        if let existing = shared {
            existing.touchIDAuthenticationAllowableReuseDuration = TimeInterval(grace)
            return existing
        }
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = TimeInterval(grace)
        shared = ctx
        return ctx
    }

    /// Drop the shared context, forcing re-authentication on the next use.
    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        shared?.invalidate()
        shared = nil
    }
}
