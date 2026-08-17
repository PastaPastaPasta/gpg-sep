import Foundation
import LocalAuthentication

/// Vends the `LAContext` used for each enclave operation and enforces the Touch
/// ID grace window per key.
///
/// A context's `touchIDAuthenticationAllowableReuseDuration` is the grace window:
/// within it a single successful authentication is reused, so a multi-commit
/// rebase authenticates once. Crucially the window is a property of the *key*, so
/// contexts are cached per keygrip **and** per grace value and never mutated
/// after they are handed out — one key's grace window can no longer clobber
/// another's, and no context is reconfigured while another thread is mid-use.
///
/// Concurrency: a cached context may be shared by two connections signing with
/// the same key at once. `LAContext` is not documented thread-safe, so callers
/// run the enclave operation inside ``withKeySerialized(_:_:)``, which serializes
/// all use of a given key's context.
public final class AuthSession {
    private let lock = NSLock()
    /// Keyed by "<UPPER-GRIP>|<grace>" so a changed grace value yields a fresh
    /// context rather than mutating a live one.
    private var contexts: [String: LAContext] = [:]
    /// One serialization lock per keygrip, guarding concurrent enclave use.
    private var keyLocks: [String: NSLock] = [:]

    /// The default grace window (seconds) used when a call does not override it.
    public let defaultGraceSeconds: Int

    public init(defaultGraceSeconds: Int = 15) {
        self.defaultGraceSeconds = defaultGraceSeconds
    }

    /// Return an `LAContext` for `keygrip` configured for the effective grace
    /// window.
    ///
    /// - `graceSeconds == 0` (or negative): a brand-new context is returned each
    ///   call so no prior authentication can be reused — per-signature Touch ID.
    /// - otherwise: a context cached for this (keygrip, grace) pair is reused so
    ///   authentications batch within the window. Its reuse duration is set once,
    ///   at creation, and never mutated afterwards.
    public func context(forKeygrip keygrip: String, graceSeconds: Int? = nil) -> LAContext {
        let grace = graceSeconds ?? defaultGraceSeconds
        if grace <= 0 {
            let ctx = LAContext()
            ctx.touchIDAuthenticationAllowableReuseDuration = 0
            return ctx
        }
        let cacheKey = "\(keygrip.uppercased())|\(grace)"
        lock.lock()
        defer { lock.unlock() }
        if let existing = contexts[cacheKey] { return existing }
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = TimeInterval(grace)
        contexts[cacheKey] = ctx
        return ctx
    }

    /// Run `body` holding the per-key serialization lock, so a shared context for
    /// `keygrip` is never used by two enclave operations concurrently.
    public func withKeySerialized<T>(_ keygrip: String, _ body: () throws -> T) rethrows -> T {
        let keyLock: NSLock
        lock.lock()
        if let existing = keyLocks[keygrip.uppercased()] {
            keyLock = existing
        } else {
            keyLock = NSLock()
            keyLocks[keygrip.uppercased()] = keyLock
        }
        lock.unlock()
        keyLock.lock()
        defer { keyLock.unlock() }
        return try body()
    }

    /// Drop all cached contexts, forcing re-authentication on the next use.
    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        for ctx in contexts.values { ctx.invalidate() }
        contexts.removeAll()
    }
}
