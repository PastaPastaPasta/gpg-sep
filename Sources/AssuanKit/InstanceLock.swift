import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// A single-writer advisory lock backed by a lockfile and `flock`/`O_EXLOCK`.
///
/// The daemon acquires one before it does anything destructive (killing the
/// stock agent, binding the socket). A second instance that tries to acquire the
/// same lock fails immediately (`O_NONBLOCK`) instead of racing the first one
/// and clobbering its socket. The lock is released when the process exits or
/// ``release()`` is called, and the OS drops it automatically on crash.
public final class InstanceLock {
    public let path: String
    private var fd: Int32

    /// Try to acquire the lock at `path`. Returns nil if another live instance
    /// already holds it. Throws only on an unexpected filesystem error.
    public static func tryAcquire(path: String) throws -> InstanceLock? {
        // O_EXLOCK takes an exclusive advisory lock atomically with the open;
        // O_NONBLOCK turns contention into EWOULDBLOCK instead of a hang.
        let fd = open(path, O_CREAT | O_RDWR | O_EXLOCK | O_NONBLOCK, 0o600)
        if fd < 0 {
            if errno == EWOULDBLOCK || errno == EAGAIN { return nil }
            throw AssuanIOError("could not open lockfile \(path)", errno: errno)
        }
        return InstanceLock(path: path, fd: fd)
    }

    private init(path: String, fd: Int32) {
        self.path = path
        self.fd = fd
    }

    deinit { release() }

    /// Release the lock. The lockfile inode is left in place (cheap, and avoids a
    /// TOCTOU with a concurrent acquirer); the advisory lock is what matters.
    public func release() {
        guard fd >= 0 else { return }
        _ = flock(fd, LOCK_UN)
        _ = Darwin.close(fd)
        fd = -1
    }
}
