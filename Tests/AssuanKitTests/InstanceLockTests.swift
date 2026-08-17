import XCTest
@testable import AssuanKit

/// M1: the single-instance lock is exclusive, so a second gpg-sep-agent bails out
/// instead of racing the first and clobbering its socket/backend.
final class InstanceLockTests: XCTestCase {
    private var lockPath: String!

    override func setUpWithError() throws {
        lockPath = "/tmp/gpgsep-lock-\(UInt32.random(in: 0..<0xFFFF_FFFF)).lock"
    }

    override func tearDownWithError() throws {
        if let lockPath { try? FileManager.default.removeItem(atPath: lockPath) }
    }

    func testSecondAcquireFailsWhileFirstIsHeld() throws {
        let first = try XCTUnwrap(try InstanceLock.tryAcquire(path: lockPath),
                                  "the first acquisition must succeed")
        XCTAssertNil(try InstanceLock.tryAcquire(path: lockPath),
                     "a second instance must fail fast while the lock is held")
        withExtendedLifetime(first) {}
    }

    func testLockIsReacquirableAfterRelease() throws {
        let first = try XCTUnwrap(try InstanceLock.tryAcquire(path: lockPath))
        first.release()
        let second = try XCTUnwrap(try InstanceLock.tryAcquire(path: lockPath),
                                   "after release the lock must be available again")
        second.release()
    }
}
