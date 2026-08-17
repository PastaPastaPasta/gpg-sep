import XCTest
import LocalAuthentication
@testable import SEPKit

/// H2: contexts are per-key and never mutated after being handed out, so one
/// key's grace window can no longer clobber another's, and there is no shared
/// mutable `LAContext` for two connections to race on.
final class AuthSessionTests: XCTestCase {
    private let gripA = String(repeating: "A", count: 40)
    private let gripB = String(repeating: "B", count: 40)

    func testDistinctKeysGetDistinctContextsWithTheirOwnReuseDurations() {
        let session = AuthSession(defaultGraceSeconds: 15)
        let a = session.context(forKeygrip: gripA, graceSeconds: 30)
        let b = session.context(forKeygrip: gripB, graceSeconds: 5)

        XCTAssertFalse(a === b, "different keys must not share one context")
        XCTAssertEqual(a.touchIDAuthenticationAllowableReuseDuration, 30)
        XCTAssertEqual(b.touchIDAuthenticationAllowableReuseDuration, 5)
    }

    func testUsingKeyBDoesNotClobberKeyAsGraceWindow() {
        let session = AuthSession(defaultGraceSeconds: 15)
        let a = session.context(forKeygrip: gripA, graceSeconds: 30)
        // The old bug: fetching B mutated the single shared context, changing A's
        // effective reuse duration. It must not any more.
        _ = session.context(forKeygrip: gripB, graceSeconds: 5)
        XCTAssertEqual(a.touchIDAuthenticationAllowableReuseDuration, 30,
                       "key A's grace window was clobbered by using key B")
    }

    func testSameKeyAndGraceReusesTheCachedContext() {
        let session = AuthSession()
        let first = session.context(forKeygrip: gripA, graceSeconds: 20)
        let second = session.context(forKeygrip: gripA, graceSeconds: 20)
        XCTAssertTrue(first === second, "the batching window relies on a stable cached context")
    }

    func testZeroGraceReturnsAFreshContextEachCall() {
        let session = AuthSession()
        let first = session.context(forKeygrip: gripA, graceSeconds: 0)
        let second = session.context(forKeygrip: gripA, graceSeconds: 0)
        XCTAssertFalse(first === second, "graceSeconds:0 must force a fresh prompt each signature")
        XCTAssertEqual(first.touchIDAuthenticationAllowableReuseDuration, 0)
    }

    func testWithKeySerializedRunsBodyExactlyOnce() throws {
        let session = AuthSession()
        var count = 0
        let out: Int = session.withKeySerialized(gripA) { count += 1; return 42 }
        XCTAssertEqual(count, 1)
        XCTAssertEqual(out, 42)
    }
}
