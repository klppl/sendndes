import Foundation
import Security

/// What a random draw is for. Lets the test hook hand out the fixed value
/// meant for each slot regardless of the order of draws.
enum RandomPurpose: Sendable {
    case vk, kdfSalt, vkWrapNonce
    case fileID, fk, fkWrapNonce, metaNonce
    case ephemeralKey
}

/// The only source of randomness in NdesCore: the OS CSPRNG.
enum Random {
    static func bytes(_ count: Int, for purpose: RandomPurpose) -> [UInt8] {
        #if NDES_TESTVECTORS
        if let source = TestHooks.fixedRandom {
            return source.next(purpose, count: count)
        }
        #endif
        guard count > 0 else { return [] }
        var out = [UInt8](repeating: 0, count: count)
        let rc = out.withUnsafeMutableBytes { p -> Int32 in
            guard let base = p.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        // There is no safe way to continue without randomness.
        precondition(rc == errSecSuccess, "SecRandomCopyBytes failed")
        return out
    }
}

#if NDES_TESTVECTORS
// Compiled only with `--traits NDES_TESTVECTORS`. A normal build has none of
// this; scripts/check-release-symbols.sh verifies that.

/// Fixed values for each random slot, consumed in order per slot.
final class FixedRandomSource: @unchecked Sendable {
    private let lock = NSLock()
    private var queues: [RandomPurpose: [[UInt8]]]

    init(_ values: [RandomPurpose: [[UInt8]]]) {
        self.queues = values
    }

    func next(_ purpose: RandomPurpose, count: Int) -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        guard var q = queues[purpose], !q.isEmpty else {
            fatalError("test hook: no fixed value for \(purpose)")
        }
        let v = q.removeFirst()
        queues[purpose] = q
        precondition(v.count == count, "test hook: \(purpose) needs \(count) bytes, got \(v.count)")
        return v
    }

    var isExhausted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return queues.values.allSatisfy { $0.isEmpty }
    }
}

enum TestHooks {
    /// Task-local, so parallel tests cannot see each other's fixed values.
    @TaskLocal static var fixedRandom: FixedRandomSource?

    static func withFixedRandom<T>(_ values: [RandomPurpose: [[UInt8]]],
                                   _ body: () throws -> T) throws -> (T, FixedRandomSource) {
        let source = FixedRandomSource(values)
        let result = try $fixedRandom.withValue(source) { try body() }
        return (result, source)
    }
}
#endif
