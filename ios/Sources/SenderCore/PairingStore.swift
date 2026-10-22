import CryptoKit
import Foundation

/// The paired configuration: what is not secret (address, label, fingerprint) lives in the shared container,
/// the secrets in the Keychain. Both the app and the share extension read it; only the app writes it.
public struct Pairing: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "Pairing(\(server.host), \(label), check \(fingerprint))" }
    public var debugDescription: String { description }
    public let server: ServerURL
    public let label: String
    public let fingerprint: String
    public let inboxPub: [UInt8]
    public let kAuth: [UInt8]
    public let token: String
}

public struct PublicPairing: Codable, Equatable, Sendable {
    public let url: String
    public let label: String
    public let fp: String
}

public final class PairingStore: @unchecked Sendable {
    public static let fileName = "pairing.json"
    private let directory: URL
    private let secrets: SecretStoring
    private let files: FileProtecting

    public init(directory: URL, secrets: SecretStoring, files: FileProtecting = NoProtection()) {
        self.directory = directory
        self.secrets = secrets
        self.files = files
    }

    private var publicURL: URL { directory.appendingPathComponent(Self.fileName) }

    public func save(_ p: SenderPayload) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        // The saved address and check value go last: a failure half way leaves a pairing `state()` rejects
        // (the check value must match the key), never new keys with an old address.
        try? FileManager.default.removeItem(at: publicURL)
        try secrets.write(.token, Data(p.token.utf8))
        try secrets.write(.kAuth, Data(p.kAuth))
        try secrets.write(.inboxPub, Data(p.inboxPub))
        let pub = PublicPairing(url: p.server.canonical, label: p.label, fp: p.fingerprint)
        try JSONEncoder().encode(pub).write(to: publicURL, options: .atomic)
        try files.protect(publicURL)
    }

    public enum State: Equatable, Sendable {
        case notPaired
        /// Saved, but the Keychain will not give the keys out now (the phone is locked).
        case keychainLocked
        case paired(Pairing)
    }

    /// The pairing state. A partial or damaged pairing counts as not paired; a locked Keychain is told apart.
    public func state() -> State {
        guard let data = try? Data(contentsOf: publicURL), let pub = try? JSONDecoder().decode(PublicPairing.self, from: data),
              let server = try? ServerURL.parse(pub.url) else { return .notPaired }
        func read(_ i: SecretItem) -> (Data?, locked: Bool) {
            do { return (try secrets.read(i), false) }
            catch let e as SecretStoreError { return (nil, e.status == -25308 || e.status == -25293 || e.status == -25295) }
            catch { return (nil, false) }
        }
        let (t, l1) = read(.token), (a, l2) = read(.kAuth), (k, l3) = read(.inboxPub)
        if l1 || l2 || l3 { return .keychainLocked }
        guard let t, let token = String(data: t, encoding: .utf8), let a, a.count == 32, let k, k.count == 32 else { return .notPaired }
        // The saved check value must belong to the saved key.
        guard PairingStore.fingerprint(of: [UInt8](k)) == pub.fp else { return .notPaired }
        return .paired(Pairing(server: server, label: pub.label, fingerprint: pub.fp, inboxPub: [UInt8](k), kAuth: [UInt8](a), token: token))
    }

    public func load() -> Pairing? {
        if case .paired(let p) = state() { return p }
        return nil
    }

    /// What an upload needs: the address, the token (readable after the first unlock) and the check value. Not the
    /// sealing keys, which are only readable while the phone is unlocked.
    public struct UploadInfo: Equatable, Sendable { public let server: ServerURL; public let token: String; public let fingerprint: String }

    public func loadUploadInfo() -> UploadInfo? {
        guard let data = try? Data(contentsOf: publicURL), let pub = try? JSONDecoder().decode(PublicPairing.self, from: data),
              let server = try? ServerURL.parse(pub.url),
              let t = try? secrets.read(.token), let token = String(data: t, encoding: .utf8) else { return nil }
        return UploadInfo(server: server, token: token, fingerprint: pub.fp)
    }

    static func fingerprint(of pub: [UInt8]) -> String {
        SHA256.hash(data: Data(pub)).prefix(4).map { String(format: "%02x", $0) }.joined()
    }

    public func publicInfo() -> PublicPairing? {
        guard let data = try? Data(contentsOf: publicURL) else { return nil }
        return try? JSONDecoder().decode(PublicPairing.self, from: data)
    }

    /// Removes the secrets and the saved address. The caller also clears the outbox and the history.
    public func remove() throws {
        try secrets.deleteAll()
        try? FileManager.default.removeItem(at: publicURL)
    }
}

/// Applies the file protection and backup exclusion the owner asked for to files we write.
public protocol FileProtecting: Sendable {
    func protect(_ url: URL) throws
}

public struct NoProtection: FileProtecting {
    public init() {}
    public func protect(_ url: URL) throws {}
}

/// iOS: complete protection until first unlock, and never in a backup. (On macOS, for tests, only the backup flag.)
public struct StandardFileProtection: FileProtecting {
    public init() {}
    public func protect(_ url: URL) throws {
        var u = url
        var v = URLResourceValues()
        v.isExcludedFromBackup = true
        try u.setResourceValues(v)
        #if os(iOS)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: url.path)
        #endif
    }
}
