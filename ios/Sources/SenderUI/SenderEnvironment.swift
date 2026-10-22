import Foundation
import SenderCore

/// Where the app and its share extension keep things. The identifiers are placeholders the owner confirms
/// (project.yml): App Group `group.se.klippel.sendndes`, keychain group `$(AppIdentifierPrefix)se.klippel.sendndes.shared`.
public struct SenderEnvironment: Sendable {
    public let appGroup: String
    public let keychainGroup: String?
    public let uploadSessionIdentifier: String
    public let container: URL

    public init(appGroup: String, keychainGroup: String?, uploadSessionIdentifier: String, container: URL) {
        self.appGroup = appGroup
        self.keychainGroup = keychainGroup
        self.uploadSessionIdentifier = uploadSessionIdentifier
        self.container = container
    }

    /// The real one: the App Group container, falling back to Application Support (previews, tests).
    public static func live(appGroup: String, keychainGroup: String?, sessionIdentifier: String) -> SenderEnvironment {
        let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
            ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return SenderEnvironment(appGroup: appGroup, keychainGroup: keychainGroup, uploadSessionIdentifier: sessionIdentifier, container: base)
    }

    var outboxDirectory: URL { container.appendingPathComponent("outbox", isDirectory: true) }
    var configDirectory: URL { container.appendingPathComponent("config", isDirectory: true) }
    var settingsURL: URL { container.appendingPathComponent("config/settings.json") }
}

/// Non-secret settings shared by the app and the share extension.
public struct SenderSettings: Codable, Equatable, Sendable {
    public var folder: String = SenderLimits.defaultFolder
    public var wifiOnly: Bool = false

    static func load(_ env: SenderEnvironment) -> SenderSettings {
        guard let d = try? Data(contentsOf: env.settingsURL), let s = try? JSONDecoder().decode(SenderSettings.self, from: d) else { return SenderSettings() }
        var out = s
        if FileNames.validateFolder(out.folder) == nil { out.folder = SenderLimits.defaultFolder }
        return out
    }

    func save(_ env: SenderEnvironment) {
        try? FileManager.default.createDirectory(at: env.configDirectory, withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(self) {
            try? d.write(to: env.settingsURL, options: .atomic)
            try? StandardFileProtection().protect(env.settingsURL)
        }
    }
}
