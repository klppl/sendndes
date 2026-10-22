#if canImport(UIKit)
import SenderUI
import SwiftUI
import UIKit

/// The app: a thin shell around SenderUI. All logic is in SenderCore, all screens in SenderUI.
@main
struct SendndesApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        WindowGroup {
            if let model = AppEnvironment.model {
                SenderRootView(model: model)
            } else {
                Text("send n*des could not open its storage.").padding()
            }
        }
    }
}

enum AppEnvironment {
    static let appGroup = "group.se.klippel.sendndes"
    static let sessionIdentifier = "se.klippel.sendndes.ios.upload"
    /// `$(AppIdentifierPrefix)se.klippel.sendndes.shared`, filled in by Xcode from the signing team (project.yml).
    static var keychainGroup: String? { Bundle.main.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String }

    @MainActor static let model: SenderModel? = {
        let env = SenderEnvironment.live(appGroup: appGroup, keychainGroup: keychainGroup, sessionIdentifier: sessionIdentifier)
        return try? SenderModel(env: env)
    }()
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, handleEventsForBackgroundURLSession identifier: String, completionHandler: @escaping () -> Void) {
        let done = UncheckedSendable(completionHandler)
        Task { @MainActor in AppEnvironment.model?.handleBackgroundEvents(identifier: identifier) { DispatchQueue.main.async { done.value() } } }
    }
}

struct UncheckedSendable<T>: @unchecked Sendable { let value: T; init(_ v: T) { value = v } }
#else
@main struct SendndesAppStub { static func main() {} }
#endif
