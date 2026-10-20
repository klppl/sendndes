import AppCore
import AppKit
import SwiftUI

@MainActor
final class AppState {
    static let shared = AppState()
    let model: AppModel
    private var signalSources: [DispatchSourceSignal] = []
    private var systemLock: SystemLockObserver?
    private var activity: ActivityMonitor?

    private init() {
        UserDefaults.standard.register(defaults: ["NSQuitAlwaysKeepsWindows": false])
        signal(SIGPIPE, SIG_IGN)
        TokenFile.sweep()
        let path = Self.helperPath()
        model = AppModel(secrets: KeychainSecretStore(),
                         runner: HelperRunner(helperPath: path, expectedSHA256: helperSHA256),
                         biometric: KeychainBiometricStore())
        let m = model
        systemLock = SystemLockObserver(onLock: { m.lockForSystemEvent() })
        activity = ActivityMonitor(model: m)
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler { [model] in
                MainActor.assumeIsolated { model.lock() }
                exit(128 + sig)
            }
            src.resume()
            signalSources.append(src)
        }
    }

    /// realpath of the bundle once, then the fixed helper slot.
    static func helperPath() -> String {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        let bundle = Bundle.main.bundleURL.path
        guard realpath(bundle, &buf) != nil else { return "/nonexistent" }
        return String(cString: buf) + "/Contents/Helpers/valv"
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { AppState.shared.model.lock() }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct SendndesApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Window("send n*des", id: "main") {
            ContentView(model: AppState.shared.model)
                .frame(minWidth: 900, minHeight: 600)
        }
        .defaultSize(width: 1100, height: 760)
        .commands { AppCommands(model: AppState.shared.model) }

        Settings { SettingsView(model: AppState.shared.model) }
    }
}
