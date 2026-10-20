import AppKit
import Foundation

/// M1: system events that lock the app at once: sleep, screen sleep, fast user switching / session resign,
/// screen lock and the screensaver. The callback runs on the main thread.
@MainActor
public final class SystemLockObserver {
    public static let workspaceEvents: [Notification.Name] = [
        NSWorkspace.willSleepNotification,
        NSWorkspace.screensDidSleepNotification,
        NSWorkspace.sessionDidResignActiveNotification,
    ]
    public static let distributedEvents: [Notification.Name] = [
        Notification.Name("com.apple.screenIsLocked"),
        Notification.Name("com.apple.screensaver.didstart"),
    ]

    private var tokens: [(NotificationCenter, NSObjectProtocol)] = []

    public init(onLock: @escaping @MainActor () -> Void) {
        let handler: @Sendable (Notification) -> Void = { _ in
            if Thread.isMainThread { MainActor.assumeIsolated { onLock() } }
            else { DispatchQueue.main.async { MainActor.assumeIsolated { onLock() } } }
        }
        for n in Self.workspaceEvents {
            tokens.append((NSWorkspace.shared.notificationCenter,
                           NSWorkspace.shared.notificationCenter.addObserver(forName: n, object: nil, queue: nil, using: handler)))
        }
        for n in Self.distributedEvents {
            tokens.append((DistributedNotificationCenter.default(),
                           DistributedNotificationCenter.default().addObserver(forName: n, object: nil, queue: nil, using: handler)))
        }
    }

    public func stop() {
        for (c, t) in tokens { c.removeObserver(t) }
        tokens = []
    }
}

/// Reports user input in the app's own windows to the model and runs the inactivity check every few seconds.
@MainActor
public final class ActivityMonitor {
    private var monitor: Any?
    private var timer: Timer?

    public init(model: AppModel, tickSeconds: TimeInterval = 5) {
        monitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .scrollWheel, .mouseMoved]) { [weak model] event in
            MainActor.assumeIsolated { model?.noteActivity() }
            return event
        }
        timer = Timer.scheduledTimer(withTimeInterval: tickSeconds, repeats: true) { [weak model] _ in
            MainActor.assumeIsolated { _ = model?.inactivityTick() }
        }
    }

    public func stop() {
        if let m = monitor { NSEvent.removeMonitor(m) }
        monitor = nil
        timer?.invalidate()
        timer = nil
    }
}
