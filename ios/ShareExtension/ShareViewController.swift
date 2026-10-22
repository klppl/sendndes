#if canImport(UIKit)
import SenderUI
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// The share sheet entry point. It seals each shared item on the phone and queues the upload; the work is in SenderUI.
final class ShareViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        let items = (extensionContext?.inputItems as? [NSExtensionItem]) ?? []
        let providers = items.flatMap { $0.attachments ?? [] }
        let env = SenderEnvironment.live(appGroup: "group.se.klippel.sendndes",
                                         keychainGroup: Bundle.main.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String,
                                         sessionIdentifier: "se.klippel.sendndes.ios.upload")
        let model = ShareFlowModel(env: env, providers: providers)
        let host = UIHostingController(rootView: ShareFlowView(model: model) { [weak self] in
            self?.extensionContext?.completeRequest(returningItems: nil)
        })
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }
}
#endif
