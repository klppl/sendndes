import Foundation
import Observation
import SenderCore
import SwiftUI
import UniformTypeIdentifiers

/// The share sheet's work: take what the host app handed over, seal each item straight from its file, queue the
/// uploads. Nothing here keeps a plaintext copy except text and links, which have no file to start from; those
/// small temporary files are deleted right after sealing.
@MainActor @Observable
public final class ShareFlowModel {
    public enum RowState: Equatable {
        case waiting, sealing, queued
        case skipped(String)
        case failed(String)
    }

    public struct Row: Identifiable, Equatable {
        public let id = UUID()
        public var title: String
        public var state: RowState = .waiting
    }

    public private(set) var rows: [Row] = []
    public private(set) var finished = false
    public private(set) var notPaired = false
    public private(set) var anyTooLarge = false
    private var cancelled = false
    private var sealedIDs: [String] = []
    private var outbox: Outbox?
    public var queuedCount: Int { rows.filter { $0.state == .queued }.count }

    /// Keeps the extension's session alive while it runs.
    private var sessionHold: (BackgroundUploader, AnyObject)?
    private let env: SenderEnvironment
    private let providers: [NSItemProvider]
    private let secrets: SecretStoring

    public init(env: SenderEnvironment, providers: [NSItemProvider], secrets: SecretStoring? = nil) {
        self.env = env
        self.providers = providers
        self.secrets = secrets ?? KeychainSecrets(accessGroup: env.keychainGroup)
        rows = providers.enumerated().map { i, p in
            Row(title: p.suggestedName.flatMap { $0.isEmpty ? nil : $0 } ?? "Item \(i + 1)")
        }
    }

    /// Cancel means cancel: what was sealed in this run is removed again, nothing is sent.
    public func cancel() {
        cancelled = true
        for id in sealedIDs { outbox?.discardQuietly(id) }
        sealedIDs = []
        for i in rows.indices where rows[i].state == .queued || rows[i].state == .waiting || rows[i].state == .sealing {
            rows[i].state = .skipped("Cancelled.")
        }
    }

    /// Plaintext leftovers of text and link shares from a crashed run (only old ones: another run may be active).
    private func sweepOldTemporaries() {
        let tmp = FileManager.default.temporaryDirectory
        for u in (try? FileManager.default.contentsOfDirectory(at: tmp, includingPropertiesForKeys: [.contentModificationDateKey])) ?? [] where u.lastPathComponent.hasPrefix("share-") {
            let m = (try? u.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantPast
            if Date().timeIntervalSince(m) > 3600 { try? FileManager.default.removeItem(at: u) }
        }
    }

    public func run() async {
        defer { finished = true }
        sweepOldTemporaries()
        let store = PairingStore(directory: env.configDirectory, secrets: secrets, files: StandardFileProtection())
        guard let pairing = store.load(), let outbox = try? Outbox(directory: env.outboxDirectory, files: StandardFileProtection()) else {
            notPaired = true
            return
        }
        self.outbox = outbox
        let settings = SenderSettings.load(env)
        let sealer = ShareSealer(pairing: pairing, outbox: outbox, files: StandardFileProtection(), folder: settings.folder)
        for i in rows.indices {
            if cancelled { break }
            if i >= SenderLimits.maxItemsPerShare {
                rows[i].state = .skipped("Only \(SenderLimits.maxItemsPerShare) items can be sent at once.")
                continue
            }
            rows[i].state = .sealing
            do {
                let item = try await ItemExtractor.seal(provider: providers[i], with: sealer)
                if cancelled { outbox.discardQuietly(item.id); continue }
                sealedIDs.append(item.id)
                rows[i].state = .queued
            } catch let e as SealError {
                switch e {
                case .tooLarge:
                    anyTooLarge = true
                    rows[i].state = .skipped(SenderLimits.tooLargeMessage)
                case .fileChanged: rows[i].state = .failed("The file changed while it was being locked. Share it again.")
                case .notARegularFile: rows[i].state = .failed("This item can't be sent as a file.")
                case .badFolder: rows[i].state = .failed("The folder name in Settings is not valid.")
                default: rows[i].state = .failed("This item could not be locked.")
                }
            } catch ItemExtractor.Failure.nothingToSend {
                rows[i].state = .failed("Nothing in this item can be sent.")
            } catch {
                rows[i].state = .failed("This item could not be read.")
            }
        }
        if queuedCount > 0, !cancelled {
            // Start the uploads from here: the system keeps them going after this extension is gone.
            // If this extension is still alive when an upload ends, record the result here; otherwise the app
            // is woken for this session's events and records it (SenderModel.handleBackgroundEvents).
            final class Hold: @unchecked Sendable { var coordinator: UploadCoordinator? }
            let hold = Hold()
            let up = BackgroundUploader(identifier: env.uploadSessionIdentifier + ".share", groupIdentifier: env.appGroup) { id, result in
                hold.coordinator?.handle(taskID: id, result: result)
            }
            let c = UploadCoordinator(outbox: outbox, pairings: store, transport: up, wifiOnly: { settings.wifiOnly })
            hold.coordinator = c
            sessionHold = (up, hold)
            c.startPending()
        }
    }
}

enum ItemExtractor {
    enum Failure: Error { case nothingToSend }

    /// Seals one item. File representations are only valid inside their completion handler, so the sealing
    /// happens there.
    static func seal(provider: NSItemProvider, with sealer: ShareSealer) async throws -> SealedItem {
        let name = provider.suggestedName
        let types = provider.registeredTypeIdentifiers.compactMap { UTType($0) }

        if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            let item = try await provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier)
            if let url = item as? URL, url.isFileURL { return try sealFileURL(url, name: name ?? url.lastPathComponent, sealer: sealer) }
        }
        if provider.hasItemConformingToTypeIdentifier(UTType.url.identifier) {
            let item = try await provider.loadItem(forTypeIdentifier: UTType.url.identifier)
            if let url = item as? URL {
                if url.isFileURL { return try sealFileURL(url, name: name ?? url.lastPathComponent, sealer: sealer) }
                let body = "[InternetShortcut]\r\nURL=\(url.absoluteString)\r\n"
                let base = FileNames.sanitize(name ?? url.host, fallback: "link")
                return try sealTemporary(Data(body.utf8), name: (base as NSString).deletingPathExtension + ".url", mime: "application/internet-shortcut", sealer: sealer)
            }
        }
        let isMedia = types.contains { $0.conforms(to: .image) || $0.conforms(to: .movie) || $0.conforms(to: .pdf) || $0.conforms(to: .audio) }
        if !isMedia, provider.hasItemConformingToTypeIdentifier(UTType.plainText.identifier) {
            let item = try await provider.loadItem(forTypeIdentifier: UTType.plainText.identifier)
            // A file behind the text is sealed in place, with no copy of it made here.
            if let url = item as? URL, url.isFileURL { return try sealFileURL(url, name: name ?? url.lastPathComponent, sealer: sealer) }
            if let d = item as? Data, Int64(d.count) > SenderLimits.maxFileBytes { throw SealError.tooLarge(Int64(d.count)) }
            let text: String? = (item as? String) ?? (item as? Data).flatMap { String(data: $0, encoding: .utf8) }
            if let text, !text.isEmpty {
                let base = FileNames.sanitize(name, fallback: FileNames.fallbackName(now: Date(), ext: "txt"))
                return try sealTemporary(Data(text.utf8), name: base.lowercased().hasSuffix(".txt") ? base : base + ".txt", mime: "text/plain", sealer: sealer)
            }
        }
        // Anything else with data behind it: photos, videos, PDFs, documents.
        guard let type = types.first(where: { $0.conforms(to: .data) && !$0.conforms(to: .url) }) ?? types.first(where: { $0.conforms(to: .item) }) else {
            throw Failure.nothingToSend
        }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<SealedItem, Error>) in
            provider.loadInPlaceFileRepresentation(forTypeIdentifier: type.identifier) { url, _, error in
                guard let url else { cont.resume(throwing: error ?? Failure.nothingToSend); return }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                var n = name ?? url.lastPathComponent
                if (n as NSString).pathExtension.isEmpty, let e = type.preferredFilenameExtension { n += "." + e }
                do { cont.resume(returning: try sealer.seal(fileAt: url, suggestedName: n, mime: type.preferredMIMEType)) }
                catch { cont.resume(throwing: error) }
            }
        }
    }

    private static func sealFileURL(_ url: URL, name: String, sealer: ShareSealer) throws -> SealedItem {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return try sealer.seal(fileAt: url, suggestedName: name)
    }

    /// Text and links have no file; a small private temporary file stands in and is removed at once.
    private static func sealTemporary(_ data: Data, name: String, mime: String, sealer: ShareSealer) throws -> SealedItem {
        guard Int64(data.count) <= SenderLimits.maxFileBytes else { throw SealError.tooLarge(Int64(data.count)) }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("share-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let f = dir.appendingPathComponent("item")
        guard FileManager.default.createFile(atPath: f.path, contents: data, attributes: [.posixPermissions: 0o600]) else { throw SealError.cannotRead }
        return try sealer.seal(fileAt: f, suggestedName: name, mime: mime)
    }
}

/// The share sheet's screen.
public struct ShareFlowView: View {
    @Bindable var model: ShareFlowModel
    let done: () -> Void

    public init(model: ShareFlowModel, done: @escaping () -> Void) {
        self.model = model
        self.done = done
    }

    public var body: some View {
        ZStack {
            Theme.paper.ignoresSafeArea()
            VStack(spacing: 14) {
                HStack(spacing: 12) {
                    Aster(mood: mood, size: 52)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("send n*des").display(24).foregroundStyle(Theme.ink)
                        Text(verbatim: subtitle).label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
                    }
                    Spacer()
                }
                if model.notPaired {
                    Banner(kind: .warn, text: "This phone is not paired yet. Open send n*des and scan the QR code from your Mac first.")
                }
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(model.rows) { row in rowView(row) }
                    }
                }
                if model.anyTooLarge { Note(text: SenderLimits.tooLargeMessage) }
                if model.finished && model.queuedCount > 0 {
                    Note(text: "They are sent in the background. Open send n*des to see how it went.")
                }
                Button(model.finished ? "Done" : "Cancel") {
                    if !model.finished { model.cancel() }
                    done()
                }
                .buttonStyle(model.finished ? .chunkyPrimary : .chunky)
            }
            .padding(20)
        }
        .tint(Theme.pink)
        .task { await model.run() }
    }

    private var mood: Aster.Mood {
        if !model.finished { return .working }
        return model.rows.contains { if case .failed = $0.state { return true }; return false } || model.notPaired ? .oops : .happy
    }

    private var subtitle: String {
        if !model.finished { return "Locking and queuing…" }
        let n = model.queuedCount
        return n == 0 ? "Nothing was queued." : "\(n) \(plural(n, "item", "items")) locked and queued."
    }

    private func rowView(_ row: ShareFlowModel.Row) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(verbatim: row.title).label(.callout, weight: .semibold).foregroundStyle(Theme.ink).lineLimit(1).truncationMode(.middle)
                Spacer()
                switch row.state {
                case .waiting: Pill(text: "Waiting")
                case .sealing: Pill(text: "Locking", tint: Theme.grape, spinner: true)
                case .queued: Pill(text: "Queued", icon: "lock.fill", tint: Theme.mint)
                case .skipped: Pill(text: "Not sent", icon: "xmark", tint: Theme.amber)
                case .failed: Pill(text: "Failed", icon: "exclamationmark.triangle.fill", tint: Theme.tomato)
                }
            }
            switch row.state {
            case .skipped(let r), .failed(let r): Text(verbatim: r).font(.caption).foregroundStyle(Theme.tomatoText)
            default: EmptyView()
            }
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading).sticker(radius: 14, shadow: 2)
    }
}
