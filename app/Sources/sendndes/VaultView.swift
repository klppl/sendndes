import AppCore
import AppKit
import QuickLook
import SwiftUI

struct VaultView: View {
    @Bindable var model: AppModel
    let openCreate: () -> Void
    let goSend: () -> Void

    var body: some View {
        switch model.lockState {
        case .noFolder: WelcomeView(model: model, openCreate: openCreate, goSend: goSend)
        case .locked, .unlocking: LockScreen(model: model, openCreate: openCreate)
        case .unlocked: VaultBrowser(model: model)
        }
    }
}

// MARK: Unlocked

struct VaultBrowser: View {
    @Bindable var model: AppModel
    @State private var selection = Set<FileEntry.ID>()
    @State private var query = ""
    @State private var targeted = false
    @State private var quickLook: URL?
    @State private var confirmOpen: FileEntry?
    @AppStorage(Prefs.skipOpenWarning) private var skipOpenWarning = false

    private var visible: [FileEntry] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return model.entries }
        return model.entries.filter { $0.name.localizedCaseInsensitiveContains(q) || $0.dir.localizedCaseInsensitiveContains(q) }
    }

    private var chosen: [FileEntry] { visible.filter { selection.contains($0.id) } }

    private var subtitle: String {
        let n = model.entries.count
        if n == 0 { return "Empty. Suspiciously tidy." }
        let size = ByteCountFormatter.string(fromByteCount: model.entries.reduce(0) { $0 + $1.size }, countStyle: .file)
        return "\(n) \(plural(n, "file", "files")) · \(size), all sealed."
    }

    var body: some View {
        let shown = visible
        let arrived = model.arrivedIDs
        VStack(alignment: .leading, spacing: 12) {
            PaneHeader(mood: model.busy || model.adding || model.pullRunning ? .working : .smitten, title: "Your vault",
                       subtitle: subtitle, sparkle: model.addItems.filter { $0.state == .sent }.count + arrived.count) {
                HStack(spacing: 8) {
                    if model.serverConfigured { inboxButton }
                    Button { Task { await model.rebuildListing() } } label: {
                        Image(systemName: "arrow.clockwise").frame(height: 20)
                    }
                    .buttonStyle(.chunkyQuiet).disabled(model.busy)
                    .help("Refresh the list (⌘R)").accessibilityLabel("Refresh")
                    Button { FilePanels.addToVault(model) } label: { Label("Add files…", systemImage: "plus") }
                        .buttonStyle(.chunkyPrimary).disabled(model.adding)
                }
                .lineLimit(1)
                .fixedSize()   // buttons keep one line; the title side gives way instead
            }
            banners
            if !model.addItems.isEmpty { addingList }
            table(shown, arrived: arrived)
            selectionBar
        }
        .padding(20)
        .overlay { if targeted { DropHint(title: "Drop to seal it in").padding(10) } }
        .animation(.snappy(duration: 0.18), value: targeted)
        .animation(.snappy(duration: 0.18), value: selection.isEmpty)
        .dropDestination(for: URL.self) { urls, _ in
            model.addToVault(urls: urls.filter { $0.isFileURL })
            return true
        } isTargeted: { targeted = $0 }
        .searchable(text: $query, placement: .toolbar, prompt: "Search names and folders")
        .onChange(of: query) { _, _ in selection = selection.intersection(Set(visible.map(\.id))) }
        .onChange(of: model.adding) { _, _ in clearWhenSealed() }
        .onAppear { clearWhenSealed() }
        .quickLookPreview($quickLook)
        .alert("Open a decrypted copy?", isPresented: Binding(get: { confirmOpen != nil }, set: { if !$0 { confirmOpen = nil } }),
               presenting: confirmOpen) { e in
            Button("Open") { open(e) }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("The vault no longer protects the copy. It sits in a private temporary folder and is deleted when you lock or quit, but the app you open it in may keep its own copy (recent files, autosave).")
        }
        .dialogSuppressionToggle("Don't ask again", isSuppressed: $skipOpenWarning)
    }

    // MARK: Inbox

    private var inboxButton: some View {
        Button { Task { await model.pullAndRefresh() } } label: {
            HStack(spacing: 6) {
                if model.pullRunning { ProgressView().controlSize(.small) } else { Image(systemName: "tray.and.arrow.down.fill") }
                Text(model.pullRunning ? "Checking…" : "Check inbox")
            }
        }
        .buttonStyle(.chunky).disabled(model.pullRunning)
        .help("Bring in files waiting on your server (⇧⌘I)")
    }

    /// One summary for the last pull, with the details a click away.
    @ViewBuilder private var inboxBanner: some View {
        if let m = model.pullMessage {
            Banner(kind: .error, text: m, actionTitle: model.pullRunning ? nil : "Try again") {
                Task { await model.pullAndRefresh() }
            }
        } else if model.pullSummary != nil {
            let items = model.pullItems
            let added = items.filter { $0.kind == .ingested }.count
            let trouble = items.filter { $0.kind != .ingested && $0.kind != .alreadyIngested }
            if added > 0 || !trouble.isEmpty {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Banner(kind: trouble.isEmpty ? .success : .warn, text: inboxText(added: added, trouble: trouble.count))
                    if !trouble.isEmpty { PullDetails(items: items) }
                }
            }
        }
    }

    private func inboxText(added: Int, trouble: Int) -> String {
        var s = added > 0 ? "\(added) new \(plural(added, "file", "files")) arrived from your inbox, marked new below." : "Nothing new in your inbox."
        if trouble > 0 { s += " \(trouble) couldn't be brought in and \(plural(trouble, "was", "were")) left on the server." }
        return s
    }

    // MARK: Banners and progress

    @ViewBuilder private var banners: some View {
        inboxBanner
        if model.listingProblems > 0 {
            Banner(kind: .warn, text: "\(model.listingProblems) \(plural(model.listingProblems, "file has a problem", "files have problems")). Run `valv verify` in Terminal for details.")
        }
        if model.listingStale { Banner(kind: .info, text: "The list may be out of date.", actionTitle: "Refresh") { Task { await model.rebuildListing() } } }
        ForEach(model.addNotes, id: \.self) { Banner(kind: .info, text: $0) }
        if let m = model.vaultMessage { Banner(kind: .error, text: m) }
        if let m = model.openMessage { Banner(kind: .warn, text: m) }
        if let m = model.exportMessage {
            Banner(kind: .success, text: m,
                   actionTitle: model.exportFolder == nil ? nil : "Show in Finder",
                   action: { if let f = model.exportFolder { NSWorkspace.shared.open(URL(fileURLWithPath: f)) } })
        }
    }

    private var addingList: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Sealing files in").label(.callout, weight: .bold).foregroundStyle(Theme.ink)
                Spacer()
                if model.addItems.contains(where: { $0.state == .sent }) {
                    Button("Clear finished") { model.clearAddFinished() }.buttonStyle(.chunkyQuietSmall)
                }
            }
            // As tall as its rows (about 44 pt each), up to four rows, then it scrolls.
            TransferList(items: model.addItems, activeText: "sealing…", doneText: "sealed")
                .frame(height: min(CGFloat(model.addItems.count) * 44, 176))
        }
        .transition(.opacity)
    }

    /// Once everything is sealed the files are in the table below, so the progress list goes away by itself.
    /// Failures stay until cleared.
    private func clearWhenSealed() {
        guard !model.adding, !model.addItems.isEmpty, model.addItems.allSatisfy({ $0.state == .sent }) else { return }
        Task {
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            guard !model.adding, model.addItems.allSatisfy({ $0.state == .sent }) else { return }
            withAnimation(.snappy(duration: 0.25)) { model.clearAddFinished() }
        }
    }

    // MARK: Table

    private func table(_ shown: [FileEntry], arrived: Set<String>) -> some View {
        Table(shown, selection: $selection) {
            TableColumn("Name") { e in
                HStack(spacing: 8) {
                    FileGlyph(name: e.name, size: 20)
                    Text(verbatim: e.name).label(.body, weight: .semibold).lineLimit(1).truncationMode(.middle)
                    if arrived.contains(e.id) { Pill(text: "new", tint: Theme.mint) }
                }
            }
            .width(min: 150, ideal: 220)
            TableColumn("Folder") { e in Text(verbatim: e.dir).foregroundStyle(Theme.inkSoft).lineLimit(1).truncationMode(.middle) }
                .width(min: 50, ideal: 80)
            TableColumn("Size") { e in Text(verbatim: ByteCountFormatter.string(fromByteCount: e.size, countStyle: .file)) }
                .width(70)
            TableColumn("Modified") { e in
                Text(verbatim: e.mtime.formatted(.dateTime.year().month(.abbreviated).day()))
                    .help(e.mtime.formatted(date: .complete, time: .shortened))
            }
            .width(min: 90, ideal: 100)
            TableColumn("ID") { e in Text(verbatim: e.shortID).font(.system(.callout, design: .monospaced)).foregroundStyle(Theme.inkSoft) }
                .width(72)
        }
        .scrollContentBackground(.hidden)
        .frame(minHeight: 140, idealHeight: 340)
        .background(Theme.card)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2))
        .overlay { if shown.isEmpty { emptyTable } }
        .onKeyPress(.space) {
            guard chosen.count == 1 else { return .ignored }
            previewSelected()
            return .handled
        }
        .contextMenu(forSelectionType: FileEntry.ID.self) { ids in
            if ids.count == 1 {
                Button("Quick Look") { selection = ids; previewSelected() }
                Button("Open") { selection = ids; openSelected() }
            }
            Button("Export…") { selection = ids; exportSelected() }
        } primaryAction: { ids in
            if ids.count == 1 { selection = ids; openSelected() }
        }
    }

    private var emptyTable: some View {
        VStack(spacing: 8) {
            Aster(mood: model.entries.isEmpty ? .asleep : .oops, size: 84)
            if model.entries.isEmpty {
                Text("Nothing in here yet").display(20).foregroundStyle(Theme.ink)
                Text("Drop files anywhere in this window, or press ⌘O.").label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
            } else {
                Text("No matches").display(20).foregroundStyle(Theme.ink)
                Text(verbatim: "Nothing in the vault matches “\(query)”.").label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
            }
        }
        .padding(.top, 24)
        .allowsHitTesting(false)
    }

    /// Actions for the selection, shown only while something is selected.
    @ViewBuilder private var selectionBar: some View {
        let c = chosen
        if !c.isEmpty {
            HStack(spacing: 10) {
                Text("\(c.count) selected").label(.callout, weight: .bold).foregroundStyle(Theme.ink)
                Spacer()
                if c.count == 1 {
                    Button { previewSelected() } label: { Label("Quick Look", systemImage: "eye") }
                        .buttonStyle(.chunkySmall).disabled(model.busy).help("Preview without leaving the app (Space)")
                    Button { openSelected() } label: { Label("Open", systemImage: "arrow.up.forward.app") }
                        .buttonStyle(.chunkySmall).disabled(model.busy)
                }
                Button { exportSelected() } label: { Label("Export…", systemImage: "square.and.arrow.up") }
                    .buttonStyle(.chunkySmall).disabled(model.exporting)
                HelpTip(title: "Open, Quick Look and Export",
                        text: "These make decrypted copies the vault no longer protects. Quick Look and Open use a private temporary folder that is emptied when you lock or quit; the app you open a file in may keep its own copy. Exported copies stay where you put them, so avoid synced or indexed folders.")
            }
            .padding(.horizontal, 12).padding(.vertical, 7)
            .sticker(radius: 12)
            .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }

    // MARK: Actions

    private func previewSelected() {
        guard chosen.count == 1, let e = chosen.first else { return }
        Task { if let url = await model.prepareOpen(e) { quickLook = url } }
    }

    private func openSelected() {
        guard chosen.count == 1, let e = chosen.first else { return }
        if skipOpenWarning { open(e) } else { confirmOpen = e }
    }

    private func open(_ e: FileEntry) {
        Task { if let url = await model.prepareOpen(e) { NSWorkspace.shared.open(url) } }
    }

    private func exportSelected() {
        let chosen = self.chosen
        guard !chosen.isEmpty else { return }
        let p = NSOpenPanel()
        p.canChooseFiles = false; p.canChooseDirectories = true; p.canCreateDirectories = true; p.allowsMultipleSelection = false
        p.prompt = "Export here"
        p.message = "Exported files are not encrypted. Choose a folder outside the vault; avoid synced or indexed folders."
        if p.runModal() == .OK, let u = p.url { Task { await model.export(chosen, toFolder: u.path) } }
    }
}

/// What happened to each file in the last pull, for the ones that did not simply arrive.
private struct PullDetails: View {
    let items: [PullItem]
    @State private var shown = false

    var body: some View {
        Button("Details") { shown.toggle() }
            .buttonStyle(.chunkySmall)
            .popover(isPresented: $shown, arrowEdge: .bottom) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Last inbox check").label(.headline, weight: .bold).foregroundStyle(Theme.ink)
                    Text("Files are listed by id: their names stay sealed until they are in the vault.")
                        .font(.caption).foregroundStyle(Theme.inkSoft).fixedSize(horizontal: false, vertical: true)
                    ScrollView {
                        VStack(spacing: 0) {
                            ForEach(items) { item in
                                FileRow(name: String(item.id.prefix(8)), showsIcon: false, mono: true) { pill(item.kind) }
                            }
                        }
                    }
                    .frame(maxHeight: 260)
                }
                .padding(14).frame(width: 420)
            }
    }

    @ViewBuilder private func pill(_ kind: PullKind) -> some View {
        switch kind {
        case .ingested: Pill(text: "added", icon: "checkmark", tint: Theme.mint)
        case .alreadyIngested: Pill(text: "already in the vault", icon: "tray.full", tint: Theme.inkSoft)
        case .notAuthentic: Pill(text: "not authentic, left on server", icon: "exclamationmark.triangle.fill", tint: Theme.tomato)
        case .conflict: Pill(text: "conflict, left on server", icon: "xmark", tint: Theme.tomato)
        case .error: Pill(text: "failed, left on server", icon: "xmark", tint: Theme.tomato)
        }
    }
}

// MARK: Transfer lists (Send queue, adding to the vault)

struct TransferList: View {
    let items: [SendItem]
    let activeText: String
    let doneText: String
    var retry: ((UUID) -> Void)?

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(Array(items.enumerated()), id: \.element.id) { i, item in
                    row(item)
                    if i < items.count - 1 { Divider().overlay(Theme.ink.opacity(0.12)).padding(.horizontal, 12) }
                }
            }
        }
        .sticker(radius: 14)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    @ViewBuilder private func row(_ item: SendItem) -> some View {
        switch item.state {
        case .waiting:
            FileRow(name: item.displayName) { Pill(text: "waiting", icon: "clock", tint: Theme.inkSoft) }
        case .sending:
            FileRow(name: item.displayName) { Pill(text: activeText, tint: Theme.grape, spinner: true) }
        case .sent:
            FileRow(name: item.displayName) { Pill(text: doneText, icon: "checkmark", tint: Theme.mint) }
        case .failed(let m):
            FileRow(name: item.displayName, detail: m, detailIsError: true) {
                HStack(spacing: 8) {
                    Pill(text: "failed", icon: "xmark", tint: Theme.tomato)
                    if let retry {
                        Button("Retry") { retry(item.id) }.buttonStyle(.chunkySmall)
                            .help("Sends the file again from the start. If the first try actually arrived, the vault gets a duplicate.")
                    }
                }
            }
        }
    }
}
