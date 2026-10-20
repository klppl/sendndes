import SwiftUI

// MARK: Buttons

/// Chunky sticker button: ink outline, hard shadow, presses down into it.
struct ChunkyButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary, quiet }
    var kind: Kind = .secondary
    var compact = false
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        let pressed = configuration.isPressed
        let shape = RoundedRectangle(cornerRadius: compact ? 9 : 12, style: .continuous)
        let raised: CGFloat = kind == .quiet ? 0 : 3
        let fill: Color = switch kind {
        case .primary: Theme.pink
        case .secondary: Theme.card
        case .quiet: Color.clear
        }
        configuration.label
            .label(compact ? .callout : .body)
            .foregroundStyle(kind == .primary ? Theme.onAccent : Theme.ink)
            .padding(.horizontal, compact ? 10 : 15).padding(.vertical, compact ? 5 : 8)
            .background {
                ZStack {
                    if raised > 0 && enabled { shape.fill(Theme.ink).offset(x: raised, y: raised) }
                    shape.fill(fill)
                    if kind == .quiet && pressed { shape.fill(Theme.ink.opacity(0.1)) }
                }
            }
            .overlay { if kind != .quiet { shape.strokeBorder(Theme.ink, lineWidth: 2) } }
            .offset(x: pressed && raised > 0 && enabled ? raised : 0, y: pressed && raised > 0 && enabled ? raised : 0)
            .padding(.trailing, raised).padding(.bottom, raised)
            .opacity(enabled ? 1 : 0.45)
            .contentShape(Rectangle())
            .animation(.snappy(duration: 0.1), value: pressed)
    }
}

extension ButtonStyle where Self == ChunkyButtonStyle {
    static var chunky: ChunkyButtonStyle { .init(kind: .secondary) }
    static var chunkyPrimary: ChunkyButtonStyle { .init(kind: .primary) }
    static var chunkyQuiet: ChunkyButtonStyle { .init(kind: .quiet) }
    static var chunkySmall: ChunkyButtonStyle { .init(kind: .secondary, compact: true) }
    static var chunkyQuietSmall: ChunkyButtonStyle { .init(kind: .quiet, compact: true) }
}

// MARK: Text field

struct StickerFieldStyle: TextFieldStyle {
    var icon: String?
    func _body(configuration: TextField<Self._Label>) -> some View {
        HStack(spacing: 8) {
            if let icon { Image(systemName: icon).foregroundStyle(Theme.inkSoft).frame(width: 18) }
            configuration.textFieldStyle(.plain)
        }
        .label(.body, weight: .medium)
        .padding(.horizontal, 12).padding(.vertical, 9)
        .background(Theme.paper, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2))
    }
}

// MARK: Banner, pill, note

struct Banner: View {
    enum Kind {
        case error, warn, info, success
        var icon: String {
            switch self {
            case .error: "exclamationmark.triangle.fill"
            case .warn: "exclamationmark.circle.fill"
            case .info: "info.circle.fill"
            case .success: "checkmark.circle.fill"
            }
        }
        var tint: Color {
            switch self {
            case .error: Theme.tomato
            case .warn: Theme.amber
            case .info: Theme.grape
            case .success: Theme.mint
            }
        }
    }

    let kind: Kind
    let text: String
    var actionTitle: String?
    var action: () -> Void = {}

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: kind.icon).foregroundStyle(kind.tint)
            Text(verbatim: text).label(.callout, weight: .medium).foregroundStyle(Theme.ink)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let actionTitle { Button(actionTitle, action: action).buttonStyle(.chunkySmall) }
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .background(kind.tint.opacity(0.17), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(kind.tint, lineWidth: 2))
        .accessibilityElement(children: .combine)
    }
}

struct Pill: View {
    let text: String
    var icon: String?
    var tint: Color = Theme.inkSoft
    var spinner = false

    var body: some View {
        HStack(spacing: 5) {
            if spinner { ProgressView().controlSize(.mini).scaleEffect(0.8) }
            else if let icon { Image(systemName: icon).font(.system(size: 11, weight: .black)).foregroundStyle(tint) }
            Text(verbatim: text)
        }
        .label(.caption, weight: .bold)
        .foregroundStyle(Theme.ink)
        .padding(.horizontal, 9).padding(.vertical, 4)
        .background(tint.opacity(0.22), in: Capsule())
        .overlay(Capsule().strokeBorder(tint, lineWidth: 1.5))
        .fixedSize()
    }
}

/// Small print that matters: kept visible and in full, just quieter.
struct Note: View {
    let text: String
    var body: some View {
        HStack(alignment: .top, spacing: 7) {
            Image(systemName: "info.circle").foregroundStyle(Theme.inkSoft).padding(.top, 1)
            Text(verbatim: text).font(.caption).foregroundStyle(Theme.inkSoft)
                
        }
    }
}

// MARK: Empty / centered states

struct EmptyState: View {
    var mood: Eggy.Mood
    let title: String
    let text: String
    var button: String?
    var action: () -> Void = {}
    var secondaryButton: String?
    var secondaryAction: () -> Void = {}

    var body: some View {
        VStack(spacing: 12) {
            Eggy(mood: mood, size: 116, interactive: true)
            Text(title).display(24).foregroundStyle(Theme.ink).multilineTextAlignment(.center)
            Text(text).label(.body, weight: .medium).foregroundStyle(Theme.inkSoft)
                .multilineTextAlignment(.center).frame(maxWidth: 400)
            if button != nil || secondaryButton != nil {
                HStack(spacing: 10) {
                    if let button { Button(button, action: action).buttonStyle(.chunkyPrimary) }
                    if let secondaryButton { Button(secondaryButton, action: secondaryAction).buttonStyle(.chunky) }
                }
                .padding(.top, 6)
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Screen heading: mascot, title, one line of subtitle.
struct PaneHeader<Trailing: View>: View {
    let mood: Eggy.Mood
    let title: String
    let subtitle: String
    var sparkle = 0
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: 14) {
            Eggy(mood: mood, size: 66, interactive: true)
                .overlay { SparkleBurst(trigger: sparkle) }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).display(28).foregroundStyle(Theme.ink)
                Text(verbatim: subtitle).label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
            }
            Spacer(minLength: 12)
            trailing
        }
    }
}

/// A file or queue row: icon, name, optional detail line, and a trailing status.
struct FileRow<Trailing: View>: View {
    let name: String
    var detail: String?
    var detailIsError = false
    var showsIcon = true
    var mono = false
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: 11) {
            if showsIcon { FileGlyph(name: name, size: 24) }
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: name)
                    .font(mono ? .system(.body, design: .monospaced, weight: .medium) : .system(.body, design: .rounded, weight: .semibold))
                    .foregroundStyle(Theme.ink).lineLimit(1).truncationMode(.middle)
                if let detail {
                    Text(verbatim: detail).font(.caption)
                        .foregroundStyle(detailIsError ? Theme.tomatoText : Theme.inkSoft).lineLimit(3)
                }
            }
            Spacer(minLength: 8)
            trailing
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
    }
}

/// Dashed drop target overlay.
struct DropHint: View {
    let title: String
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.pink.opacity(0.16))
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(Theme.pink, style: StrokeStyle(lineWidth: 4, dash: [10, 8]))
            VStack(spacing: 8) {
                Eggy(mood: .wow, size: 96)
                Text(title).display(22).foregroundStyle(Theme.ink)
            }
        }
        .allowsHitTesting(false)
        .transition(.opacity.combined(with: .scale(scale: 0.98)))
    }
}

func plural(_ n: Int, _ one: String, _ many: String) -> String { n == 1 ? one : many }
