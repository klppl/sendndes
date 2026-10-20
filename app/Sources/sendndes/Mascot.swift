import SwiftUI

/// Aster, the asterisk from "n*des", with a face. Purely decorative (hidden from VoiceOver); the words
/// next to it always say the same thing. Idle motion stops when Reduce Motion is on.
struct Aster: View {
    enum Mood { case asleep, happy, wow, oops, working }

    var mood: Mood
    var size: CGFloat = 120
    var interactive = false
    /// No idle sway or breathing (used when rendering the app icon).
    var still = false

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var bob = false
    @State private var blink = false
    @State private var winking = false
    @State private var hop: CGFloat = 0
    @State private var spin = false

    private var outline: CGFloat { max(1.5, size * 0.035) }
    private var line: CGFloat { max(1.2, size * 0.026) }
    private var armLength: CGFloat { size * 0.94 }
    private var armThickness: CGFloat { size * 0.235 }

    var body: some View {
        ZStack {
            ZStack {
                arms(extra: outline * 2).foregroundStyle(Theme.ink)   // outline = the same shape, inked and fatter
                arms(extra: 0).foregroundStyle(Theme.pink)
            }
            .rotationEffect(.degrees(spin ? 360 : 0))
            face
            if mood == .asleep { zzz }
        }
        .frame(width: size, height: size)
        .rotationEffect(.degrees(reduceMotion || still ? 0 : (bob ? 3 : -3)))
        .scaleEffect(reduceMotion || still ? 1 : (bob ? 1.025 : 0.985))
        .offset(y: hop)
        .accessibilityHidden(true)
        .onTapGesture { if interactive { poke() } }
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.easeInOut(duration: mood == .asleep ? 2.8 : 1.9).repeatForever(autoreverses: true)) { bob = true }
            updateSpin()
        }
        .onChange(of: mood) { _, _ in updateSpin() }
        .task(id: mood) { await blinkLoop() }
    }

    // MARK: Pieces

    private func arms(extra: CGFloat) -> some View {
        ZStack {
            ForEach([30.0, 90.0, 150.0], id: \.self) { deg in
                Capsule().frame(width: armLength + extra, height: armThickness + extra).rotationEffect(.degrees(deg))
            }
        }
        .frame(width: armLength, height: armLength)
    }

    private var closedEyes: Bool { mood == .asleep }

    private var face: some View {
        ZStack {
            HStack(spacing: size * 0.085) {
                eye(closed: closedEyes)
                eye(closed: closedEyes || winking, happyArc: winking && !closedEyes)
            }
            .offset(y: -size * 0.04)
            HStack(spacing: size * 0.23) {
                Circle().fill(Theme.tomato.opacity(0.45)).frame(width: size * 0.05, height: size * 0.05)
                Circle().fill(Theme.tomato.opacity(0.45)).frame(width: size * 0.05, height: size * 0.05)
            }
            .offset(y: size * 0.045)
            mouth.offset(y: size * 0.075)
        }
        .foregroundStyle(Theme.onAccentInk)
    }

    @ViewBuilder private func eye(closed: Bool, happyArc: Bool = false) -> some View {
        let w = size * (mood == .wow ? 0.075 : 0.062), h = size * (mood == .wow ? 0.105 : 0.088)
        if closed {
            Curve(depth: happyArc ? -1 : 1)
                .stroke(style: StrokeStyle(lineWidth: line, lineCap: .round))
                .frame(width: w * 1.5, height: h * 0.45)
        } else {
            Ellipse().frame(width: w, height: h * (blink ? 0.1 : 1))
                .overlay(alignment: .topLeading) {
                    if size >= 56 && !blink {
                        Circle().fill(.white).frame(width: w * 0.36, height: w * 0.36).offset(x: w * 0.18, y: h * 0.14)
                    }
                }
        }
    }

    @ViewBuilder private var mouth: some View {
        switch mood {
        case .happy: Curve(depth: 1).stroke(style: StrokeStyle(lineWidth: line, lineCap: .round)).frame(width: size * 0.12, height: size * 0.055)
        case .asleep: Curve(depth: 0.25).stroke(style: StrokeStyle(lineWidth: line, lineCap: .round)).frame(width: size * 0.06, height: size * 0.03)
        case .wow: Ellipse().frame(width: size * 0.06, height: size * 0.08)
        case .oops: Ellipse().stroke(lineWidth: line).frame(width: size * 0.05, height: size * 0.045)
        case .working: Curve(depth: 0.5).stroke(style: StrokeStyle(lineWidth: line, lineCap: .round)).frame(width: size * 0.08, height: size * 0.04)
        }
    }

    private var zzz: some View {
        ZStack {
            Text("z").font(.system(size: size * 0.15, weight: .heavy, design: .rounded)).offset(x: size * 0.40, y: -size * 0.30)
            Text("z").font(.system(size: size * 0.10, weight: .heavy, design: .rounded)).offset(x: size * 0.50, y: -size * 0.42)
        }
        .foregroundStyle(Theme.inkSoft)
        .opacity(reduceMotion ? 1 : (bob ? 1 : 0.35))
    }

    // MARK: Motion

    private func updateSpin() {
        if mood == .working && !reduceMotion {
            spin = false
            withAnimation(.linear(duration: 1.8).repeatForever(autoreverses: false)) { spin = true }
        } else {
            withAnimation(.easeOut(duration: 0.25)) { spin = false }
        }
    }

    private func blinkLoop() async {
        guard !reduceMotion, mood != .asleep else { return }
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: UInt64.random(in: 2_200_000_000...4_800_000_000))
            if Task.isCancelled { return }
            blink = true
            try? await Task.sleep(nanoseconds: 120_000_000)
            blink = false
        }
    }

    private func poke() {
        winking = true
        if !reduceMotion {
            withAnimation(.interpolatingSpring(stiffness: 420, damping: 9)) { hop = -size * 0.14 }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.16) {
                withAnimation(.interpolatingSpring(stiffness: 300, damping: 12)) { hop = 0 }
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { winking = false }
    }
}

extension Theme {
    /// Face ink: always the dark ink, because the face sits on the pink arms in both appearances.
    static let onAccentInk = Theme.onAccent
}

/// A quadratic arc across the top edge of its rect: `depth` 1 dips to the bottom (a smile or a closed
/// eye), -1 arches upward, 0 is flat.
struct Curve: Shape {
    var depth: CGFloat
    func path(in r: CGRect) -> Path {
        var p = Path()
        let y = depth >= 0 ? r.minY : r.maxY
        p.move(to: CGPoint(x: r.minX, y: y))
        p.addQuadCurve(to: CGPoint(x: r.maxX, y: y), control: CGPoint(x: r.midX, y: y + r.height * 2 * depth))
        return p
    }
}

/// Wordmark: "send n*des" with the asterisk in pink; it spins when hovered.
struct Wordmark: View {
    var size: CGFloat = 20
    @State private var hover = false
    var body: some View {
        HStack(spacing: 0) {
            Text("send n")
            Text("*").foregroundStyle(Theme.pink)
                .rotationEffect(.degrees(hover ? 180 : 0))
                .animation(.spring(response: 0.5, dampingFraction: 0.55), value: hover)
            Text("des")
        }
        .display(size)
        .foregroundStyle(Theme.ink)
        .onHover { hover = $0 }
        .accessibilityLabel("send n*des")
    }
}

/// Little stars that pop outward whenever `trigger` changes.
struct SparkleBurst: View {
    let trigger: Int
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var active = false
    @State private var out = false

    var body: some View {
        ZStack {
            ForEach(0..<8, id: \.self) { i in
                let angle = Double(i) / 8 * 2 * .pi
                Image(systemName: i.isMultiple(of: 2) ? "sparkle" : "plus")
                    .font(.system(size: i.isMultiple(of: 2) ? 14 : 10, weight: .black))
                    .foregroundStyle(i % 3 == 0 ? Theme.sun : (i % 3 == 1 ? Theme.pink : Theme.mint))
                    .offset(x: cos(angle) * (out ? 44 : 4), y: sin(angle) * (out ? 44 : 4))
                    .scaleEffect(out ? 1 : 0.3)
                    .opacity(active ? (out ? 0 : 1) : 0)
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
        .onChange(of: trigger) { _, _ in
            guard !reduceMotion else { return }
            out = false; active = true
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 20_000_000)
                withAnimation(.easeOut(duration: 0.75)) { out = true }
                try? await Task.sleep(nanoseconds: 850_000_000)
                active = false
            }
        }
    }
}

/// Horizontal wiggle for "nope".
struct Shake: GeometryEffect {
    var shakes: CGFloat
    var animatableData: CGFloat {
        get { shakes }
        set { shakes = newValue }
    }
    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: 9 * sin(shakes * .pi * 2), y: 0))
    }
}
