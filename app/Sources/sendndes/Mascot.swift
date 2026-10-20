import SwiftUI

/// Eggy, the eggplant with an asterisk for a leafy cap. Purely decorative (hidden from VoiceOver); the
/// words next to it always say the same thing. Idle motion stops when Reduce Motion is on.
struct Eggy: View {
    enum Mood { case asleep, happy, wow, oops, working }

    var mood: Mood
    var size: CGFloat = 120
    var interactive = false

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var bob = false
    @State private var blink = false
    @State private var winking = false
    @State private var hop: CGFloat = 0
    @State private var spin = false

    private static let purple = Color(.sRGB, red: 0x7B / 255, green: 0x4F / 255, blue: 0xD6 / 255, opacity: 1)
    private static let sheen = Color(.sRGB, red: 0xB7 / 255, green: 0x9B / 255, blue: 0xF2 / 255, opacity: 1)
    private static let leaf = Color(.sRGB, red: 0x3D / 255, green: 0xBE / 255, blue: 0x7E / 255, opacity: 1)
    private static let faceInk = Color(.sRGB, red: 0xFB / 255, green: 0xF3 / 255, blue: 0xE4 / 255, opacity: 1)

    /// Everything is laid out in a 140-unit-tall design space and scaled by `u`.
    private var u: CGFloat { size / 140 }
    private var outline: CGFloat { max(1.5, size * 0.03) }
    private var line: CGFloat { max(1.2, size * 0.024) }

    /// Design-space point to an offset from the frame centre (the body's bounding box centre is (0, -2)).
    private func at(_ x: CGFloat, _ y: CGFloat) -> CGSize { CGSize(width: x * u, height: (y + 2) * u) }

    var body: some View {
        ZStack {
            EggBody().fill(Self.purple)
                .overlay(EggBody().stroke(Theme.ink, style: StrokeStyle(lineWidth: outline, lineJoin: .round)))
                .frame(width: 70 * u, height: 140 * u)
            EggSheen().stroke(Self.sheen, style: StrokeStyle(lineWidth: max(2, 5 * u), lineCap: .round))
                .frame(width: 70 * u, height: 140 * u)
            calyx.offset(at(1, -52))
            face
            if mood == .asleep { zzz }
        }
        .frame(width: size, height: size)
        .rotationEffect(.degrees(reduceMotion ? 8 : (bob ? 11 : 5)), anchor: .bottom)
        .scaleEffect(reduceMotion ? 1 : (bob ? 1.02 : 0.99), anchor: .bottom)
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

    private var calyx: some View {
        ZStack {
            CalyxArms().stroke(Theme.ink, style: StrokeStyle(lineWidth: max(3, 13 * u), lineCap: .round))
            CalyxArms().stroke(Self.leaf, style: StrokeStyle(lineWidth: max(1.8, 7 * u), lineCap: .round))
        }
        .frame(width: 40 * u, height: 36 * u)
        .rotationEffect(.degrees(spin ? 360 : 0))
    }

    private var closedEyes: Bool { mood == .asleep }

    private var face: some View {
        ZStack {
            eye(closed: closedEyes).offset(at(-8, 30))
            eye(closed: closedEyes || winking, happyArc: winking && !closedEyes).offset(at(10, 30))
            Circle().fill(Theme.pink.opacity(0.75)).frame(width: 9 * u, height: 9 * u).offset(at(-16, 40))
            Circle().fill(Theme.pink.opacity(0.75)).frame(width: 9 * u, height: 9 * u).offset(at(18, 40))
            mouth.offset(at(1, 43))
        }
        .foregroundStyle(Self.faceInk)
    }

    @ViewBuilder private func eye(closed: Bool, happyArc: Bool = false) -> some View {
        let w = u * (mood == .wow ? 8 : 6.4), h = u * (mood == .wow ? 11 : 8.8)
        if closed {
            Curve(depth: happyArc ? -1 : 1)
                .stroke(style: StrokeStyle(lineWidth: line, lineCap: .round))
                .frame(width: w * 1.5, height: h * 0.45)
        } else {
            Ellipse().frame(width: w, height: h * (blink ? 0.1 : 1))
        }
    }

    @ViewBuilder private var mouth: some View {
        switch mood {
        case .happy: Curve(depth: 1).stroke(style: StrokeStyle(lineWidth: line, lineCap: .round)).frame(width: 12 * u, height: 5.5 * u)
        case .asleep: Curve(depth: 0.25).stroke(style: StrokeStyle(lineWidth: line, lineCap: .round)).frame(width: 6 * u, height: 3 * u)
        case .wow: Ellipse().frame(width: 6 * u, height: 8 * u)
        case .oops: Ellipse().stroke(lineWidth: line).frame(width: 5 * u, height: 4.5 * u)
        case .working: Curve(depth: 0.5).stroke(style: StrokeStyle(lineWidth: line, lineCap: .round)).frame(width: 8 * u, height: 4 * u)
        }
    }

    private var zzz: some View {
        ZStack {
            Text("z").font(.system(size: size * 0.15, weight: .heavy, design: .rounded)).offset(x: size * 0.30, y: -size * 0.30)
            Text("z").font(.system(size: size * 0.10, weight: .heavy, design: .rounded)).offset(x: size * 0.40, y: -size * 0.42)
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

/// Body outline in a 70 x 140 box (design space shifted by (35, 72)).
private struct EggBody: Shape {
    func path(in r: CGRect) -> Path {
        let k = r.width / 70
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: r.minX + (x + 35) * k, y: r.minY + (y + 72) * k) }
        var path = Path()
        path.move(to: p(-6, -52))
        path.addCurve(to: p(-24, 26), control1: p(-6, -24), control2: p(-26, -6))
        path.addCurve(to: p(4, 66), control1: p(-23, 52), control2: p(-10, 66))
        path.addCurve(to: p(22, 26), control1: p(20, 64), control2: p(26, 48))
        path.addCurve(to: p(8, -52), control1: p(18, 2), control2: p(8, -24))
        path.closeSubpath()
        return path
    }
}

private struct EggSheen: Shape {
    func path(in r: CGRect) -> Path {
        let k = r.width / 70
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: r.minX + (x + 35) * k, y: r.minY + (y + 72) * k) }
        var path = Path()
        path.move(to: p(-14, 0))
        path.addCurve(to: p(-10, 48), control1: p(-18, 16), control2: p(-17, 34))
        return path
    }
}

/// Three leafy prongs from one point (the asterisk cap), in a 40 x 36 box with the root at its centre.
private struct CalyxArms: Shape {
    func path(in r: CGRect) -> Path {
        let root = CGPoint(x: r.midX, y: r.midY)
        let k = r.width / 40
        var path = Path()
        for (dx, dy) in [(0.0, -12.0), (-14.0, 8.0), (14.0, 8.0)] {
            path.move(to: root)
            path.addLine(to: CGPoint(x: root.x + dx * k, y: root.y + dy * k))
        }
        return path
    }
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
