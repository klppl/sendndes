import SwiftUI

/// Aster, the asterisk from "n*des", with a face. Purely decorative (hidden from VoiceOver); the words
/// next to it always say the same thing. Idle motion stops when Reduce Motion is on.
struct Aster: View {
    enum Mood { case asleep, happy, wow, oops, working, flustered, smitten }

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
    @State private var pulse = false
    @State private var shiver = false

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
            floaters
            if mood == .asleep { zzz }
        }
        .frame(width: size, height: size)
        .rotationEffect(.degrees(reduceMotion || still ? 0 : (bob ? 3 : -3) + (mood == .flustered ? (shiver ? 2 : -2) : 0)))
        .scaleEffect(reduceMotion || still ? 1 : (bob ? 1.025 : 0.985))
        .scaleEffect(throbScale)
        .offset(y: hop)
        .accessibilityHidden(true)
        .onTapGesture { if interactive { poke() } }
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.easeInOut(duration: mood == .asleep ? 2.8 : (hot ? 3.6 : 1.9)).repeatForever(autoreverses: true)) { bob = true }
            updateMotion()
        }
        .onChange(of: mood) { _, _ in updateMotion() }
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
    private var hot: Bool { mood == .flustered || mood == .smitten }
    private var throbScale: CGFloat { reduceMotion || still ? 1 : (hot && pulse ? 1.06 : 1) }

    private var face: some View {
        ZStack {
            HStack(spacing: size * 0.085) {
                eye(closed: closedEyes)
                eye(closed: closedEyes || winking, happyArc: winking && !closedEyes)
            }
            .offset(y: -size * 0.04)
            HStack(spacing: size * (hot ? 0.25 : 0.23)) {
                cheek
                cheek
            }
            .offset(y: size * 0.045)
            mouth.offset(y: size * 0.075)
        }
        .foregroundStyle(Theme.onAccentInk)
    }

    private var cheek: some View {
        Circle().fill(Theme.tomato.opacity(hot ? 0.8 : 0.45))
            .frame(width: size * (hot ? 0.075 : 0.05), height: size * (hot ? 0.075 : 0.05))
            .scaleEffect(hot && pulse && !reduceMotion && !still ? 1.2 : 1)
    }

    @ViewBuilder private func eye(closed: Bool, happyArc: Bool = false) -> some View {
        let w = size * (mood == .wow ? 0.075 : 0.062), h = size * (mood == .wow ? 0.105 : 0.088)
        if closed {
            Curve(depth: happyArc ? -1 : 1)
                .stroke(style: StrokeStyle(lineWidth: line, lineCap: .round))
                .frame(width: w * 1.5, height: h * 0.45)
        } else if mood == .smitten {
            Heart().fill(Theme.tomato)
                .overlay(Heart().stroke(Theme.onAccent, lineWidth: max(0.8, size * 0.012)))
                .frame(width: size * 0.105, height: size * 0.095)
                .scaleEffect(pulse && !reduceMotion && !still ? 1.2 : 1)
        } else if mood == .flustered {
            HalfEye().frame(width: w * 1.2, height: h * 0.8 * (blink ? 0.2 : 1))
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
        case .flustered:
            Ellipse().frame(width: size * 0.05, height: size * 0.06)
                .scaleEffect(pulse && !reduceMotion && !still ? 1.3 : 0.85)
        case .smitten:
            OpenGrin().fill(Theme.onAccent)
                .overlay(alignment: .bottom) {
                    Ellipse().fill(Theme.tomato).frame(width: size * 0.08, height: size * 0.05).offset(y: size * 0.02)
                }
                .clipShape(OpenGrin())
                .frame(width: size * 0.14, height: size * 0.085)
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

    // MARK: Floating extras (hearts when smitten; breath and a sweat drop when flustered)

    @ViewBuilder private var floaters: some View {
        if hot {
            TimelineView(.animation(minimumInterval: 1.0 / 30, paused: reduceMotion || still)) { tl in
                let t = reduceMotion || still ? 0.3 : tl.date.timeIntervalSinceReferenceDate
                ZStack {
                    ForEach(0..<3, id: \.self) { i in
                        if mood == .smitten { floatingHeart(i, t) } else { puff(i, t) }
                    }
                    if mood == .flustered { sweat(t) }
                }
            }
            .frame(width: size, height: size)
        }
    }

    private func phase(_ t: Double, _ i: Int, speed: Double) -> Double {
        (t * speed + Double(i) / 3).truncatingRemainder(dividingBy: 1)
    }

    private func floatingHeart(_ i: Int, _ t: Double) -> some View {
        let p = CGFloat(phase(t, i, speed: 0.11))
        let grow: CGFloat = 0.6 + 0.5 * p
        let sway: CGFloat = 0.1 * CGFloat(sin(Double(p) * 6 + Double(i) * 2.1))
        let spread: CGFloat = (CGFloat(i) - 1) * 0.12
        let lift: CGFloat = 0.44 + 0.3 * p
        let fill: Color = i == 1 ? Theme.tomato : Theme.pink
        let edge: CGFloat = max(0.8, size * 0.008)
        return Heart().fill(fill)
            .overlay(Heart().stroke(Theme.onAccent, lineWidth: edge))
            .frame(width: size * 0.13 * grow, height: size * 0.12 * grow)
            .offset(x: size * (sway + spread), y: -size * lift)
            .opacity(sin(Double(p) * .pi))
    }

    private func puff(_ i: Int, _ t: Double) -> some View {
        let p = CGFloat(phase(t, i, speed: 0.2))
        let d: CGFloat = size * (0.03 + 0.05 * p)
        let x: CGFloat = size * (0.14 + 0.3 * p)
        let y: CGFloat = size * (0.1 - 0.14 * p)
        let edge: CGFloat = max(0.6, size * 0.006)
        return Circle().fill(Theme.card.opacity(0.9))
            .overlay(Circle().stroke(Theme.ink.opacity(0.5), lineWidth: edge))
            .frame(width: d, height: d)
            .offset(x: x, y: y)
            .opacity(Double(0.9 * (1 - p)))
    }

    private func sweat(_ t: Double) -> some View {
        let p = CGFloat((t * 0.14).truncatingRemainder(dividingBy: 1))
        let y: CGFloat = -size * (0.3 - 0.2 * p)
        let edge: CGFloat = max(0.8, size * 0.01)
        return Drop().fill(Color(red: 0.56, green: 0.83, blue: 1.0))
            .overlay(Drop().stroke(Theme.onAccent, lineWidth: edge))
            .frame(width: size * 0.06, height: size * 0.085)
            .offset(x: -size * 0.34, y: y)
            .opacity(sin(Double(p) * .pi))
    }

    // MARK: Motion

    private func updateMotion() {
        updateSpin()
        if hot && !reduceMotion && !still {
            pulse = false; shiver = false
            withAnimation(.easeInOut(duration: mood == .flustered ? 1.8 : 2.8).repeatForever(autoreverses: true)) { pulse = true }
            if mood == .flustered {
                withAnimation(.easeInOut(duration: 1.3).repeatForever(autoreverses: true)) { shiver = true }
            }
        } else {
            withAnimation(.easeOut(duration: 0.2)) { pulse = false; shiver = false }
        }
    }

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

/// A heart in its rect.
struct Heart: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        let w = r.width, h = r.height
        p.move(to: CGPoint(x: r.midX, y: r.maxY))
        p.addCurve(to: CGPoint(x: r.minX, y: r.minY + h * 0.3), control1: CGPoint(x: r.minX + w * 0.1, y: r.maxY - h * 0.25), control2: CGPoint(x: r.minX, y: r.minY + h * 0.55))
        p.addArc(center: CGPoint(x: r.minX + w * 0.25, y: r.minY + h * 0.28), radius: w * 0.25, startAngle: .degrees(180), endAngle: .degrees(0), clockwise: false)
        p.addArc(center: CGPoint(x: r.minX + w * 0.75, y: r.minY + h * 0.28), radius: w * 0.25, startAngle: .degrees(180), endAngle: .degrees(0), clockwise: false)
        p.addCurve(to: CGPoint(x: r.midX, y: r.maxY), control1: CGPoint(x: r.maxX, y: r.minY + h * 0.55), control2: CGPoint(x: r.maxX - w * 0.1, y: r.maxY - h * 0.25))
        p.closeSubpath()
        return p
    }
}

/// The bottom half of an ellipse with a flat top: a heavy-lidded eye.
struct HalfEye: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: r.minX, y: r.minY))
        p.addLine(to: CGPoint(x: r.maxX, y: r.minY))
        p.addArc(center: CGPoint(x: r.midX, y: r.minY), radius: r.width / 2, startAngle: .degrees(0), endAngle: .degrees(180), clockwise: false)
        p.closeSubpath()
        return p
    }
}

/// An open grin: flat top, rounded bottom.
struct OpenGrin: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: r.minX, y: r.minY))
        p.addLine(to: CGPoint(x: r.maxX, y: r.minY))
        p.addCurve(to: CGPoint(x: r.minX, y: r.minY), control1: CGPoint(x: r.maxX - r.width * 0.1, y: r.maxY * 1.25), control2: CGPoint(x: r.minX + r.width * 0.1, y: r.maxY * 1.25))
        p.closeSubpath()
        return p
    }
}

/// A teardrop.
struct Drop: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: r.midX, y: r.minY))
        p.addCurve(to: CGPoint(x: r.midX, y: r.maxY), control1: CGPoint(x: r.maxX + r.width * 0.1, y: r.midY), control2: CGPoint(x: r.maxX, y: r.maxY))
        p.addCurve(to: CGPoint(x: r.midX, y: r.minY), control1: CGPoint(x: r.minX, y: r.maxY), control2: CGPoint(x: r.minX - r.width * 0.1, y: r.midY))
        p.closeSubpath()
        return p
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
