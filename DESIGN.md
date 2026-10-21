---
name: send n*des
description: A personal encrypted vault in a cheeky sticker world - warm paper, ink outlines, hard offset shadows, one hot-pink action.
colors:
  paper: "#FBF3E4"
  paper-dark: "#1C1923"
  paper-deep: "#F3E6CD"
  paper-deep-dark: "#141219"
  card: "#FFFCF5"
  card-dark: "#29252F"
  ink: "#241B2F"
  ink-dark: "#F6EDE0"
  ink-soft: "#5C5266"
  ink-soft-dark: "#BBB1C6"
  on-accent: "#241B2F"
  pink: "#FF5C8A"
  pink-dark: "#FF7AA3"
  pink-text: "#C2185B"
  pink-text-dark: "#FF8FB2"
  mint: "#2FC594"
  mint-dark: "#4FD8A8"
  mint-text: "#0B6B4C"
  mint-text-dark: "#7BE8C2"
  mint-tint: "#E3F8EF"
  mint-tint-dark: "#1F3A31"
  grape: "#8466FF"
  grape-dark: "#A48FFF"
  grape-text: "#5B3FD6"
  grape-text-dark: "#C3B5FF"
  grape-tint: "#ECE7FF"
  grape-tint-dark: "#2D2748"
  sun: "#FFC93C"
  sun-dark: "#FFD45C"
  sun-tint: "#FFF1C9"
  sun-tint-dark: "#3A3220"
  amber: "#F2A31F"
  amber-dark: "#FFB947"
  amber-text: "#8A5200"
  amber-text-dark: "#FFC56B"
  tomato: "#E0334F"
  tomato-dark: "#FF7088"
  tomato-text: "#B3162F"
  tomato-text-dark: "#FF8EA0"
typography:
  display:
    fontFamily: "Nunito, ui-rounded, SF Pro Rounded, system-ui, sans-serif"
    fontSize: "clamp(2.8rem, 6.4vw, 5.6rem)"
    fontWeight: 900
    lineHeight: 0.98
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "Nunito, ui-rounded, SF Pro Rounded, system-ui, sans-serif"
    fontSize: "clamp(2.2rem, 5vw, 3.6rem)"
    fontWeight: 900
    lineHeight: 1.02
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Nunito, ui-rounded, SF Pro Rounded, system-ui, sans-serif"
    fontSize: "1.35rem"
    fontWeight: 900
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  body:
    fontFamily: "Nunito, ui-rounded, SF Pro Rounded, system-ui, sans-serif"
    fontSize: "18px"
    fontWeight: 600
    lineHeight: 1.55
  label:
    fontFamily: "Nunito, ui-rounded, SF Pro Rounded, system-ui, sans-serif"
    fontSize: "0.78rem"
    fontWeight: 900
    lineHeight: 1.2
    letterSpacing: "0.08em"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "0.95rem"
    fontWeight: 700
    lineHeight: 1.3
rounded:
  button-sm: "9px"
  field: "11px"
  button: "12px"
  card: "16px"
  card-lg: "20px"
  pill: "99px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  gutter: "clamp(16px, 5vw, 72px)"
  section: "clamp(64px, 9vw, 128px)"
components:
  button-primary:
    backgroundColor: "{colors.pink}"
    textColor: "{colors.on-accent}"
    typography: "{typography.title}"
    rounded: "{rounded.button}"
    padding: "9px 16px"
  button-secondary:
    backgroundColor: "{colors.card}"
    textColor: "{colors.ink}"
    rounded: "{rounded.button}"
    padding: "9px 16px"
  button-quiet:
    textColor: "{colors.ink}"
    rounded: "{rounded.button}"
    padding: "9px 16px"
  button-small:
    backgroundColor: "{colors.card}"
    textColor: "{colors.ink}"
    rounded: "{rounded.button-sm}"
    padding: "5px 11px"
  sticker-card:
    backgroundColor: "{colors.card}"
    textColor: "{colors.ink}"
    rounded: "{rounded.card}"
    padding: "20px"
  field:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.field}"
    padding: "10px 12px"
  pill:
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "5px 10px"
  banner:
    textColor: "{colors.ink}"
    rounded: "{rounded.button}"
    padding: "10px 12px"
  choice-card:
    backgroundColor: "{colors.card}"
    textColor: "{colors.ink}"
    rounded: "{rounded.card}"
    padding: "14px 16px"
  stop-sticker:
    backgroundColor: "{colors.card}"
    textColor: "{colors.ink}"
    rounded: "{rounded.card-lg}"
    padding: "14px 16px 14px 62px"
  ticket:
    backgroundColor: "{colors.card}"
    textColor: "{colors.ink}"
    rounded: "{rounded.card-lg}"
    padding: "22px 20px 18px"
---

# Design System: send n*des

## Overview

**Creative North Star: "The Sticker Sheet"**

Every surface is a sticker peeled off a sheet and pressed onto warm paper: a cream card, a firm ink outline, and a solid ink shadow offset down and to the right, as if the sticker is lifted a few millimetres off the page. The world is the same in three places (the Mac app in SwiftUI, the ndesd admin page, the GitHub Pages site) and the tokens agree across all three; the Mac app's `Theme.swift` is the origin and both web stylesheets mirror it.

The tone is a cheeky hook delivered in heavy rounded type, then plain facts. Colour is mostly paper and ink; one hot pink carries the action and the asterisk, and four role colours (mint, grape, sun, tomato) tint stops, states and badges. Aster, a pink asterisk with a face, is the one character and appears as wordmark companion, empty-state host and status mood. Density differs by surface: the app and admin page use the light hand (2px outlines, 3-5px shadows); the marketing site uses the heavy hand (3px outlines, 5-9px shadows, slight rotations).

**Key Characteristics:**
- Warm paper ground with cream cards; dark mode is aubergine paper with cream ink, never pure black.
- Ink outlines on every raised surface: 2px in product UI, 3px on the site.
- Hard offset ink shadows with zero blur; buttons press into them.
- One hot-pink action colour; text sits in ink, never on pink-coloured words except the documented exception.
- Heavy rounded type everywhere: SF Rounded in the app, self-hosted Nunito on the web; monospace for file names, ids, ciphertext and code.
- Aster the asterisk mascot, with moods.

## Colors

Warm cream paper and deep aubergine ink, one hot pink for action, four bright role colours used as fills, each with a darker text-safe sibling. Every colour has a light and a dark value; the `-dark` tokens are the `prefers-color-scheme: dark` / dark Aqua values.

### Primary
- **Hot Pink** (`pink` / `pink-dark`): primary buttons, the asterisk in the wordmark, Aster's arms, the pinned route marker, the stop icon of the first stop, text selection. A fill, not a text colour.
- **Deep Raspberry** (`pink-text` / `pink-text-dark`): the only pink allowed as words, used for the pink "n*des" in a headline and the quiet link hover on the site. It exists because hot pink on paper fails contrast.

### Secondary
- **Mint** (`mint`): success, "sealed", ticks, the final stop, recommended badges. Text-safe sibling **Forest Mint** (`mint-text`) for words and outlines; **Mint Wash** (`mint-tint`) for tinted stickers.
- **Grape** (`grape`): info, the inbox-server stop, Tailscale badge, and the focus ring. Text-safe sibling **Deep Grape** (`grape-text`) for ciphertext names on the site; **Grape Wash** (`grape-tint`).

### Tertiary
- **Sun** (`sun`): the cloud stop, "host can see" ledger, LAN badge, asides. **Sun Wash** (`sun-tint`) for tinted stickers and asides.
- **Amber** (`amber`): warning banners and pills in product UI; **Burnt Amber** (`amber-text`) for warning words.
- **Tomato** (`tomato`): errors, "not protected", Aster's cheeks and heart; **Brick** (`tomato-text`) for danger buttons and error words.

### Neutral
- **Warm Paper** (`paper`): page ground; also the inset fill of fields and copy rows.
- **Deep Paper** (`paper-deep`): header strips of listings, tags.
- **Card Cream** (`card`): every sticker surface and secondary button.
- **Aubergine Ink** (`ink`): all text, every outline, every shadow. Flips to cream in dark mode, so outlines and shadows invert with it.
- **Soft Ink** (`ink-soft`): secondary copy, captions, field labels, struck-through readers.
- **On-Accent** (`on-accent`): text and icon strokes sitting on pink, mint, grape, sun or tomato fills. Always the light-mode ink (#241B2F) in both appearances, because the fills stay bright.

### Named Rules
**The Words Are Ink Rule.** Text is ink or soft ink. Role colours are fills, outlines and icons; when a role colour must carry words, use its `-text` sibling (`mint-text`, `amber-text`, `tomato-text`, `grape-text`, `pink-text`), never the fill value.

**The One Pink Rule.** Hot pink marks the action and the asterisk. One pink button per view region; secondary actions are cream or quiet.

**The Always-Dark Ink On Fills Rule.** Anything drawn on a bright fill (button label, badge glyph, stop icon stroke, Aster's face) uses `on-accent`, not `ink`, so it stays dark when the page goes dark.

## Typography

**Display Font:** Nunito (self-hosted woff2, weights 500-900) on the web; SF Rounded (`.rounded` design, heavy) in the app.
**Body Font:** the same rounded family, semibold.
**Label/Mono Font:** ui-monospace / SF Mono / Menlo for file names, ids, ciphertext, URLs and code.

**Character:** Heavy, soft-cornered and friendly, like sticker lettering; the monospace is the "machine truth" voice that shows exactly what a host sees.

### Hierarchy
- **Display** (900, clamp(2.8rem, 6.4vw, 5.6rem), 0.98): the site hero headline only.
- **Headline** (900, clamp(2.2rem, 5vw, 3.6rem), 1.02): site section headings. In the admin page, h1 is 800 at 1.9rem; in the app, `display(size)` is heavy rounded.
- **Title** (900, 1.35rem, 1.2): card and leg headings; the admin uses 800 at 1.05-1.35rem.
- **Body** (600, 18px, 1.55) on the site; 500-600 at 16px in the admin page and app. Lines held to about 34-46em.
- **Label** (800-900, 0.7-0.85rem, 0.07-0.12em tracking, uppercase): field labels, stop place names, ledger column heads, tags. Only inside a component, naming the field it sits on.
- **Mono** (700-800, 0.9-1.2rem): file names, ids, ciphertext, URLs, terminal.

### Named Rules
**The Heavy Rounded Rule.** Headings are 800-900 weight in a rounded face with slightly tight tracking (-0.01 to -0.02em). No serif, no thin weights.

**The Machine Truth Rule.** Anything a disk, host or server literally stores (file name, ciphertext name, id, URL, command) is set in monospace; everything a person says is rounded.

## Layout

The site is a centred column (max 1240px, hero and nav 1440px) with a fluid gutter (`spacing.gutter`) and generous section spacing (`spacing.section`). Two-column splits use a 5:7 ratio (copy : visual), alternating sides for features, collapsing to one column at 980px; nav links hide at 760px, leaving the GitHub button. The admin page is a single 900px column of cards with a two-up grid that collapses at 720px. The app uses SwiftUI panes built from the same stickers.

The site's spatial story is a route: a dashed ink line (3.5px, dash 12/11) runs from the hero through four stop stickers and continues down the page as the spine of "the trip", with each leg hanging off a round stop marker and a sticky ticket pinned to the line. Spacing inside components runs on 4/8/12/16/24px.

## Elevation & Depth

Depth is entirely hard, unblurred offset shadows in ink, plus outlines. There are no blurred or ambient shadows, no gradients and no translucency layers beyond `color-mix` washes. A sticker sits flat (outline only) or lifted (outline plus offset shadow); lift grows with importance.

### Shadow Vocabulary
- **Lift 3** (`box-shadow: 3px 3px 0 var(--ink)`): buttons and collapsible setting cards in product UI, small site buttons, stop markers.
- **Lift 4-5** (`4px 4px 0` / `5px 5px 0`): product cards and selected choice cards; site buttons at rest.
- **Lift 6-9** (`6px` to `9px`): site-only stickers by importance: stop sticker 6, ticket and screenshots 7, listing and shot frames 8, the security receipt 9.
- **Pressed** (`0 0 0`): button active state; the button translates by its shadow offset so it lands on its own shadow.

### Named Rules
**The Sticker Lift Rule.** Shadows are solid ink, offset equally down and right, zero blur. Hover lifts a site button 2px further (translate -2px, shadow 7px); press drops it onto the page.

## Shapes

Generous continuous corners on everything: 9px small buttons, 11px fields, 12px buttons and banners, 16-18px cards, 20-24px for the site's large stickers, full capsules for pills and chips, circles for stop markers and status dots. Outlines are 2px in product UI and 3px on the site (1.5px for pills and tags; 2.5px for icon tiles). Dashed ink lines (route, ticket divider, footer rule, receipt column heads) mark journeys and tear-off edges. On the site, stickers may be rotated between -2.5deg and 3deg to feel hand-placed; product UI never rotates.

## Components

### Buttons
Chunky and pressable, like a sticker you push into the page.
- **Shape:** 12px corners (9px small), ink outline (2px product, 3px site, where corners grow to 15px).
- **Primary:** hot pink fill, `on-accent` label, heavy rounded label, lifted.
- **Secondary:** card cream fill, ink label, lifted.
- **Quiet:** no fill, outline or shadow; a faint ink wash (8%) on hover. On the site the quiet action is an underlined link (2.5px underline) turning `pink-text` on hover.
- **Danger:** secondary shape with a `tomato-text` label.
- **Hover / Focus / Active:** site buttons lift on hover; all press onto their shadow on active (80-120ms). Focus is a 3px grape outline offset 2-3px. Disabled: 45% opacity, no shadow.

### Pills
- **Style:** capsule, 1.5px outline in the role tint, fill at 22% of the tint, ink label, a leading 8px dot (or SF Symbol in the app) in the tint.
- **State:** ok (mint), warn (amber), bad (tomato), off (grape), neutral (soft ink). Site variants: hero chips (2px ink outline on card) and the "new" tag (`mint-text` outline on `mint-tint`).

### Banners
- **Style:** 12px corners, 2px outline in the tint, fill at 17% of the tint, semibold ink text, a leading round icon in the tint.
- **Kinds:** info (grape), success (mint), warn (amber), error (tomato).

### Cards / Containers (Sticker Card)
- **Corner Style:** 16-18px.
- **Background:** card cream; tinted variants use the role washes.
- **Shadow Strategy:** flat or lifted per Elevation.
- **Border:** ink outline.
- **Internal Padding:** 20px (16px on narrow screens).

### Inputs / Fields
- **Style:** warm paper fill (inset against the card), 2px ink outline, 11px corners, semibold rounded text; code entry in large spaced monospace.
- **Focus:** 3px grape outline. Field labels use the uppercase label style in soft ink.

### Choice Card
Radio options as stickers: a 44px rounded-square badge in a role colour (grape Tailscale, mint proxy, sun LAN, pink everything) beside a title and soft description. Selected: lifted 4px and washed 10% pink.

### Route and Stop Sticker
The site's signature. A dashed ink route connects stop stickers: card cream (or role wash), 3px outline, 20px corners, 6px lift, slight rotation, a 36px pink/grape/sun/mint icon tile at left, an uppercase place label, the file as it exists there in monospace (ciphertext in `grape-text`), and a soft one-line note. On narrow screens the route straightens into a vertical dashed rail.

### Ticket
A sticky card that travels the route as the visitor scrolls: monospace file name that blurs while it changes, a soft "where" line, a dashed tear line, and reader pills (can read in `mint-text`, cannot in struck soft ink, briefly in `amber-text`). Its fill takes the wash of the current stop; a short ink string and pink marker pin it to the line.

### Navigation
Wordmark "send n*des" with the asterisk in pink (spins 180deg on hover) beside a small Aster; soft-ink 800-weight links that turn ink and underline on hover; a small secondary button for GitHub.

### Aster
A three-arm asterisk (capsules at 30/90/150deg) in hot pink, outlined by the same shape inked and fattened, with a face always drawn in dark ink. Moods: happy, asleep, wow, oops, working, flustered, smitten. Idle bob (3.8s, +/-3deg) and blink (4.7s); working spins the arms; wow and smitten hop; asleep slows and shows a fading "zzz". All motion stops under reduced motion. Aster is decorative and hidden from assistive tech; adjacent words always say the same thing.

## Do's and Don'ts

### Do:
- **Do** put every raised surface on card cream with an ink outline, and lift it with a solid ink offset shadow (3-5px product, up to 9px on the site).
- **Do** use hot pink only for the primary action, the asterisk and Aster; use `pink-text` (#C2185B light, #FF8FB2 dark) when pink must be words.
- **Do** use `on-accent` for anything drawn on a bright fill, in both appearances.
- **Do** set file names, ids, ciphertext, URLs and commands in monospace.
- **Do** ship a dark value for every colour and honour `prefers-reduced-motion` by stopping all animation.
- **Do** use the grape 3px outline for keyboard focus.

### Don't:
- **Don't** blur a shadow or use ambient, coloured or gradient elevation; depth is ink offset only.
- **Don't** set words in a role fill colour (pink, mint, sun, amber, grape, tomato); use the `-text` sibling or ink.
- **Don't** use pure black or pure white grounds; paper and ink carry the warmth in both modes.
- **Don't** rotate stickers in product UI; tilt is a site-only gesture.
- **Don't** load third-party fonts or assets on the admin page; Nunito is self-hosted on the site.
