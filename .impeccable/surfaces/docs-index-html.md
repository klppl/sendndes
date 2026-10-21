---
version: 1
slug: "docs-index-html"
primary_target: "docs/index.html"
related_targets: []
---

# Surface: project site (docs/index.html, GitHub Pages)

Scope: public landing page at klppl.github.io/sendndes. Mode: Persuade.
Audience: self-hosters (Docker, Tailscale at home). Action: View on GitHub (repo + README quick start). Tone: cheeky hook, then plain credible facts.
Proof on hand: docs/screenshots (Mac app with demo vault; admin page with example data). No users, audits, downloads or license; invent none.

## Direction contract

THESIS: The mechanism is the story: one file, passport.pdf, travels down the page from phone to inbox server (sealed) to Google Drive (only a ciphertext name) to the Mac vault (back by name). Refuses the headline-over-feature-grid product page.

OWN-WORLD: The app's world: warm paper ground, 3px ink outlines, hard offset sticker shadows, hot-pink action, mint/grape/sun stop tints, rounded heavy type (Nunito as the web stand-in for SF Rounded), Aster the asterisk mascot, a dashed ink route line, monospace for file names and ciphertext.

STORY: Visitor gets the joke, then sees exactly where a file goes and who can read it at each stop, sees the real app and server, reads an honest ledger, and clicks View on GitHub to self-host.

FIRST VIEWPORT: Nav (wordmark, Trip, Features, Security, GitHub). Left 40%: headline "Send n*des. Nobody in between can look.", subcopy, pink View on GitHub + quiet "Follow the file". Right 60%: dashed route snaking through four tilted stop stickers (1 phone passport.pdf, 2 inbox server sealed, 3 Google Drive 7f3a91…c9.v1, 4 Mac vault passport.pdf, new). Primary action above the fold, left.

FORM: "The trip of one file", position 1 on the ordered list; dealt in the surface roll, seed key 2d63460e.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

Signature interaction: as the visitor scrolls, a passport.pdf sticker rides the dashed route and its label swaps to ciphertext at the Drive stop and back to its name at the vault (CSS scroll-driven where supported, static with all four states visible otherwise; reduced motion shows the static version).
