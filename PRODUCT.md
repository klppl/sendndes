# Product

<!-- impeccable:product-schema 1 -->

## Platform

web (admin page, project site) and macOS (the Mac app)

## Users

Self-hosters first: people who already run Docker and Tailscale at home and want their own private place for sensitive files, plus a drop box their devices can send to. Single user per vault, not teams.

## Product Purpose

send n*des (repo: Valv) is a personal encrypted vault. Files, names and folders are sealed before they reach any disk, so the vault folder can live on a NAS, Google Drive or Dropbox and the host only sees ciphertext. A small self-hosted inbox server (valvd) accepts files from your devices and seals them for the vault without ever being able to read it. Success: you stop keeping passports, scans and private photos in plain folders.

## Positioning

A write-only inbox that can seal files for your vault but never open them, paired with a vault that is just a folder you can put anywhere. Own open format with two independent implementations (Go and Swift) that agree byte for byte.

## Capabilities and Constraints

- Mac app (macOS 14+, Apple silicon, ad-hoc signed; built from source, no signed download yet), CLI `valv` (macOS, Linux), server `valvd` (Linux, Docker image `ghcr.io/klppl/valv`). No Windows.
- Experimental: frozen v1 format with model-assisted review only, no external audit. Users must keep plaintext backups.
- In this version the inbox server briefly sees a sent file's contents and name while sealing it; on-device sealing is planned.
- Host can see file count, exact sizes and modification times.

## Brand Commitments

- Name "send n*des", with the asterisk in pink; mascot Aster (a pink asterisk with a face and moods).
- Voice: cheeky hook, then plain, credible facts. Never oversell security.

## Evidence on Hand

Screenshots in `docs/screenshots/` (Mac app with a demo vault; admin page rendered with example data). No users, testimonials, audits, download counts or license file exist; do not invent them.

## Product Principles

- Honest about limits: every security claim must be true today.
- The vault is just a folder: no lock-in to a host.
- Useful first, clever second.
