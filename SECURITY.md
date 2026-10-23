# Security

send n\*des was designed and written by AI and has not been audited by a human cryptographer. Read the note at the top of the [README](README.md) before trusting it with anything you can't lose.

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

**[Report a vulnerability](https://github.com/klppl/sendndes/security/advisories/new)** (GitHub private advisory)

Helpful to include:

- what is affected: the format ([SPEC.md](SPEC.md)), the Go core, the CLI (`ndes`), the inbox server (`ndesd`), the Mac app or the iPhone app
- the version or commit
- steps or a test vector that shows the problem

This is a one-person project, so replies are best effort. There is no bug bounty. Fixes go into the next release, and the advisory is published once a fixed version is out.

## Supported versions

Only the [latest release](https://github.com/klppl/sendndes/releases/latest) gets fixes.

## In scope

Anything that breaks what [SPEC.md §7](SPEC.md) promises, for example:

- reading file contents, names or folder structure without the passphrase or recovery key
- tampering with a vault or an inbox upload without it being detected
- the inbox server, or anyone who only has an upload token, reading or deleting files
- pairing or token handling that lets an unapproved device connect

Things §7 already lists as not protected (malware on an unlocked device, weak passphrases, a host deleting or rolling back files, visible file counts, sizes and times) are not vulnerabilities, but ideas for improving them are welcome as normal issues.
