# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-09-01

### Fixed

- Legacy tickets recorded before the TTL existed (no `expiresAt`) now expire
  at `requestedAt` + TTL instead of lingering as pending forever.
- TDD-seeded regression tests for legacy-ticket expiry (106 tests).

## [0.2.1] - 2026-09-01

### Fixed

- Strip quoted spans on the full command text BEFORE segmenting the
  protected-op check: multiline quoted data (an instruction prompt, a node -e
  body) that legitimately spans `&&`/`;`/`|`/newline separators no longer
  fragments into exposed phrasings (defect found by the first real-session
  probe against v0.2.0).

## [0.2.0] - 2026-09-01

### Added

- **Chat-approval flow** — blocked protected ops record one-shot tickets
  (`~/.dsh/dsh-maestro-guard/pending.json`) and are approved via
  `maestro_guard_approve` after the human consents in the conversation.
- **Release-tag protection** — `git push origin vX.Y.Z` / `refs/tags/…` /
  bare numeric tags / prereleases require the same human approval as release
  creation (they trigger the CI publish workflow).

### Changed

- Approval hashes cover the executed command text only — cosmetic argument
  fields (description/timeoutMs) no longer mint a fresh ticket on retry.
- Approved (and stale pending) tickets expire after a 30 min TTL, and
  consumption is scoped to the session that recorded the ticket.
- Branch detection follows the repo the command actually targets (`cd` /
  `git -C`), not the session cwd; unparsable cd targets are treated as
  unknown instead of assuming the session branch.
- Protected-op detection runs on the executed command surface only — tools
  without a command field (write/read/memory) are never git/publish-gated;
  quoted spans are treated as data; branch resolution is lazy (only when the
  command mentions git/gh).

## [0.1.0] - 2026-08-28

Initial scaffold of `@ddtcorex/dsh-maestro-guard` — host-only safety gate plugin for DeepSeek Harness.

### Added

- **Cordis row `dsh-maestro-guard`** (`cordis.patch.yml` channel `/dsh-maestro-guard`) — single host-only row wiring the guard handler into the tool-execution waterfall (pre-execute).
- **ApprovalStore** (`src/host/approval-store.ts`) — persistent approval grants with legacy migration, revoke, and read-modify-write safety under a mutex; never `mkdir` recursively on revoke.
- **SecretRedactor** (`src/host/secret-redactor.ts`) — redacts known secret families (`ghp_`, `xox`, private keys, etc.) before calls are logged or persisted; gated on `containsSecret` before truncating.
- **PermissionPolicy** (`src/host/permission-policy.ts`) — pure, unit-testable allow/deny checks for tool calls.
- **Waterfall pre-execute integration** (`src/host/index.ts`) — `apply()` builds the guard handler and wires it into the DSH tool-execution waterfall; declared via `inject` and reversible `ctx.effect`.
- Host-only TypeScript setup (`tsconfig.json` `rootDir: src/host` → flat `lib/index.js`), committed `lib/` build output, and vitest suites (`tests/*.test.ts`, 27 tests).
- Public package metadata (`package.json` `private: false`, `pnpm@11.7.0`), documentation (`README.md`, `AGENTS.md` + `CLAUDE.md -> AGENTS.md` symlink), and community files per `docs/PUBLIC_REPO_CHECKLIST.md` §3.
