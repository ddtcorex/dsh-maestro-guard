# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
