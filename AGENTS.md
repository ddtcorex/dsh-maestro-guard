# AGENTS.md — dsh-maestro-guard

> `CLAUDE.md` at the repo root is a symlink to `AGENTS.md`. Claude Code follows the same rule set as Codex CLI. Only edit `AGENTS.md` — never edit `CLAUDE.md` directly or replace the symlink with a copy.

## Purpose

Host-only safety gate plugin for the DeepSeek Harness (DSH). One Cordis row (`id: dsh-maestro-guard`) that gates tool execution before dispatch: approval store, secret redaction, permission policy, and waterfall pre-execute integration.

Names by boundary: npm package = `@ddtcorex/dsh-maestro-guard`; Cordis patch row id = `dsh-maestro-guard`.

Part of the Maestro Harness suite. No client bundle — everything runs in the Node host.

## Layout

- `src/host/index.ts` — host `apply()`: builds the guard handler and wires it into the tool-execution waterfall (pre-execute).
- `src/host/approval-store.ts` — persistent approval grants (legacy migration, revoke, RMW-safe under a mutex).
- `src/host/secret-redactor.ts` — redacts known secret families before a call is logged/persisted.
- `src/host/permission-policy.ts` — policy check for whether a tool call is allowed.
- `src/host/augment.d.ts` — local structural types for the DSH tool-execution contract (do NOT import from `deepseek-harness`).
- `tests/*.test.ts` — vitest suites (90 tests): guard, approval-store, secret-redactor, permission, sandbox (branch-scope), approval lifecycle (TTL/session), command-surface.

## Development

```sh
pnpm verify   # tsc --noEmit
pnpm test     # vitest run
pnpm build    # tsc -p tsconfig.json  -> lib/
```

Host-only: no `build:client` step, no client bundle.

## Git workflow

- Default branch `master`. No direct commits to `master` — use `feat/<topic>` / `fix/<topic>` and a PR.
- Conventional commits, imperative mood (`feat(guard): ...`, `fix(guard): ...`).
- One TDD task = one commit; never commit while `pnpm verify` is red.
- **Always request approval before merge or release** — never merge a PR/MR or publish a release (`git tag vX.Y.Z` / `pnpm publish` / `gh release create`) without an explicit human approval; request review (`gh pr ready` / `gh pr request-review` / ask in chat) and wait for `APPROVED` per `docs/PUBLIC_REPO_CHECKLIST.md` §2/§8.

## Conventions

- **Host-only** — this package has no client half. Any future browser UI belongs to a separate client package or an existing one.
- **Redaction breadth** — gate on `containsSecret` before truncating/redacting; cover the full secret families (`ghp_`, `xox`, private keys, etc.), not a fixed list of patterns.
- **Permission semantics** — policy checks return a clear allow/deny; keep the check pure and unit-testable (no side effects).
- **ApprovalStore** — mutate the store under the RMW mutex; never `mkdir` recursively on revoke (the alias/file layout is fixed).
- **Types** — extend `augment.d.ts` with local structural types; the workspace excludes `deepseek-harness`, so its package paths are not resolvable here.
- Every capability is a reversible effect (`ctx.effect(() => ... , label)`); declare `inject` for hard dependencies.

## Validation

`pnpm verify` + `pnpm test` green before any success claim. Guard is pure modules (no file modes / runtime wiring to test hermetically) — evidence is the vitest suite plus `tsc --noEmit`.
