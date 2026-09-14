# AGENTS.md — dsh-maestro-guard

> `CLAUDE.md` at the repo root is a symlink to `AGENTS.md`. Claude Code follows the same rule set as Codex CLI. Only edit `AGENTS.md` — never edit `CLAUDE.md` directly or replace the symlink with a copy.

## Purpose

Host-only safety gate plugin for the DeepSeek Harness (DSH). One Cordis row (`id: dsh-maestro-guard`) decides every tool call before dispatch on the `tools/pre-execute` waterfall:

```
parse → classify → decide → journal → act
```

The `ask` tier raises DSH's own approval prompt; the guard keeps no ticket store and registers no approval tool, so no agent can grant itself a protected operation.

Names by boundary: npm package = `@ddtcorex/dsh-maestro-guard`; Cordis patch row id = `dsh-maestro-guard`.

Part of the Maestro Harness suite. No client bundle — everything runs in the Node host.

## Layout

- `src/host/index.ts` — host `apply()`: builds the guard handler (`createGuardHandler`) and wires it into the `tools/pre-execute` waterfall; `branchOf()`; retires the legacy store once per boot inside `ctx.effect`.
- `src/host/tiers.ts` — the `Tier` union (`allow` | `journal` | `ask` | `deny`) and its `TIERS` list.
- `src/host/rules.ts` — `classify()`: the rule ids (`RULE_IDS`), `DEFAULT_TIERS`, and the parsed command-surface / file-path checks that produce a `Verdict`.
- `src/host/decide.ts` — `decide()` (the enforced tier after `domains.guard.rules` overrides; `deny` is a structural floor) and `renderReason()`.
- `src/host/parse.ts` — the shell-aware tokenizer/segmenter (`parseCommand`, `unwrapSegments`) plus the command/argument interpretation helpers (`extractCommandText`, `extractPathField`, `getCommandWorkingDir`, `stripQuoted`, `stripHeredocs`); pure — no filesystem.
- `src/host/paths.ts` — the path rules: `defaultProtectedPaths()` / `guardConfigPaths()` and the primitives `classify` consumes (`isBlockedPath`, `isOutsideCwd`, `isRuntimeSpillPath`, `isWithinTempDir`). The always-blocked path names are assembled from string fragments, because the OLD 0.2.3 guard is still the live listener and blocks any tool call carrying one contiguously.
- `src/host/config.ts` — `GuardConfigV2`, `DEFAULT_CONFIG`, `mergeGuardConfig()`, `loadGuardConfig()` over `domains.guard`.
- `src/host/journal.ts` — `Journal`, `journalDir()`, `journalPath()`; one JSON line per decision with **every string field redacted inside `append()`** (the single choke point — callers pass raw verdict fields), never throws.
- `src/host/redact.ts` — `containsSecret()` / `redact()`: the secret families and prefix-keeping patterns, applied to journal copies only.
- `src/host/migrate.ts` — `retireLegacyStore()`: moves a legacy ticket file to `legacy-pending.json` (0600) and journals one `guard.migration` entry; a no-op when the source is absent.
- `src/host/permission-policy.ts` — `PermissionPolicy`: pure allow/deny check on the tool name.
- `src/host/full-scan-tool.ts` — the on-demand full-scan tool registration.
- `src/host/augment.d.ts` — local structural types for the DSH tool-execution contract and the `tools/pre-execute` event (do NOT import from `deepseek-harness`).
- `tests/*.test.ts` — 14 vitest suites: guard, guard-handler, rules, rules-git, rules-paths, parse, parse-wrappers, decide, journal, migrate, redact, permission, paths, full-scan-tool.

## Decision tiers & approval

Every decision resolves to exactly one of four tiers:

| Tier | Effect |
| --- | --- |
| `allow` | run the call; nothing recorded |
| `journal` | run the call and record it (e.g. `gh pr merge`) |
| `ask` | raise **DSH's native approval prompt** |
| `deny` | refuse with a reason (unappealable: `guard.tamper`) |

- **Native ask** — the guard reads the `approval` service with `ctx.get('approval')` (a soft dependency, not an `inject`) and calls `request()` itself; only `allowed-once` is a grant. The outcome and the time the human took are journaled. There is no ticket store and no approve tool.
- **Fail-closed** — a session whose approval policy never prompts, an agent-less execution, a missing or unreachable `approval` service, or a `request()` that throws all resolve to a denial naming the cause and the fix. `deny` cannot be downgraded by configuration, and a partial or unreadable config falls back to the built-in defaults, never to an empty policy.
- **Journal** — `~/.dsh/dsh-maestro-guard/journal.jsonl` (0600). Secret families are redacted on the stored copy only; the executed call is never rewritten. A journal write that fails is logged and changes no decision.
- **Arriving in a later task** — two read-only tools, `maestro_guard_status` and `maestro_guard_stats`, will expose the recent journal and per-rule/per-outcome counters. Today the guard registers exactly one tool besides those: `maestro_full_scan` (the on-demand scan wired in `apply()` from `full-scan-tool.ts`). It registers **no approval tool** — `ask` is answered by DSH's own prompt — so no agent can grant itself a protected operation.
- **Deployment files that must stay in sync** — the `permission` row in `~/.dsh/profiles/web/cordis.patch.yml` (its `presets` table must define `full-access-ask`) and `permission.defaultPreset` in `~/.dsh/settings.yaml` (must name it). Neither ships in this package, and a session on `approval: never` denies every `ask`.

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
- **Rule ids are the contract** — config overrides, journal entries and approval reasons all key on `RULE_IDS` (`git.push.protected`, `git.merge.protected`, `git.tag.release`, `git.push.force`, `gh.release.create`, `gh.protection.delete`, `pkg.publish`, `secret.access`, `fs.write.outside`, `net.exec.remote`, `guard.tamper`); never rename one casually. New protection means a new rule id plus a `DEFAULT_TIERS` entry.
- **Redaction breadth** — extend the secret-family and prefix-keeping tables rather than adding a one-off regex. Redaction runs at the journal choke point (`Journal.append` redacts every string field), not at each call site, and the executed arguments are never rewritten; `containsSecret()` stays available where a caller needs a boolean check.
- **Precision in the classifier** — judge a shell command on its stripped command surface (quotes and heredocs are data) and a non-shell tool on its path field, never on its content. `guard.tamper` is the deliberate raw-text exception.
- **Permission semantics** — policy checks return a clear allow/deny; keep the check pure and unit-testable (no side effects).
- **Journal and migration never throw** — a failed journal write or a failed legacy-store retirement is logged and changes no decision; the guard must still boot.
- **Types** — extend `augment.d.ts` with local structural types; the workspace excludes `deepseek-harness`, so its package paths are not resolvable here.
- Every capability is a reversible effect (`ctx.effect(() => ... , label)`); declare `inject` only for hard dependencies (`tools`), and read optional services with `ctx.get`.

## Validation

`pnpm verify` + `pnpm test` green before any success claim. Guard is pure modules (no file modes / runtime wiring to test hermetically) — evidence is the vitest suite plus `tsc --noEmit`.
