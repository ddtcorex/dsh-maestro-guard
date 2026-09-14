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

- `src/host/index.ts` — host `apply()`: builds the guard handler (`createGuardHandler`) and wires it into the `tools/pre-execute` waterfall; `contractMismatch()` (spec §8: an unknown payload denies + journals `contract-mismatch`); `branchOf()`; retires the legacy store once per boot inside `ctx.effect`.
- `src/host/tiers.ts` — the `Tier` union (`allow` | `journal` | `ask` | `deny`) and its `TIERS` list.
- `src/host/rules.ts` — `classify()`: the rule ids (`RULE_IDS`), `DEFAULT_TIERS`, and the parsed command-surface / file-path checks that produce a `Verdict`. `secret.access` reads each parsed segment's **argv** (`isAccess`) for the path but judges the access VERB against the segment's COMMAND — a mention-only verb is never an access, an access verb inside a message/body is not the command, a heredoc body is never argv, and an `ambiguous` segment treats a protected path in its argv as an access on its own. `guard.tamper` is scoped to EDITS: a mutating verb (or `sed`/`perl` with an in-place flag) whose segment names a guard path, or a write redirection whose TARGET is one, in every spelling `pathSpellings` produces. The mutation does not have to be the segment's OWN verb: a wipe handed to a wrapper, to a `find` action flag, to a `-c` script, or to an `xargs` across a pipe denies too (`nice rm -f <journal>`, `find . -execdir rm -f <journal> +`, `find . -exec bash -c "rm -f <journal>" +`, `echo <journal> | xargs rm -f`), because the parser marks those wrappers `ambiguous` rather than unwrapping them.
- `src/host/decide.ts` — `decide()` (the enforced tier after `domains.guard.rules` overrides; `deny` is a structural floor) and `renderReason()`. An override that merely ECHOES the rule's `DEFAULT_TIERS` entry is not an override — `cfg.rules` is the fully-populated default table, so honouring it made every classify-level refinement (the `--dry-run` → `journal` case) unreachable.
- `src/host/parse.ts` — the shell-aware tokenizer/segmenter (`parseCommand`, `unwrapSegments`) plus the command/argument interpretation helpers (`extractCommandText`, `extractPathField`, `getCommandWorkingDir`, `stripQuoted`, `stripHeredocs`); pure — no filesystem. `unresolvedCommand()` is the SHAPE test that marks a segment `ambiguous` when its first token cannot be a command (`VAR=value`, `(`/`{`, a shell keyword) or when a later token names a rule verb by its BASE name while `argv[0]` does not; a segment LED by a `MENTION_VERBS` verb opts out of that later-token rule (a `find` action flag — `FIND_ACTION_FLAGS`: `-exec`, `-execdir`, `-ok`, `-okdir` — stays in), and `unwrapSegments` re-parses a `-c` script handed to a shell by a verb the guard cannot name. `SHELL_COMMAND_FLAG` / `SHELL_VERBS` name the `-c`/`-lc`/`--command` switch and the shells that read it; `scanRedirect` reads `>|` as ONE clobber operator (it used to split at the `|`, moving the target into a segment of its own where no rule saw it).
- `src/host/paths.ts` — the path rules: `defaultProtectedPaths()` / `guardConfigPaths()` / `guardPathSpellings()` and the primitives `classify` consumes (`isBlockedPath`, `isOutsideCwd`, `isRuntimeSpillPath`, `isWithinTempDir`, `pathSpellings`). `guardConfigPaths()` covers the settings file, the profile row patch, the profile `package.json` that MOUNTS the guard, and the journal + `legacy-pending.json` under `journalDir()`; `pathSpellings` derives the `~`/`$HOME`/`${HOME}` spellings of any of them. The always-blocked path names were assembled from string fragments while the OLD 0.2.3 guard was the live listener and blocked any tool call carrying one contiguously. That listener has since been replaced by THIS build (the `dsh web` restart landed 2026-09-14), so the fragments are no longer required and can be inlined in a later pass.
- `src/host/config.ts` — `GuardConfigV2`, `DEFAULT_CONFIG`, `mergeGuardConfig()`, `loadGuardConfig()` over `domains.guard`. The `journal` retention windows/switches and `workingDirContainment` are validated on merge: a window that is not a positive INTEGER (`retainFiles`/`retainDays`) falls back to the built-in window (unvalidated, it pruned every archive; floored, `0.5` became 0 and did the same).
- `src/host/journal.ts` — `Journal`, `journalDir()`, `journalPath()`; one JSON line per decision with **every string field redacted inside `append()`** (the single choke point — callers pass raw verdict fields), never throws. Also holds the in-memory `allow` counters + periodic `counters` flush, the NEWEST-FIRST `read()` across the live file and its archives, and rotation: `rotate()` archives the live file and prunes by both retention windows (serialized so overlapping calls cannot collide on a name), driven in production by `rotateIfStale()` at boot (the `shouldRotateAtBoot` mtime-day check) and `startDailyRotation()` on a timer.
- `src/host/redact.ts` — `containsSecret()` / `redact()`: the secret families and prefix-keeping patterns, applied to journal copies only.
- `src/host/migrate.ts` — `retireLegacyStore()`: moves a legacy ticket file to `legacy-pending.json` (0600) and journals one `guard.migration` entry; a no-op when the source is absent.
- `src/host/permission-policy.ts` — `PermissionPolicy`: pure allow/deny check on the tool name.
- `src/host/full-scan-tool.ts` — the on-demand full-scan tool registration.
- `src/host/status-tool.ts` — `createStatusTools()` / `applyStatusTools()`: the two read-only journal tools (`maestro_guard_status`, `maestro_guard_stats`), each registration its own reversible effect. `byRule`/`byTier` fold only rows whose rule is one of the closed `RULE_IDS`; `counters`, `config-legacy`, `guard.migration` and `policy.deny` are bookkeeping and stay out (`byOutcome` counts every row).
- `src/host/augment.d.ts` — local structural types for the DSH tool-execution contract and the `tools/pre-execute` event (do NOT import from `deepseek-harness`).
- `tests/*.test.ts` + `tests/*.spec.ts` — 19 vitest suites: guard, guard-handler, apply, rules, rules-git, rules-paths, parse, parse-wrappers, decide, journal, journal-retention, migrate, redact, permission, paths, config, corpus, full-scan-tool, status-tool.

## Decision tiers & approval

Every decision resolves to exactly one of four tiers:

| Tier | Effect |
| --- | --- |
| `allow` | run the call; nothing recorded |
| `journal` | run the call and record it (e.g. `gh pr merge`) |
| `ask` | raise **DSH's native approval prompt** |
| `deny` | refuse with a reason (unappealable: `guard.tamper`) |

- **Native ask** — the guard reads the `approval` service with `ctx.get('approval')` (a soft dependency, not an `inject`) and calls `request()` itself; only `allowed-once` is a grant. The outcome and the time the human took are journaled, and a granted ask returns `next()` so later pre-execute listeners still run. There is no ticket store and no approve tool.
- **Fail-closed** — a session whose approval policy never prompts, an agent-less execution, a missing or unreachable `approval` service, or a `request()` that throws all resolve to a denial naming the cause and the fix. DSH resolves a `never` policy to `rejected` inside the approval service before any answerer is dispatched, so the reject text names both causes and the preset fix; a thrown `request()` carries its message into the journal entry's `note`, which is what the deny text ("see the guard journal") points at. `deny` cannot be downgraded by configuration, and a partial or unreadable config falls back to the built-in defaults, never to an empty policy.
- **Runtime contract (spec §8)** — `contractMismatch()` rejects a `tools/pre-execute` payload carrying neither spelling of the tool name (`name`/`tool`) or of the arguments (`args`/`arguments`) with a `deny` + a `contract-mismatch` journal row. A `null` argument list counts as ABSENT (the handler's `??` already falls through on null), so it is denied rather than reaching `extractCommandText`. Without this a DSH upgrade that renames `args` would make every command rule read `undefined` and silently allow everything.
- **Journal** — `~/.dsh/dsh-maestro-guard/journal.jsonl` (0600). Secret families are redacted on the stored copy only; the executed call is never rewritten. A journal write that fails is logged and changes no decision. `allow` decisions are counted in memory and persisted as one periodic `counters` aggregate line, and rotation runs from `apply()`: `rotateIfStale()` rolls the live file at boot when its last write predates today, `startDailyRotation()` rolls once a day, and each archives the live file and prunes archives by **both** retention windows. The `domains.guard.journal` block (`enabled`, `allowCounters`, `retainFiles`, `retainDays`) is read **once at boot**, so changing it needs a host restart; its retention windows are VALIDATED on merge (they must be positive integers — a non-numeric or fractional window would otherwise prune every archive) and `domains.guard.workingDirContainment` (`enabled`, `spillReads`) is part of the per-call read instead.
- **Read-only tools** — the guard registers exactly three host tools: `maestro_guard_status` (the ~20 most recent decisions, the effective rule tiers, the journal path/state), `maestro_guard_stats` (the counters folded over the last ~1000 journal entries — `byRule` / `byTier` / `byOutcome` plus the `ask` latency percentiles; `byRule`/`byTier` fold only closed `RULE_IDS` rows, so `counters`, `config-legacy`, `guard.migration` and `policy.deny` stay out), and `maestro_full_scan` (the on-demand scan wired in `apply()` from `full-scan-tool.ts`). None can write, approve or re-decide anything. The guard registers **no approval tool** — `ask` is answered by DSH's own prompt — so no agent can grant itself a protected operation.
- **Deployment files that must stay in sync** — the `permission` row in `~/.dsh/profiles/web/cordis.patch.yml` (its `presets` table must give `danger-full-access` `approval: ask` — the deployment deliberately drops the never-prompting variant, and the picker's glyph set is closed, so a fourth preset value would render without an icon) and `permission.defaultPreset` in `~/.dsh/settings.yaml` (must name it). Neither ships in this package, and a session on `approval: never` denies every `ask`. **Live validation is still outstanding:** the spec requires a CDP probe on `:3080` (prompt shown → Allow runs the call once / Reject denies, a `never`-policy session denied, a background subagent failing closed). The `dsh web` restart that made this build the live listener has already happened (2026-09-14, observed through the guard's own `counters`/`guard.tamper` journal rows and the retired `legacy-pending.json`), so the probe is the remaining gate — run it before claiming the release validated.

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
- **Precision in the classifier** — judge a shell command on its PARSED segments' argv (quotes are already gone and their content kept; a heredoc body is data; a mention-only verb is never an access) and a non-shell tool on its path field, never on its content. `guard.tamper` is the deliberate raw-text exception, and even there only an EDIT of a guard path denies (a mutating verb or a write redirection whose target is one, in any spelling, wherever in the segment the mutation sits) — a READ falls through, or the guard's own "see the guard journal" deny text could not be followed. A mutation WORD is only read at a command position: a segment a mention verb leads is scanned after a `find` action flag only, so `rg rm <journal>` stays the read it is while `find . -execdir rm <journal> +` does not. `touch` on a guard path stays an allow on purpose — it destroys no content and an empty config loads as the built-in defaults, so it does not meet the deny tier's "edits the config or truncates/removes the journal" bar. An `ambiguous` segment escalates toward `ask`, never toward `allow`.
- **Permission semantics** — policy checks return a clear allow/deny; keep the check pure and unit-testable (no side effects).
- **Journal and migration never throw** — a failed journal write or a failed legacy-store retirement is logged and changes no decision; the guard must still boot.
- **Types** — extend `augment.d.ts` with local structural types; the workspace excludes `deepseek-harness`, so its package paths are not resolvable here.
- Every capability is a reversible effect (`ctx.effect(() => ... , label)`); declare `inject` only for hard dependencies (`tools`), and read optional services with `ctx.get`.

## Validation

`pnpm verify` + `pnpm test` green before any success claim. The rule/parse/journal modules are pure, so the vitest suite is the evidence; `tests/apply.test.ts` drives the real `apply()` against a minimal fake ctx (the `tools/pre-execute` registration and the four fail-closed outcomes), so the runtime wiring is no longer untested. Live validation against the running host is the outstanding step recorded above.
