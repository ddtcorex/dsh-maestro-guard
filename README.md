# @ddtcorex/dsh-maestro-guard

Host-only safety gate for the DeepSeek Harness: one Cordis row (`dsh-maestro-guard`) listens on
the `tools/pre-execute` waterfall and decides every tool call before it runs.

Part of the Maestro Harness suite (`dsh-maestro-*`). Cordis patch row id: `dsh-maestro-guard`.

> Opt-in and intentionally **not** part of the meta-bundle one-liner until published:
> add it explicitly with `dsh plugin add @ddtcorex/dsh-maestro-guard`.

## What it provides

Every call runs the same five-step pipeline:

```
parse → classify → decide → journal → act
```

1. **parse** — read the executed surface of the call: a shell tool's command text, a file tool's
   path field. The command is **parsed**, not regex-matched: a shell-aware tokenizer/segmenter
   splits it on operators that sit outside quotes, unwraps the wrappers that only change *who*
   runs it (`env VAR=…`, `sudo`, `nohup`, `time`, `command`, `busybox`) and replaces a shell
   wrapper (`bash -c <script>`, `bash -s`, a `bash <<EOF` body) with the script it runs. Anything
   unresolvable is marked **ambiguous**, and an ambiguous segment is escalated whenever its
   unresolved text names a rule verb the guard can act on (`git push`, `gh pr merge`, a package
   publish, `curl … | sh`) — so an unreadable wrapper around a protected operation is still asked
   about, never allowed. When the unresolved text names no such verb it stays an `allow`, and
   quoted or inline program text is deliberately data: a protected operation spelled inside
   `python3 -c "…"` or an `--body "…"` is not a command.

   Two hard cases are decided by SHAPE rather than by a longer verb list. A segment whose first
   token cannot be a command (a `VAR=value` assignment, a `(`/`{` group opener, a shell keyword)
   or whose LATER tokens name a rule verb while `argv[0]` does not (`pkexec …`, `perf …`,
   `my-custom-runner …`) is ambiguous, so the operation written behind it is asked about instead
   of silently allowed. And a quoted protected path is not erased: `secret.access` reads the
   parsed segment argv, where the tokenizer has already dropped the quotes and kept the content,
   so `cat "<path>"`, `cp "<path>" /tmp/x`, `curl -T "<path>" …` and the write-into
   `cp /tmp/x "<path>"` all ask just like their unquoted forms.

   The corpus rows `carried: interpreter inline program pushing a protected branch`, `carried:
   node -e inline program tagging a release`, `carried: quoted data mentioning a release` and the
   `protected path: quoted …` rows pin those decisions — including the deliberate fail-closed
   trade-off that an interpreter inline program which names a protected path asks again. The one
   deliberate raw-text exception is `guard.tamper`, which scans the **unstripped** command text:
   tampering with the guard itself is judged on the whole command.
2. **classify** — map the call to a stable rule id (below), resolving the branch of the repo the
   command targets through its `cd` / `git -C`.
3. **decide** — resolve the tier: the classified tier, unless `domains.guard.rules` carries an
   entry that DIFFERS from the rule's built-in default. An entry that merely echoes the default is
   the table repeating itself, not a user choice — honouring those made every classify-level
   refinement (a `--dry-run` publish is a `journal`, not an `ask`) unreachable.
4. **journal** — append one redacted record per decision.
5. **act** — run the call or return a deny decision.

### Rule ids

Rule ids are the contract — config overrides, journal entries and approval reasons all key on
them. There are **11**:

| Rule id | Default tier | Fires on |
| --- | --- | --- |
| `git.push.protected` | `ask` | a push targeting a protected branch: an explicit refspec naming one, `HEAD`/no refspec resolved through the target repo's checked-out branch, `--all`/`--mirror` (they push every local branch), or a branch that cannot be resolved (fail-closed) |
| `git.merge.protected` | `journal` | a `gh pr merge` (recorded rather than gated) |
| `git.tag.release` | `ask` | a release/semver tag push (a `refs/tags/*` refspec, a bare `vX.Y.Z`, or `--tags`) |
| `git.push.force` | `ask` | a force push (`--force`, `--force-with-lease`, `-f`, `+refspec`) |
| `gh.release.create` | `ask` | `gh release create` / `gh release publish` |
| `gh.protection.delete` | `ask` | a `gh api … DELETE` against branch protection |
| `pkg.publish` | `ask` | a package-manager publish (npm / pnpm / yarn) |
| `secret.access` | `ask` | access to a protected credential path — **any** file tool (read *or* write) whose path field is the protected path, or a parsed segment whose argv holds both an access verb and the path (a mention-only verb such as `grep`/`ls`/`printf` is never an access, and a heredoc body is never argv) |
| `fs.write.outside` | `ask` | a file-tool write outside the session working directory (the OS temp dir is exempt, and so is the runtime spill dir while `spillReads` is on) |
| `net.exec.remote` | `ask` | piping a remote script into a shell (`curl … \| sh`, `source <(curl …)`) |
| `guard.tamper` | `deny` | touching the guard's own config paths |

`guard.tamper` is an unappealable `deny` floor — it cannot be downgraded by configuration.
Every other default tier can be overridden per rule id in `domains.guard.rules`.

### Decision tiers

| Tier | Effect |
| --- | --- |
| `allow` | run the call; nothing recorded |
| `journal` | run the call and record it (e.g. `gh pr merge` is no longer gated) |
| `ask` | **DSH's native approval prompt**: the guard calls the `approval` service itself, only `allowed-once` proceeds, and the outcome plus the time the human took is recorded |
| `deny` | refuse and tell the agent why (unappealable self-protection: `guard.tamper`) |

A `deny` also fires when the tool policy (`PermissionPolicy`) rejects the call. The guard
registers **no** approval tool, so no agent can grant itself a protected operation.

**Fail-closed by construction:** a session whose approval policy never prompts, an agent-less
execution, or a missing/unreachable `approval` service all resolve to a denial that names the
cause and the fix — the shipped `unavailable` message reads `no approval channel is available for
this session (start a session under a preset that prompts — this deployment's `danger-full-access` now asks)`. Nothing is ever allowed silently
because the prompt could not be raised.

A `request()` that throws is denied with `the approval request failed (see the guard journal)`, and
the thrown message is stored in that journal entry's `note`, so the pointer is honest. DSH resolves
a `never` approval policy to `rejected` inside the approval service, before any answerer is
dispatched, so the guard cannot tell a policy rejection from a human one — the reject text names
both causes and the preset fix rather than claiming a human decided.

The handler also refuses to run on an unknown `tools/pre-execute` payload (spec §8): a payload
carrying neither `name`/`tool` nor `args`/`arguments` is denied and journaled as
`contract-mismatch`. Without that guard a DSH upgrade that renames `args` would make every command
rule read `undefined` and silently allow everything.

### What an `ask` looks like

`git push origin master` classifies as `git.push.protected`, so the guard journals the decision and
raises DSH's own prompt instead of running the call. The prompt carries the rule id and the exact
command the guard classified (the `reason` string is `<rule id> :: <redacted command>`):

```text
Approval required
git.push.protected :: git push origin master
  Allow once   /   Reject
```

**Allow** runs that one call (`outcome: granted` in the journal) and returns `next()`, so any other
pre-execute listener still runs; the next `git push origin master`
asks again — there is no standing grant. **Reject** returns a deny to the agent and records
`outcome: rejected`, which is what `maestro_guard_status` then shows. A prompt that cannot be
raised at all is the fail-closed `unavailable` outcome above, never a silent allow.

### Journal

`~/.dsh/dsh-maestro-guard/journal.jsonl` — one JSON line per decision, mode 0600. Secret
families (registry tokens, env assignments, auth headers, private keys) are redacted at the
`Journal.append` choke point, so **every** string field of a persisted entry is redacted and no
call site can write an unredacted value; the executed call is never rewritten. A legacy
`pending.json` ticket file is retired to `legacy-pending.json` on first boot.

Ordinary (`allow`) decisions never reach the journal individually: they are counted in memory and
persisted as one periodic `counters` aggregate line, so they stay off the decision path.

Rotation and retention run on their own: at boot the guard rolls the live file when its last write
predates today, then rolls once a day, archiving it as `journal-YYYY-MM-DD.jsonl` and pruning
archived files that fall outside **both** retention windows (`retainFiles` and `retainDays`). So the
live file stays bounded and those knobs actually apply on a host that never restarts — rotation is
time-based, not a size trigger, and `Journal.rotate()` remains callable on demand.

### Tools

The guard registers three host tools. All are read-only with respect to the guard:

- `maestro_guard_status` — the ~20 most recent decisions, the effective rule tiers, and the
  journal path/state.
- `maestro_guard_stats` — the folded counters over the last ~1000 journal entries: `byRule`,
  `byTier`, `byOutcome`, and the `ask` approval-latency percentiles (`p50` / `p90` / `max`).
  `byRule`/`byTier` fold only rows whose rule is one of the closed rule ids, so the guard's own
  bookkeeping rows (`counters`, `config-legacy`, `guard.migration`, `policy.deny`) do not appear
  as decisions; `byOutcome` counts every row.
- `maestro_full_scan` — the on-demand full scan.

There is **no** approval tool: `ask` is answered by DSH's own prompt, so no agent can grant itself
a protected operation.

### Configuration — `domains.guard` (schema v2)

In the shared Maestro settings store:

| Key | Meaning |
| --- | --- |
| `rules` | per-rule-id tier override (merges per id onto the defaults). An entry that equals the rule's built-in default is not an override — the effective tier is the classified one unless an entry DIFFERS from the default |
| `protectedBranches` | branch names treated as protected (default `master`, `main`) |
| `protectedPaths` | credential paths that fire `secret.access` when any file tool targets them |
| `guardPaths` | the guard's own config/secret paths (`guard.tamper`): the settings file, the profile row patch, the profile `package.json` that mounts the guard, and the journal + `legacy-pending.json` |
| `journal` | `enabled`, `allowCounters`, and the retention window `retainFiles` (14) / `retainDays` (30); a non-numeric window falls back to the built-in one (unvalidated, it made `rotate()` prune every archive) |
| `workingDirContainment` | `enabled` (default `true`) switches the `fs.write.outside` rule on/off; `spillReads` (default `true`) keeps the runtime spill dir exempt from that rule — set `false` to gate spill-dir writes too |

The `journal` block is read **once at boot** (it decides whether the journal writes at all and
which retention defaults rotation uses), so changing it needs a host restart. Every other key,
`workingDirContainment` included, is part of the per-call config read and takes effect on the next
tool call. A missing, unreadable or half-written config falls back to the built-in defaults —
protection degrades in precision, never in coverage.

**Legacy keys** written for schema v1 are translated forward on read and the translated key is
journalled once per boot:

| Legacy key | Maps to |
| --- | --- |
| `gitProtection.enabled: false` | the three git rules (`git.push.protected`, `git.tag.release`, `git.push.force`) become `journal` |
| `gitProtection.branches` | `protectedBranches` |
| `publishBlocked: false` | `pkg.publish` becomes `journal` |
| `cwdContainment: false` | `fs.write.outside` becomes `journal` |
| `credentialPaths` | **added** to `protectedPaths` (never replaces it) |

An explicit v2 `rules` entry wins over the legacy boolean that produced the same rule id.

### Deployment files that must stay in sync

An `ask` tier only bites if the session actually prompts, and two deployment files carry that
(neither ships in this package):

- the **`permission` row** in the `web` profile composition
  (`~/.dsh/profiles/web/cordis.patch.yml`) — its `presets` table must define
  `danger-full-access` with `approval: ask` (the prompting full-access mode rides the existing
  preset value so it keeps the picker's built-in shield glyph, product label and risk confirmation);
- **`permission.defaultPreset`** in `~/.dsh/settings.yaml` — must name `danger-full-access`, so new
  sessions prompt instead of running under an `approval: never` preset.

Change one without the other and every `ask` denies (fail-closed, but unusable). Rollback: set
`permission.defaultPreset` back to `danger-full-access`, remove the `permission` row patch,
restart.

**Live validation is a recorded, deliberate deferral — not an oversight.** The spec marks a CDP
probe on `:3080` (prompt appears with the rendered reason; Allow runs; Reject blocks; a `never`
session is denied with the actionable message; a background subagent fails closed) as required
before "done". The human deferred the `dsh web` restart that would put this build into the running
host, so the deployed host is still 0.2.3. The profile installs this package with `link:` and `lib/`
is already built, so **any unrelated `dsh web` restart deploys 0.3.0 unvalidated** against a live
approval prompt — until this validation runs, the build is unverified in production.

Host-only: no client bundle; DSH types come from local structural declarations
(`src/host/augment.d.ts`).

## Development

```sh
pnpm install
pnpm verify   # tsc --noEmit
pnpm test     # vitest run
pnpm build    # tsc -> lib/
```

## License

MIT
