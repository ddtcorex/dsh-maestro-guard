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
   wrapper (`bash -c <script>`, `bash -s`, a `bash <<EOF` body) with the script it runs. Quoted
   spans are data; a heredoc body fed to a shell is script, and one fed to a non-shell (`cat`,
   `tee`, an interpreter) stays data. Anything unresolvable is marked **ambiguous**, and an
   ambiguous segment is escalated whenever its unresolved text names a rule verb the guard can
   act on (`git push`, `gh pr merge`, a package publish, `curl … | sh`) — so an unreadable
   wrapper around a protected operation is still asked about, never allowed. When the unresolved
   text names no such verb it stays an `allow`, and quoted or inline program text is deliberately
   data: a protected operation spelled inside `python3 -c "…"` or an `--body "…"` is not a
   command. The corpus rows `carried: interpreter inline program pushing a protected branch`,
   `carried: node -e inline program tagging a release` and `carried: quoted data mentioning a
   release` pin exactly those allows. The one deliberate raw-text exception is `guard.tamper`,
   which scans the **unstripped** command text: tampering with the guard itself is judged on the
   whole command.
2. **classify** — map the call to a stable rule id (below), resolving the branch of the repo the
   command targets through its `cd` / `git -C`.
3. **decide** — look the rule id up in `domains.guard.rules` to get one of the four tiers below.
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
| `secret.access` | `ask` | access to a protected credential path — **any** file tool (read *or* write) whose path field is the protected path, or an access verb on the command surface |
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
this session (start a session under the full-access-ask preset)`. Nothing is ever allowed silently
because the prompt could not be raised.

### What an `ask` looks like

`git push origin master` classifies as `git.push.protected`, so the guard journals the decision and
raises DSH's own prompt instead of running the call. The prompt carries the rule id and the exact
command the guard classified (the `reason` string is `<rule id> :: <redacted command>`):

```text
Approval required
git.push.protected :: git push origin master
  Allow once   /   Reject
```

**Allow** runs that one call (`outcome: granted` in the journal); the next `git push origin master`
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
- `maestro_full_scan` — the on-demand full scan.

There is **no** approval tool: `ask` is answered by DSH's own prompt, so no agent can grant itself
a protected operation.

### Configuration — `domains.guard` (schema v2)

In the shared Maestro settings store:

| Key | Meaning |
| --- | --- |
| `rules` | per-rule-id tier override (merges per id onto the defaults) |
| `protectedBranches` | branch names treated as protected (default `master`, `main`) |
| `protectedPaths` | credential paths that fire `secret.access` when any file tool targets them |
| `guardPaths` | the guard's own config/secret paths (`guard.tamper`) |
| `journal` | `enabled`, `allowCounters`, and the retention window `retainFiles` (14) / `retainDays` (30) |
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
  `full-access-ask` (`sandbox: danger-full-access`, `approval: ask`);
- **`permission.defaultPreset`** in `~/.dsh/settings.yaml` — must name `full-access-ask`, so new
  sessions prompt instead of running under `danger-full-access` + `approval: never`.

Change one without the other and every `ask` denies (fail-closed, but unusable). Rollback: set
`permission.defaultPreset` back to `danger-full-access`, remove the `permission` row patch,
restart.

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
