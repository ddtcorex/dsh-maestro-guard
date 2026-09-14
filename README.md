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
   runs it (`env VAR=…`, `sudo`, `nohup`, `time`) and replaces a shell wrapper (`bash -c <script>`,
   `bash -s`, a `bash <<EOF` body) with the script it runs. Quoted spans are data; a heredoc body
   fed to a shell is script, and one fed to a non-shell (`cat`, `tee`, an interpreter) stays data.
   Anything unresolvable is marked **ambiguous**, and the rule layer never treats ambiguity as an
   allow — it escalates. The one deliberate raw-text exception is `guard.tamper`, which scans the
   **unstripped** command text: tampering with the guard itself is judged on the whole command.
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
| `git.push.protected` | `ask` | a push (or `HEAD`) targeting a protected branch |
| `git.merge.protected` | `journal` | a `gh pr merge` (recorded rather than gated) |
| `git.tag.release` | `ask` | a release/semver tag push |
| `git.push.force` | `ask` | a force push |
| `gh.release.create` | `ask` | `gh release create` / `gh release publish` |
| `gh.protection.delete` | `ask` | a `gh api … DELETE` against branch protection |
| `pkg.publish` | `ask` | a package-manager publish (npm / pnpm / yarn) |
| `secret.access` | `ask` | access to a protected credential path — a file tool's path or an access verb on the command surface |
| `fs.write.outside` | `ask` | a file-tool write outside the session working directory (temp dir exempt) |
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

### Journal

`~/.dsh/dsh-maestro-guard/journal.jsonl` — one JSON line per decision, mode 0600. Secret
families (registry tokens, env assignments, auth headers, private keys) are redacted at the
`Journal.append` choke point, so **every** string field of a persisted entry is redacted and no
call site can write an unredacted value; the executed call is never rewritten. A legacy
`pending.json` ticket file is retired to `legacy-pending.json` on first boot.

Ordinary (`allow`) decisions never reach the journal individually: they are counted in memory and
persisted as one periodic `counters` aggregate line, so they stay off the decision path.
`Journal.rotate()` archives the live file as `journal-YYYY-MM-DD.jsonl` and prunes archived files
that fall outside **both** retention windows (`retainFiles` and `retainDays`) — rotation is an
explicit call, not an automatic size trigger.

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
| `protectedPaths` | credential paths whose read fires `secret.access` |
| `guardPaths` | the guard's own config/secret paths (`guard.tamper`) |
| `journal` | `enabled`, `allowCounters`, and the retention window `retainFiles` (14) / `retainDays` (30) |
| `workingDirContainment` | `enabled`, `spillReads` — the outside-cwd write check |

The `journal` block is read **once at boot** (it decides whether the journal writes at all and
which retention defaults rotation uses), so changing it needs a host restart. A missing, unreadable
or half-written config falls back to the built-in defaults — protection degrades in precision,
never in coverage.

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
