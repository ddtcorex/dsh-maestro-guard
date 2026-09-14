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
   path field. Quoted spans and heredoc bodies are treated as data, and a tool's *content* is
   never scanned, so mentioning a protected path is not an access. The one deliberate exception is
   `guard.tamper`, which scans the **raw, unstripped** command text: tampering with the guard itself
   is judged on the whole command, not on the stripped surface.
2. **classify** — map the call to a stable rule id (`git.push.protected`, `git.merge.protected`,
   `git.tag.release`, `git.push.force`, `gh.release.create`, `gh.protection.delete`, `pkg.publish`,
   `secret.access`, `fs.write.outside`, `net.exec.remote`, `guard.tamper`), resolving the branch of
   the repo the command targets through its `cd` / `git -C`.
3. **decide** — look the rule id up in `domains.guard.rules` to get one of the four tiers below.
4. **journal** — append one redacted record per decision.
5. **act** — run the call or return a deny decision.

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
families (registry tokens, env assignments, auth headers, private keys) are redacted on the
journal copy only; the executed call is never rewritten. A legacy `pending.json` ticket file is
retired to `legacy-pending.json` on first boot.

`domains.guard` in the shared Maestro settings store tunes the gate: `rules` (per-rule tier
override), `protectedBranches`, `protectedPaths`, `guardPaths`, `journal`,
`workingDirContainment`. A missing, unreadable or half-written config falls back to the built-in
defaults — protection degrades in precision, never in coverage.

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
