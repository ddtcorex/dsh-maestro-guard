# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-09-14

### Changed
- Blocked operations now raise DSH's native approval prompt: the guard calls
  `approval.request()` itself and maps the outcome to allow-once or deny. The agent-mediated
  ticket flow and the `maestro_guard_approve` tool are removed, so no agent can grant itself a
  protected operation.
- Decision rules are identified by id (`git.push.protected`, `pkg.publish`, `secret.access`, …)
  and each rule's tier is overridable from `domains.guard.rules`.
- Command classification is now parsed instead of regex-matched. A shell-aware
  tokenizer/segmenter splits the command on operators that sit outside quotes, keeps every word
  and redirection, and marks anything it cannot resolve as ambiguous. An ambiguous segment is
  escalated whenever its unresolved text names a rule verb the guard can act on; when it names
  none it stays an `allow`, and quoted or inline program text is deliberately data (the corpus
  pins the `python3 -c "…"` inline-program allow). This closes the value-taking-global-option
  bypass (`git -C /repo push origin v1.2.3`, `pnpm --dir /repo publish`, `npm --prefix … publish`),
  where the old matcher never saw the subcommand.
- Shell wrappers are unwrapped: `env VAR=…`, `sudo`, `nohup` and `time` are peeled off, and a
  shell wrapper (`bash -c <script>`, `bash -s`, a `bash <<EOF` body) is replaced by the script it
  runs, so a wrapped publish or merge is judged as itself. A wrapper whose script cannot be read
  (a script file, `-c` with no argument, a nest deeper than `MAX_WRAP_DEPTH`, an interpreter's
  inline program) is marked ambiguous rather than resolved, and an exec-like wrapper the guard
  deliberately does not unwrap (`timeout`, `nice`, `setsid`, `watch`) keeps its raw surface.
  Backticks set the same expansion signal as `$(...)`.
- Heredocs are classified as data or as script: a body fed to a shell is parsed as the commands
  it runs, while a body fed to a non-shell (`cat`, `tee`, an interpreter) is attached to its
  segment as `Segment.heredoc` and never turned into segments.
- `gh pr merge` is recorded in the journal instead of being gated (`journal` tier).
- Credential scanning no longer reads tool *content*: only the executing command surface and a
  file tool's path field are inspected, which removes the mention-vs-access false positives.
- Secret redaction now applies to journal copies only and never rewrites the executed call;
  the pattern set covers registry tokens, env assignments, auth headers and private keys.
- Fail-closed by construction: a session whose approval policy never prompts is denied with an
  actionable message.
- The journal is now rotatable and retention-pruned. `Journal.rotate()` archives the live file as
  `journal-YYYY-MM-DD.jsonl` (serialized, so overlapping calls cannot collide on the name) and
  removes archived files only once they fall outside BOTH the file-count and the age window.
  Rotation is driven by the guard itself: once at boot when the live file's last write predates
  today, then once a day, so the live file stays bounded and the retention knobs apply on a host
  that never restarts. Ordinary (`allow`) decisions stay in memory and reach disk as one periodic
  `counters` aggregate line, so they never sit on the decision path.

### Added
- `~/.dsh/dsh-maestro-guard/journal.jsonl` — durable per-decision record.
- A rule registry of **11 rule ids** (`git.push.protected`, `git.merge.protected`,
  `git.tag.release`, `git.push.force`, `gh.release.create`, `gh.protection.delete`, `pkg.publish`,
  `secret.access`, `fs.write.outside`, `net.exec.remote`, `guard.tamper`) with a default tier per
  id; every tier except `guard.tamper`'s `deny` floor is overridable from `domains.guard.rules`.
- A golden corpus (`tests/fixtures/guard-corpus.json`, driven by `tests/corpus.test.ts`): one row
  per real event — a closed bypass, an over-block now allowed, or a true positive that must keep
  firing — stated as the `{ ruleId, tier }` the pipeline must produce.
- Journal counters (`byRule` / `byTier` / `byOutcome` / ask-latency percentiles) and rotation with
  retention.
- Two read-only host tools: `maestro_guard_status` (the most recent decisions, the effective rule
  tiers, the journal path) and `maestro_guard_stats` (the folded counters and ask latencies).
  Neither can write, approve or re-decide anything. `maestro_full_scan` is unchanged.
- `domains.guard.journal` knobs — `enabled` (disable journaling), `allowCounters` (stop counting
  `allow` decisions) and the retention window `retainFiles` (default 14) / `retainDays`
  (default 30). They are read once at boot, so changing them needs a host restart.
- `domains.guard.workingDirContainment` is honoured rather than merely documented: `enabled`
  (default `true`) switches the `fs.write.outside` rule on and off, and `spillReads` (default
  `true`) keeps the runtime spill dir exempt from it — with `spillReads: false` a spill-dir write
  is gated like any other write outside the session cwd. Read per call, so it applies from the
  next tool call.

### Fixed
- `secret.access` reads the parsed segment **argv** instead of `stripQuoted(command)`, which erased
  a quoted protected path before the rule looked: `cat "<path>"`, `cat '<path>'`,
  `cp "<path>" /tmp/x`, `curl -T "<path>" …` and the write-into `cp /tmp/x "<path>"` were allowed
  while their unquoted forms asked. A mention-only verb is still never an access and a heredoc body
  is still data; an ambiguous segment (an interpreter inline program, an unknown wrapper) now
  treats a protected path in its argv as an access on its own — the deliberate fail-closed
  trade-off, pinned by a corpus row.
- A segment whose first token cannot be a command (a `VAR=value` assignment, a `(`/`{` group
  opener, a shell keyword) or whose later tokens name a rule verb while `argv[0]` does not
  (`pkexec`, `perf`, `valgrind`, `sshpass`, `daemonize`, `xvfb-run`, `watchexec`, …) is marked
  ambiguous and escalated to `ask`. Those shapes used to be silently allowed because `verb =
  argv[0]` matched no rule.
- `decide()` no longer treats a `domains.guard.rules` entry that merely echoes the rule's built-in
  default as an override. The handler passes the fully-populated default table, so that reading
  made the classifier's `--dry-run` → `journal` refinement unreachable and production asked for a
  dry run. An entry that differs from the default still raises or lowers the tier, and
  `guard.tamper`'s `deny` floor is unchanged. The corpus and its driver now assert through the same
  call the handler makes.
- `guardConfigPaths()` covers the journal and the retired `legacy-pending.json` (truncating or
  removing the guard's own audit trail is the `deny` tier the spec names) and the profile
  `package.json` that actually mounts the guard row.
- An unknown `tools/pre-execute` payload now denies and journals `contract-mismatch` (spec §8). A
  DSH upgrade that renamed `args` used to make every command rule read `undefined` and silently
  allow everything.
- The thrown approval message is stored in the journal entry's `note`, so the deny text ("see the
  guard journal") points at a record that actually carries it. A granted ask returns `next()`
  rather than a bare allow, so later pre-execute listeners still run.
- `domains.guard.journal`'s `retainFiles`/`retainDays` and `domains.guard.workingDirContainment`
  are validated on merge; a non-numeric retention window used to make `rotate()` prune every
  archive.
- `maestro_guard_stats` folds only closed rule ids into `byRule`/`byTier`, so the guard's own
  bookkeeping rows (`counters`, `config-legacy`, `guard.migration`, `policy.deny`) no longer appear
  as decisions; `byOutcome` still counts every row.
- Precision follow-up on the fix wave's over-blocks and residuals:
  - `guard.tamper` is scoped to **edits**, as the spec's deny tier says: a shell segment denies
    only when a mutating verb (`rm`, `mv`, `cp`, `truncate`, `shred`, `dd`, `tee`, `install`,
    `chmod`, `chown`, `sed -i`, `perl -i`) names a guard path, or a write redirection (`>`, `>>`,
    `2>`, `&>`) targets one. Reads fall through, so the journal stays readable by the path the
    guard's own deny text points at, and the matcher now knows the `~`, `$HOME` and `${HOME}`
    spellings of every guard path rather than only the absolute one.
  - A mention-led segment no longer escalates: `rg git push docs/`, `grep -rn npm publish docs`
    and `echo pnpm publish` stay `allow` (those verbs cannot execute their arguments), while
    `find` still asks through any of its action flags (`-exec`, `-execdir`, `-ok`, `-okdir`).
  - `secret.access` tests the access verb against the segment's **command**, not the whole argv,
    so a commit message or PR body that merely writes `cat <path>` is text about the path and no
    longer asks.
  - A path-qualified verb resolves by base name (`/usr/bin/git` is `git`), and a `-c` script
    handed to a shell by a verb the guard cannot name (`my-custom-runner bash -c "…"`) is parsed
    as the command that really runs.
  - `contractMismatch` treats a `null` argument list as absent, and a retention window must be a
    positive INTEGER — `retainDays: 0.5` used to floor to 0 and prune every archive.
- Fix wave on that follow-up's own deny-tier regression, found by re-review and measured against
  the built classifier. Narrowing `guard.tamper` to EDITS left the tier blind to every mutation
  whose verb is not the segment's own, because the parser marks an exec wrapper `ambiguous`
  instead of unwrapping it — each of these resolved to `allow`, i.e. a wipe of the guard's own
  journal with no prompt at all, where the pre-fix build denied even a bare mention:
  - a mutation behind a wrapper: `nice`, `timeout 5`, `flock L`, `ssh host`, `doas`, `xargs`,
    `eval`;
  - a mutation `find` runs: `-exec` (already covered), plus `-execdir`, `-ok`, `-okdir`;
  - a mutation one level deeper: `find … -exec bash -c "rm -f <journal>" +`;
  - a mutation an OPAQUE verb takes across a pipe: `echo <journal> | xargs rm -f`;
  - a clobber redirect: `echo x >| <journal>` (the tokenizer split `>|` into `>` and `|`, so the
    target became a segment of its own that no rule read);
  - a symlink swap in place of the journal: `ln` is now a mutating verb.

  The read exemption is unchanged and re-pinned: a mutation WORD is only read at a command
  position, so `rg rm <journal>`, `echo rm -f <journal>`, `timeout 5 cat <journal>` and
  `find . -exec cat <journal> +` all stay `allow`. `touch` on a guard path also stays an allow —
  it destroys no content, and an empty config loads as the built-in defaults.

### Removed
- `pending.json` ticket store, the approve/list tools and the unused approval store. A legacy
  ticket file is retired to `legacy-pending.json` on first boot.
- `src/host/sandbox.ts` — its command matching died into `src/host/parse.ts` (shell-aware
  tokenizer/segmenter and wrapper unwrapping) and its path checks into `src/host/paths.ts`.

## [0.2.3] - 2026-09-04

### Fixed

- Resolve relative file paths against the session cwd instead of the
  process cwd. (#19)
- Allow read-only access to the DSH runtime session-spill directory so
  reviewers can read spilled diffs. (#20)

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
