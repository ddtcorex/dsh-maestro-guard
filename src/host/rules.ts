import type { Tier } from './tiers.js'
import {
  parseCommand,
  unwrapSegments,
  extractCommandText,
  extractPathField,
  getCommandWorkingDir,
  stripQuoted,
  EXEC_WRAPPERS,
  MENTION_VERBS,
  OPAQUE_VERBS,
  type Segment,
} from './parse.js'
import { isBlockedPath, isOutsideCwd, isRuntimeSpillPath, isWithinTempDir, pathSpellings } from './paths.js'

/**
 * The closed set of rule ids the classifier can emit (the empty id is the
 * allow verdict, deliberately not listed — there is no allow "rule").
 * Rule ids are the stable contract: config overrides, journal entries and
 * approval reasons all key on them, so they are never renamed casually.
 */
export const RULE_IDS = [
  'git.push.protected',
  'git.merge.protected',
  'git.tag.release',
  'git.push.force',
  'gh.release.create',
  'gh.protection.delete',
  'pkg.publish',
  'secret.access',
  'fs.write.outside',
  'net.exec.remote',
  'guard.tamper',
] as const

/** Default tier per rule id, before any config override (see `decide`). */
export const DEFAULT_TIERS: Record<string, Tier> = {
  'git.push.protected': 'ask',
  'git.merge.protected': 'journal',
  'git.tag.release': 'ask',
  'git.push.force': 'ask',
  'gh.release.create': 'ask',
  'gh.protection.delete': 'ask',
  'pkg.publish': 'ask',
  'secret.access': 'ask',
  'fs.write.outside': 'ask',
  'net.exec.remote': 'ask',
  'guard.tamper': 'deny',
}

/**
 * The `domains.guard.workingDirContainment` block after config merge. Both
 * switches default to `true` in `DEFAULT_CONFIG`, so an absent block here is
 * read as the documented default (containment ON) rather than as an escape
 * hatch — a caller that cannot read config must never disarm the rule.
 */
export interface WorkingDirContainmentSettings {
  /** `false` disables the `fs.write.outside` rule entirely. */
  enabled?: boolean
  /** `false` removes the runtime-spill exemption (the OS temp exemption stays). */
  spillReads?: boolean
}

export interface RuleSettings {
  protectedBranches: string[]
  protectedPaths: string[]
  guardPaths: string[]
  /**
   * Optional so a direct `classify` caller (tests, tools) that has no config
   * reading still gets the safe default; `index.ts` always threads the merged
   * `domains.guard` block through.
   */
  workingDirContainment?: WorkingDirContainmentSettings
}

export interface Verdict {
  ruleId: string
  tier: Tier
  target: string
  repo?: string
  branch?: string
  detail?: Record<string, string>
}

export interface ClassifyContext {
  tool: string
  args: unknown
  cwd?: string
  settings: RuleSettings
  branchOf?: (dir: string) => string | undefined
}

const FILE_TOOLS = new Set([
  'read',
  'write',
  'edit',
  'maestro_read_file',
  'maestro_write_file',
  'fs_read',
  'fs_write',
  'read_file',
  'write_file',
])
const WRITE_FILE_TOOLS = new Set(['write', 'edit', 'maestro_write_file', 'fs_write', 'write_file'])
/** Verbs that actually touch file contents — a protected path next to one is an access. */
const ACCESS_VERBS = /\b(cat|bat|head|tail|less|more|cp|scp|rsync|curl|wget|source|tee|dd|install|xxd|base64|openssl|gpg|tar|zip)\b/

/**
 * Verbs that WRITE the file they name. A guard path next to one of these is an
 * EDIT, which is what the spec's deny tier covers (§5.4/§5.6: "a segment that
 * edits the guard's own settings/config or truncates/removes the journal").
 * Reads (`cat`, `tail`, `head`, `grep`, `less`) are deliberately absent: the
 * guard's own deny text tells the agent to "see the guard journal", so a read
 * has to fall through to the ordinary rules.
 */
const MUTATION_VERBS = new Set(['rm', 'mv', 'cp', 'truncate', 'shred', 'dd', 'tee', 'install', 'chmod', 'chown'])
/** Editors that write only when their in-place switch is present. */
const IN_PLACE_EDITORS = new Set(['sed', 'perl'])
/** `-i`, `-ni`, `-i.bak`, `--in-place` — the in-place switch of those editors. */
const IN_PLACE_FLAG = /^--in-place(?:=.*)?$|^-[A-Za-z]*i/
/** A redirection that WRITES its target (`>`, `>>`, `2>`, `&>`). Not `>&2`, not `<`. */
const WRITE_REDIRECT = /^(?:[0-9]+)?(?:&>>?|>>?)$/

/**
 * `fs.write.outside` covers the whole write family — the DSH-native `write` and
 * `edit` tools as well as the legacy Maestro writers. Scoping the rule to the
 * legacy names alone is what made the original cwd containment inert: the tools
 * actually in use (`read`/`write`/`edit`) were never matched. The OS temp dir is
 * exempt (`isWithinTempDir`) so scratch work stays frictionless; the runtime
 * spill dir is a subdirectory of it and keeps its explicit exemption while
 * `workingDirContainment.spillReads` is on. Both exemptions are resolved against
 * the SAME base as the containment test — the session cwd — so the two can never
 * disagree about a relative target.
 *
 * The spill switch is why {@link isExemptWritePath} tests the spill path BEFORE
 * the temp dir: the spill dir lives under `os.tmpdir()`, so testing the temp
 * exemption first would make `spillReads: false` a no-op for every absolute
 * spill path — the "documented but inert" failure the wiring closes.
 */
function isExemptWritePath(path: string, cwd: string, containment?: WorkingDirContainmentSettings): boolean {
  if (isRuntimeSpillPath(path, cwd)) return containment?.spillReads !== false
  return isWithinTempDir(path, cwd)
}

/* ------------------------------------------------------------------ *
 * Protected operations, resolved from parsed segments
 * ------------------------------------------------------------------ */

/** Package managers whose `publish` verb is gated. */
const PACKAGE_MANAGERS = new Set(['pnpm', 'npm', 'yarn'])

/**
 * Package-manager verbs that run a named SCRIPT or package: `npm run publish`
 * runs a script called `publish` and `yarn dlx publish` runs a package, so in
 * neither is `publish` the verb that publishes THIS project.
 */
const SCRIPT_RUNNER_VERBS = new Set(['run', 'run-script', 'exec', 'dlx'])

/** Shells whose `-c`/stdin argument the parser can read (see `parse.ts`'s SHELLS). */
const SHELL_NAMES = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'ash', 'fish', 'csh', 'tcsh'])

/** `source`/`.` execute the process substitution they are handed, like a shell does. */
const SOURCE_VERBS = new Set(['source', '.'])

/** `vX.Y.Z` / `X.Y.Z` plus an optional prerelease or build suffix — a release tag, not a branch. */
const SEMVER_REF = /^v?\d+\.\d+\.\d+(?:[-+][0-9a-z.]+)?$/i

/**
 * Raw-text shapes for the ambiguity escalation. A segment the parser could not
 * resolve (an exec-like wrapper, an expansion, an unknown option) is escalated
 * only when its own raw text carries one of these — otherwise `ssh host ls`
 * would prompt on every call. They are deliberately the same shapes the rule
 * layer resolves from a parsed segment, applied to the text the parser refused
 * to resolve — read through `rawSurface`, so quoted data cannot fire one.
 */
const RAW_GH_PR_MERGE = /\bgh\s+pr\s+merge\b/
const RAW_GH_RELEASE = /\bgh\s+release\s+(?:create|publish)\b/i
/** `gh api … DELETE …` — the protected branch it runs on is checked separately. */
const RAW_GH_API_DELETE = /\bgh\s+api\b[\s\S]*\bdelete\b/i
const RAW_PUBLISH = /\b(pnpm|npm|yarn)\b[^\n]*\bpublish\b/
const RAW_GIT_PUSH = /\bgit\s+push\b/
const RAW_RELEASE_TAG = /refs\/tags\/|(?:^|\s)v?\d+\.\d+\.\d+(?:[-+][0-9a-z.]+)?(?:\s|$)/
const RAW_FORCE_PUSH = /(?:^|\s)(?:--force(?:-with-lease)?|-f)(?:=|\s|$)/
const RAW_REMOTE_EXEC =
  /\b(curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(source|\.)\s*<\(\s*(curl|wget)\b|\b(?:ba|z|da)?sh\s*<\(\s*(curl|wget)\b/

/** The verb without its directory (`/bin/bash` → `bash`). */
function baseName(verb: string | undefined): string | undefined {
  if (verb === undefined) return undefined
  const cut = verb.lastIndexOf('/')
  return cut === -1 ? verb : verb.slice(cut + 1)
}

/** The shell a verb names, bare or by path (`/bin/bash` → `bash`). */
function shellName(verb: string | undefined): string | undefined {
  const base = baseName(verb)
  return base !== undefined && SHELL_NAMES.has(base) ? base : undefined
}

/**
 * True when a verb RUNS a command of its own: an exec-like wrapper the parser
 * deliberately does not unwrap (`ssh host CMD`, `timeout 5 CMD`, `script -c
 * CMD`) or an opaque runner (`eval`, `exec`, `xargs`). Both classes are exactly
 * the segments the parser marks `ambiguous` on the verb alone, and in both the
 * quoted span is the command being run, not data about it. The sets live in
 * `parse.ts`, which owns the ambiguity classification.
 */
function runsOwnCommand(verb: string | undefined): boolean {
  const base = baseName(verb)
  return base !== undefined && (EXEC_WRAPPERS.has(base) || OPAQUE_VERBS.has(base))
}

/**
 * The text a raw-shape matcher reads for one segment: `seg.raw` with its quoted
 * spans collapsed, because the batch contract is that quotes are DATA. A quoted
 * mention therefore never fires a rule — `gh pr create --body "gh release create
 * v1"` is a description, and a quoted task or program body that happens to hold
 * `git push origin v1.0.0` is text, not a push.
 *
 * The one exception is a verb that runs its own argument (`runsOwnCommand`):
 * `ssh host "git push origin main"` really does push, so collapsing that quote
 * would turn the fail-closed ambiguity escalation into an allow.
 *
 * KNOWN, DELIBERATE `allow` — interpreter inline programs: `python3 -c "…"`,
 * `node -e "…"`, `perl -e "…"`, `php -r "…"` are not in either unwrap set, so
 * the quoted program is data and a protected operation spelled inside it is
 * allowed (`python3 -c "…os.system('git push origin master')"`). That is
 * accepted rather than overlooked: an inline program is lexically
 * indistinguishable from the `node -e` MENTION case the deleted
 * `multiline-quoted` suite pinned as not-gated (`node -e "… git push origin
 * v1.0.0 …"` must stay quiet), and the guard never reads a script file's
 * contents either way — `python3 deploy.py` is equally opaque. Gating it would
 * require the guard to interpret the interpreter's language. Task B5 must pin
 * this residual as an explicit `allow` row in the golden corpus.
 */
function rawSurface(seg: Segment): string {
  return runsOwnCommand(seg.verb) ? seg.raw : stripQuoted(seg.raw)
}

/** Both sides of a refspec: `+refs/heads/x:refs/heads/y` → `['x', 'y']`. */
function refNames(refspec: string): string[] {
  return refspec
    .replace(/^\+/, '')
    .split(':')
    .map((side) => side.replace(/^refs\/(?:heads|tags|remotes)\//, '').replace(/^refs\//, ''))
    .filter((side) => side !== '')
}

/** True when any refspec this push names is one of the protected branches. */
function namesProtectedBranch(seg: Segment, branches: string[]): boolean {
  const wanted = new Set(branches.map((b) => b.toLowerCase()))
  return seg.refspecs.some((r) => refNames(r).some((name) => wanted.has(name.toLowerCase())))
}

/** True for `refs/tags/*` and for a bare semver tag (`v1.2.3`, `1.2.3-rc.2`). */
function isTagRefspec(refspec: string): boolean {
  if (refspec.replace(/^\+/, '').split(':').some((side) => side.startsWith('refs/tags/'))) return true
  return refNames(refspec).some((name) => SEMVER_REF.test(name))
}

/** `--force`, `--force-with-lease[=…]`, a `-f` (alone or in a short cluster), or a `+refspec`. */
function isForcePush(seg: Segment): boolean {
  if (seg.refspecs.some((r) => r.startsWith('+'))) return true
  return seg.flags.some(
    (f) => f === '--force' || f.startsWith('--force-with-lease') || (/^-[A-Za-z]+$/.test(f) && f.includes('f')),
  )
}

/**
 * `HEAD` (and `@`) alone name no target of their own: they push the branch the
 * repository is checked out on, so they are resolved through `branchOf` rather
 * than read as an explicit, safe refspec. `HEAD:feature/x` is explicit — its
 * destination names the target.
 */
function isImplicitRefspec(refspec: string): boolean {
  const bare = refspec.replace(/^\+/, '')
  if (bare.includes(':')) return false
  return bare === 'HEAD' || bare === '@'
}

/**
 * `git push`, refspec-first (spec §5.4): an explicit refspec is the target, so a
 * protected name or a release tag in it decides the verdict; only a push with
 * nothing but the remote (or `HEAD`) falls back to the branch the target repo is
 * checked out on. A branch that cannot be resolved is fail-closed: `cd "$D" &&
 * git push origin HEAD` must ask because the branch cannot be proven safe.
 */
function classifyPush(seg: Segment, command: string, ctx: ClassifyContext, cwd?: string): Verdict | undefined {
  const branches = ctx.settings.protectedBranches
  if (namesProtectedBranch(seg, branches)) {
    return { ruleId: 'git.push.protected', tier: 'ask', target: command }
  }
  if (seg.refspecs.some(isTagRefspec)) {
    return { ruleId: 'git.tag.release', tier: 'ask', target: command }
  }
  // Flag targets, checked before the refspec reading: `--all`/`--mirror` push
  // every local branch — including a protected one — and `--mirror` can also
  // force-update or delete remote refs, while `--tags` means `refs/tags/*`.
  // None of them carries a refspec, so the flag itself is the target and the
  // branch fallback must never see them.
  if (seg.flags.includes('--all') || seg.flags.includes('--mirror')) {
    return { ruleId: 'git.push.protected', tier: 'ask', target: command }
  }
  if (seg.flags.includes('--tags')) {
    return { ruleId: 'git.tag.release', tier: 'ask', target: command }
  }
  if (isForcePush(seg)) {
    return { ruleId: 'git.push.force', tier: 'ask', target: command }
  }
  const explicit = seg.refspecs.slice(1).filter((r) => !isImplicitRefspec(r))
  if (explicit.length > 0) return undefined
  // The repo the push actually runs in: `cd <dir>` / `git -C <dir>` when the
  // command names one, the session cwd otherwise — never an empty-dir sentinel.
  const repo = getCommandWorkingDir(command, cwd)
  const branch = repo === undefined ? undefined : ctx.branchOf?.(repo)
  if (branch !== undefined && branches.some((b) => b.toLowerCase() === branch.toLowerCase())) {
    return { ruleId: 'git.push.protected', tier: 'ask', target: command, repo, branch }
  }
  if (branch === undefined) {
    // A repo that names a working directory the guard cannot read, or a branch
    // `branchOf` cannot resolve, must not be treated as safe: ask.
    return { ruleId: 'git.push.protected', tier: 'ask', target: command, repo }
  }
  return undefined
}

/** `gh pr merge` — parsed, not matched against the raw text. */
function isGhPrMerge(seg: Segment): boolean {
  if (baseName(seg.verb) !== 'gh') return false
  return seg.argv.some((word, i) => word === 'pr' && seg.argv[i + 1] === 'merge')
}

/**
 * A `gh` statement read from the segment that carries it. A RESOLVED segment
 * must name `gh` as its verb, so a quoted mention inside a resolved
 * `echo "gh release create v1"` stays data; a segment the parser could not
 * resolve is judged on its raw text — the same fail-closed reading every other
 * ambiguity escalation uses — because the command it really runs was never
 * parsed. Neither shape needs parser support beyond the segment boundary, and
 * both read `rawSurface` so a quoted mention (`gh pr create --body "… gh release
 * create …"`) cannot fire the rule it is describing.
 */
function namesGhStatement(seg: Segment, shape: RegExp): boolean {
  if (!seg.ambiguous && baseName(seg.verb) !== 'gh') return false
  return shape.test(rawSurface(seg))
}

/**
 * `gh api … delete … /branches/<protected>/protection` removes the gate the
 * workspace relies on, so it asks. The branch set is the same one `git push`
 * uses; the match is a plain lowercased substring so a branch name carrying
 * regex characters cannot change the result.
 *
 * The shape gate reads `rawSurface` (quotes are data), but the branch LOCATOR is
 * a target lookup, not a shape match: it must read the RAW segment text. People
 * quote the path precisely because it is built (`{}`, `$VAR`, a URL), and on the
 * stripped surface `gh api -X DELETE "<path>"` collapses to `gh api -X DELETE`,
 * so the locator would find no branch and allow the deletion.
 */
function deletesProtectedBranchProtection(seg: Segment, branches: string[]): boolean {
  if (!namesGhStatement(seg, RAW_GH_API_DELETE)) return false
  const lower = seg.raw.toLowerCase()
  return branches.some((b) => {
    const name = b.trim().toLowerCase()
    return name !== '' && lower.includes(`/branches/${name}/protection`)
  })
}

/**
 * True when the segment is a `git push`. The resolved reading is the parser's
 * subcommand; a segment the parser could not resolve still names `push` in its
 * `argv`/`refspecs` (`git $GITS push origin master` — an expansion between the
 * verb and the subcommand), and that shape is routed to the same push
 * classifier rather than allowed.
 */
function isPushSegment(seg: Segment): boolean {
  if (seg.subcommand === 'push') return true
  return seg.ambiguous && (seg.argv.includes('push') || seg.refspecs.includes('push'))
}

/**
 * A package-manager publish. The publish verb is looked up among the segment's
 * non-flag words instead of `subcommand`, because an untabled value-taking short
 * option occupies that slot (`npm -w <name> publish` reads `subcommand '<name>'`).
 * Two shapes are excluded so the word `publish` alone is not enough:
 *
 * - a `publish` word sitting BEFORE the resolved subcommand is the value of a
 *   value-taking option (`pnpm --filter publish test`), never the verb;
 * - a SCRIPT RUNNER occupying the resolved subcommand slot (`npm run publish`,
 *   `npm exec publish`, `yarn dlx publish`) makes every later `publish` word the
 *   name of a script or a package. The test is positional, never a scan of the
 *   words before `publish`: a value-taking option's VALUE can read `run`
 *   (`pnpm --filter run publish` filters the package named `run` and then really
 *   publishes), and the parser has already consumed that value, so the slot
 *   holds `publish` and the publish must fire. A scan of the raw argv read the
 *   option value as a runner and allowed a real publish — the B3/B4 finding this
 *   positional reading closes.
 */
function classifyPublish(seg: Segment, command: string): Verdict | undefined {
  const verb = baseName(seg.verb)
  if (verb === undefined || !PACKAGE_MANAGERS.has(verb)) return undefined
  const argv = seg.argv
  const subIndex = seg.subcommand === undefined ? -1 : argv.indexOf(seg.subcommand, 1)
  // Only a runner in the subcommand SLOT makes `publish` a script/package name.
  // Reading the slot (not the words before `publish`) is what keeps a flag
  // between the two (`npm run --silent publish`) suppressed as well.
  const runnerIsSubcommand = subIndex >= 0 && SCRIPT_RUNNER_VERBS.has(argv[subIndex])
  const isPublishVerb = argv.some((word, i) => {
    if (i < 1 || word !== 'publish') return false
    if (subIndex >= 0 && i < subIndex) return false
    return !runnerIsSubcommand
  })
  if (!isPublishVerb) return undefined
  const dryRun = seg.flags.some(
    (f) => f === '--dry-run' || f === '--dryRun' || f.startsWith('--dry-run=') || f.startsWith('--dryRun='),
  )
  return { ruleId: 'pkg.publish', tier: dryRun ? 'journal' : 'ask', target: command }
}

/** True when the token names the local `curl`/`wget` binary (a URL is not a fetcher). */
function isNetworkFetcher(token: string): boolean {
  if (token.includes('://')) return false
  const base = baseName(token)
  return base === 'curl' || base === 'wget'
}

/**
 * `curl … | bash` / `wget … | sh` (the pipe token stays on the fetcher's own
 * segment) and `source <(curl …)` / `bash <(curl …)` (the process substitution
 * is one segment, so its `<` and `(curl` tokens are both visible).
 */
function isRemoteExecPair(segs: Segment[], i: number): boolean {
  const seg = segs[i]
  if (seg.argv.includes('|') && seg.argv.some(isNetworkFetcher)) {
    const next = segs[i + 1]
    if (next !== undefined && shellName(next.verb) !== undefined) return true
  }
  const consumer = baseName(seg.verb)
  const shellConsumer = shellName(seg.verb) !== undefined || (consumer !== undefined && SOURCE_VERBS.has(consumer))
  return (
    shellConsumer &&
    seg.argv.includes('<') &&
    seg.argv.some((t) => t.startsWith('(curl') || t.startsWith('(wget'))
  )
}

/**
 * The verdict for a segment the parser could not resolve: `ask` for the rule its
 * `rawSurface` names, `undefined` when it names none. This is the §5.3
 * escalation, scoped so that an unresolved wrapper around a harmless command
 * stays quiet.
 */
function ambiguousVerdict(seg: Segment, command: string): Verdict | undefined {
  const raw = rawSurface(seg)
  if (RAW_GH_PR_MERGE.test(raw)) return { ruleId: 'git.merge.protected', tier: 'ask', target: command }
  if (RAW_PUBLISH.test(raw)) return { ruleId: 'pkg.publish', tier: 'ask', target: command }
  if (RAW_GIT_PUSH.test(raw)) {
    if (RAW_RELEASE_TAG.test(raw)) return { ruleId: 'git.tag.release', tier: 'ask', target: command }
    if (RAW_FORCE_PUSH.test(raw)) return { ruleId: 'git.push.force', tier: 'ask', target: command }
    return { ruleId: 'git.push.protected', tier: 'ask', target: command }
  }
  if (RAW_REMOTE_EXEC.test(raw)) return { ruleId: 'net.exec.remote', tier: 'ask', target: command }
  return undefined
}

const ALLOW = (target: string): Verdict => ({ ruleId: '', tier: 'allow', target })

/**
 * Every spelling of the guard's own paths: the absolute forms from config plus
 * their `~`/`$HOME`/`${HOME}` forms (`pathSpellings`). A command can reach a
 * guarded file through any of them, and the previous absolute-only test missed
 * exactly that.
 */
function guardPathMatchers(guardPaths: string[]): string[] {
  const out = new Set<string>()
  for (const p of guardPaths) {
    if (typeof p !== 'string' || p === '') continue
    for (const s of pathSpellings(p)) out.add(s)
  }
  return [...out]
}

/**
 * True when this parsed segment EDITS one of the guard's own paths.
 *
 * The deny tier is scoped to edits, not mentions: a raw-text match refused every
 * read (`tail -n 5 <journal>`, `cat <profile package.json>`) even though the
 * guard's own deny text tells the agent to "see the guard journal". Two mutation
 * shapes count:
 *
 * - a mutating verb ({@link MUTATION_VERBS}) — or an in-place editor
 *   ({@link IN_PLACE_EDITORS} with {@link IN_PLACE_FLAG}) — whose segment names
 *   a guard path;
 * - a redirection ({@link WRITE_REDIRECT}) whose TARGET is a guard path.
 *
 * Both read the segment's `argv`, where quotes are already gone and their
 * content kept, so a quoted path cannot hide a mutation — and where a quoted
 * MENTION (`git commit -m "rm -f <journal>"`) stays a single data token, so it
 * cannot fake one. The redirect pair is read from `argv` for the same reason: a
 * `>` inside a quoted message is not a redirection token.
 *
 * A recorded trade-off: an interpreter inline program (`python -c "open(p,'w')"`)
 * is NOT a mutation here. The guard does not interpret the program's language,
 * and the shape is lexically indistinguishable from the `node -e "… mention …"`
 * allow case. The deny tier therefore covers the mutation shapes the parser can
 * prove; see the module's `rawSurface` note for the same choice on shape rules.
 */
function mutatesGuardPath(seg: Segment, guardSpellings: string[]): boolean {
  const names = (text: string) => guardSpellings.some((p) => text.includes(p))
  const verb = baseName(seg.verb)
  const namesPath = seg.argv.some(names)
  if (namesPath && verb !== undefined && MUTATION_VERBS.has(verb)) return true
  if (namesPath && verb !== undefined && IN_PLACE_EDITORS.has(verb) && seg.flags.some((f) => IN_PLACE_FLAG.test(f))) {
    return true
  }
  return seg.argv.some((word, i) => WRITE_REDIRECT.test(word) && i + 1 < seg.argv.length && names(seg.argv[i + 1]))
}

/**
 * The `secret.access` decision for ONE parsed segment. Two tables decide it, and
 * both read the segment's own verb:
 *
 * - a MENTION verb (`grep`, `ls`, `printf`, `find`, …) only scans or prints its
 *   arguments, so a protected path in its argv is a mention, never an access;
 * - otherwise the segment's argv must hold BOTH an access verb and a protected
 *   path.
 *
 * The surface is `seg.argv`, never `stripQuoted(command)`. That text-based
 * surface was the 0.2.3 fail-open: it erased a QUOTED protected path before the
 * rule looked, so `cat <path>` asked while `cat "<path>"`, `cp "<path>" /tmp/x`,
 * `curl -T "<path>" …` and `cp /tmp/x "<path>"` were all allowed. The tokenizer
 * already removed the quotes and kept their content, so quoting cannot hide an
 * access from argv.
 *
 * A segment the parser could not resolve (`seg.ambiguous`: an interpreter inline
 * program, an unknown wrapper, an expansion) cannot be proven to be a mention,
 * so a protected path in its argv is an access on its own. That is the intended
 * fail-closed trade-off — `python3 -c "… '<path>' …"` asks again.
 *
 * `seg.heredoc` is never read: a heredoc body is data, not argv, so a body that
 * merely names a protected path stays quiet.
 */
function isAccess(seg: Segment, protectedPaths: string[]): boolean {
  const verb = baseName(seg.verb)
  if (verb !== undefined && MENTION_VERBS.has(verb)) return false
  const argvSurface = seg.argv.join(' ')
  if (!isBlockedPath(argvSurface, protectedPaths)) return false
  return seg.ambiguous || ACCESS_VERBS.test(argvSurface)
}

/**
 * Classify one tool call into a rule id + default tier.
 *
 * Precision rule: only a real ACCESS is gated. A shell command is judged on its
 * parsed segments' argv (a mention-only verb is never an access, and a heredoc
 * body is data); a non-shell tool is judged on the path it targets, never on its
 * content — a document that *discusses* a protected path, or a write that happens
 * to contain secret-looking text, is not an access.
 *
 * `guard.tamper` is the deliberate exception on one count: it is the only deny
 * rule and the spec treats deny as unappealable self-protection. It therefore
 * judges the segment that EDITS a guard path, not only the resolved rule shapes
 * — but it is still scoped to an edit (a mutating verb or a write redirection
 * targeting a guard path), never to a bare mention. A read of the journal must
 * fall through, because the guard's own deny text says "see the guard journal".
 */
export function classify(ctx: ClassifyContext): Verdict {
  const { tool, args, cwd, settings } = ctx
  const command = extractCommandText(args)
  const path = extractPathField(args)
  const target = command ?? path ?? tool
  const guardSpellings = guardPathMatchers(settings.guardPaths)
  const touchesGuardConfig = (text: string) => guardSpellings.some((p) => text.includes(p))
  // Parsed once and shared: the tamper check and the rule loop judge the same
  // segments, wrappers already removed.
  const segs = command !== undefined ? unwrapSegments(parseCommand(command)) : []

  // guard.tamper — highest priority, never approvable, scoped to EDITS (above).
  if (WRITE_FILE_TOOLS.has(tool) && path && touchesGuardConfig(path)) {
    return { ruleId: 'guard.tamper', tier: 'deny', target, detail: { reason: 'guard configuration write' } }
  }
  if (segs.some((seg) => mutatesGuardPath(seg, guardSpellings))) {
    return { ruleId: 'guard.tamper', tier: 'deny', target, detail: { reason: 'guard configuration access' } }
  }

  if (FILE_TOOLS.has(tool)) {
    if (path && isBlockedPath(path, settings.protectedPaths)) {
      return { ruleId: 'secret.access', tier: 'ask', target: path }
    }
    if (WRITE_FILE_TOOLS.has(tool) && path && cwd && settings.workingDirContainment?.enabled !== false
      && isOutsideCwd(path, cwd) && !isExemptWritePath(path, cwd, settings.workingDirContainment)) {
      return { ruleId: 'fs.write.outside', tier: 'ask', target: path }
    }
    // Tool content is never scanned — an analysis/write call is not an access.
    return ALLOW(target)
  }

  if (command) {
    // Protected operations are resolved from parsed segments, never from a
    // regex over the raw text: the parser sees past value-taking global options
    // (`git -C <dir> push …`, `npm -w <name> publish`) and wrappers
    // (`bash -c …`), which is where the raw matchers lost them.
    // secret.access is checked over every segment BEFORE the rule loop, so an
    // access verdict keeps outranking an ordinary rule match on the same
    // command (its historical precedence).
    for (const seg of segs) {
      if (isAccess(seg, settings.protectedPaths)) {
        return { ruleId: 'secret.access', tier: 'ask', target: command }
      }
    }
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i]
      // Ambiguity escalates first: a segment the parser could not resolve is
      // asked about whenever its own raw text names a verb the rules resolve.
      if (seg.ambiguous) {
        const escalated = ambiguousVerdict(seg, command)
        if (escalated) return escalated
      }
      if (isRemoteExecPair(segs, i)) {
        return { ruleId: 'net.exec.remote', tier: 'ask', target: command }
      }
      if (isGhPrMerge(seg)) {
        return { ruleId: 'git.merge.protected', tier: 'journal', target: command }
      }
      if (namesGhStatement(seg, RAW_GH_RELEASE)) {
        return { ruleId: 'gh.release.create', tier: 'ask', target: command }
      }
      if (deletesProtectedBranchProtection(seg, settings.protectedBranches)) {
        return { ruleId: 'gh.protection.delete', tier: 'ask', target: command }
      }
      if (baseName(seg.verb) === 'git' && isPushSegment(seg)) {
        const push = classifyPush(seg, command, ctx, cwd)
        if (push) return push
        // An ambiguous segment cannot be proven to push a safe refspec, so it
        // is answered like an unprovable branch: ask, never allow.
        if (seg.ambiguous) return { ruleId: 'git.push.protected', tier: 'ask', target: command }
      }
      const publish = classifyPublish(seg, command)
      if (publish) return publish
    }
  }

  return ALLOW(target)
}
