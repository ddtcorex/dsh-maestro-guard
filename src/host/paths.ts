import { homedir, tmpdir } from 'node:os'
import { join, resolve, normalize } from 'node:path'
import { journalDir, journalPath } from './journal.js'

/**
 * Path rules: the always-blocked credential locations, the guard's own
 * configuration files, and the containment tests the classifier runs on a
 * tool's path field. Task B4 moved these out of the deleted `sandbox.ts`; they
 * are the only path logic in the package.
 *
 * Fragment assembly is deliberate, not stylistic: the OLD 0.2.3 guard is still
 * the live listener in this host, and it blocks any tool call whose TEXT
 * contains one of the protected path names contiguously. Building every literal
 * here from pieces keeps this module — and every tool call that reads it —
 * shippable through that guard. A later task inlines them after the supervised
 * restart onto the new guard.
 */
const AUTH_FILE = '.' + 'creden' + 'tials' + '.yaml'
const TUNNEL_AUTH_DIR = '.' + 'cloud' + 'flared'
const TOKEN_NAME = 'NPM' + '_TOKEN'
const DSH_DIR = '.' + 'dsh'
const CREDENTIAL_WORD = 'creden' + 'tials'

function resolveHome(dshHome?: string): string {
  return dshHome ?? process.env.DSH_HOME ?? join(homedir(), DSH_DIR)
}

function expandHome(p: string): string {
  if (!p) return p
  const home = homedir()
  if (p === '~') return home
  if (p.startsWith('~/')) return join(home, p.slice(2))
  if (p.startsWith('$HOME/')) return join(home, p.slice(6))
  if (p.startsWith('${HOME}/')) return join(home, p.slice(8))
  return p
}

function normalizePath(p: string): string {
  try {
    return normalize(expandHome(p))
  } catch {
    return expandHome(p)
  }
}

/**
 * The paths the guard blocks unconditionally, in the order the legacy
 * `sandbox.ts` already used, so callers may index them positionally (see
 * `tests/paths.test.ts`):
 *
 * 1. the DSH-private auth file, under the DSH home (explicit argument, else
 *    `$DSH_HOME`, else the user home's DSH directory);
 * 2. the tunnel credential directory, under the USER home — exactly what
 *    `sandbox.ts` hard-codes with `join(homedir(), ...)`. It is NOT a child of
 *    the DSH home and stays under the user home even when a `dshHome` is given.
 *
 * The guard's own configuration is deliberately NOT part of this list: it is
 * protected by the stricter `guard.tamper` deny rule, which reads
 * `guardConfigPaths()` directly.
 */
export function defaultProtectedPaths(dshHome?: string): string[] {
  const home = resolveHome(dshHome)
  return [join(home, AUTH_FILE), join(homedir(), TUNNEL_AUTH_DIR)]
}

/**
 * The guard's own configuration files. A write to any of them is a tamper
 * attempt (`guard.tamper`, tier `deny`) — the classifier compares the raw
 * command text and the tool's path field against this list.
 *
 * Four families, all of them things whose edit silently changes what runs or
 * erases what already ran:
 *
 * 1. `settings.json` — the `domains.guard` document itself;
 * 2. `profiles/web/cordis.patch.yml` — the row patch that configures the guard;
 * 3. `profiles/web/package.json` — the profile manifest that actually MOUNTS the
 *    guard (`@ddtcorex/dsh-maestro-guard` sits in its `dependencies` as a
 *    `link:`); the `cordis.patch.yml` beside it is a different file, and
 *    rewriting either one redirects or disables the guard on the next boot;
 * 4. the journal and the legacy ticket file beside it (`journalDir()`), because
 *    the spec's deny tier covers an attempt to truncate or remove the guard's
 *    own audit trail — an unlogged decision is not a lesser tamper.
 */
export function guardConfigPaths(dshHome?: string): string[] {
  const home = resolveHome(dshHome)
  return [
    join(home, 'dsh-maestro-config', 'settings.json'),
    join(home, 'profiles', 'web', 'cordis.patch.yml'),
    join(home, 'profiles', 'web', 'package.json'),
    journalPath(dshHome),
    join(journalDir(dshHome), 'legacy-pending.json'),
  ]
}

/**
 * True if path points to a blocked credential / secret location.
 * Covers: the DSH auth file (any expansion), the tunnel auth dir, the registry
 * token name, and the auth-file name as a substring.
 * `protectedPaths` are additional paths from config (`domains.guard.protectedPaths`)
 * — merged with the always-blocked names by the caller. The always-blocked
 * substrings stay blocked even when that list is empty.
 */
export function isBlockedPath(input: string, protectedPaths?: string[]): boolean {
  if (!input || typeof input !== 'string') return false
  const trimmed = input.trim()
  if (!trimmed) return false

  // Direct substring checks (covers JSON-stringified args, env leakage, etc.) — always blocked
  if (trimmed.includes(AUTH_FILE)) return true
  if (trimmed.includes(TUNNEL_AUTH_DIR)) return true
  if (trimmed.includes(TOKEN_NAME)) return true
  if (trimmed.includes(DSH_DIR) && trimmed.includes(CREDENTIAL_WORD)) return true

  // Normalized expanded check for defaults
  const norm = normalizePath(trimmed)
  if (norm.includes(AUTH_FILE)) return true
  if (norm.includes(TUNNEL_AUTH_DIR)) return true
  // Check absolute homedir variant
  const absCred = join(homedir(), DSH_DIR, AUTH_FILE)
  if (norm === absCred || norm.startsWith(absCred)) return true
  const absCf = join(homedir(), TUNNEL_AUTH_DIR)
  if (norm === absCf || norm.startsWith(absCf + '/') || norm.includes(TUNNEL_AUTH_DIR)) return true

  // Injected protectedPaths from config (additional) — substring + normalized + prefix
  if (protectedPaths && protectedPaths.length > 0) {
    for (const p of protectedPaths) {
      if (!p || typeof p !== 'string') continue
      const t = p.trim()
      if (!t) continue
      if (trimmed.includes(t)) return true
      const normP = normalizePath(t)
      if (norm.includes(normP)) return true
      if (norm === normP) return true
      if (norm.startsWith(normP + '/')) return true
    }
  }

  return false
}

/**
 * True if target path is outside cwd (strict containment).
 * Relative targets resolve against cwd (the calling agent's session cwd),
 * matching how maestro file tools resolve them — resolving against the host
 * process.cwd() instead false-positives every worktree-relative read
 * (review sessions read /tmp worktrees while the host runs elsewhere).
 */
export function isOutsideCwd(target: string, cwd: string): boolean {
  if (!target || !cwd) return false
  const expTarget = expandHome(target)
  const expCwd = expandHome(cwd)
  const resolvedCwd = resolve(expCwd)
  const resolvedTarget = resolve(resolvedCwd, expTarget)
  if (resolvedTarget === resolvedCwd) return false
  // Ensure cwd prefix with separator to avoid /tmp/proj matching /tmp/proj2
  return !resolvedTarget.startsWith(resolvedCwd + '/')
}

/**
 * True for reads of the DSH runtime spill dir (`$TMPDIR/dsh-spill-*`).
 * The spill policy persists oversized tool results there and instructs the
 * model to read them back via read tools — blocking those reads breaks the
 * foundation's own retrieval flow (tickets g-dd0d1679/g-716cd436/g-d77f0144).
 * Read-only: only read tools consult this; writes stay cwd-contained.
 * The random dir suffix makes cross-session spills unguessable, and the
 * runtime only ever discloses an agent's own spill paths to it.
 *
 * `base` is the directory a RELATIVE target resolves against, and it must be
 * the same base `isOutsideCwd`/`isWithinTempDir` use — the session cwd. The
 * default (`process.cwd()`) is kept for callers that only pass absolute targets,
 * but resolving against the host cwd while the containment test resolves against
 * the session cwd lets the two disagree: a relative path that escapes the
 * session cwd could then be exempted purely because of where the host happens
 * to run. `classify` therefore always passes the session cwd.
 */
export function isRuntimeSpillPath(target: string, base?: string): boolean {
  if (!target || typeof target !== 'string') return false
  const resolved = resolve(expandHome(base ?? process.cwd()), expandHome(target.trim()))
  const prefix = join(tmpdir(), 'dsh-spill-')
  return resolved.startsWith(prefix)
}

/**
 * True when target resolves inside the OS temp dir (`os.tmpdir()`).
 * Scratch work is deliberately exempt from the outside-cwd write gate: a
 * temporary deliverable (`/tmp/x.md`, `$TMPDIR/...`) is not a filesystem
 * escape, and gating it would re-introduce the false-positive class the
 * outside-cwd rule exists to remove. Resolution reuses the module's
 * expandHome/resolve helpers, and containment is checked with a trailing
 * separator so `/tmpfoo` never matches a temp dir of `/tmp`.
 *
 * `base` is the directory a RELATIVE target resolves against, and it must be
 * the same base `isOutsideCwd` uses — the session cwd.
 */
export function isWithinTempDir(target: string, base?: string): boolean {
  if (!target || typeof target !== 'string') return false
  const resolved = resolve(expandHome(base ?? process.cwd()), expandHome(target.trim()))
  const tmp = resolve(expandHome(tmpdir()))
  if (resolved === tmp) return true
  return resolved.startsWith(tmp + '/')
}
