import type { Tier } from './tiers.js'
import {
  isBlockedPath,
  isBlockedCommand,
  isBlockedGitCommand,
  isOutsideCwd,
  isRuntimeSpillPath,
  isWithinTempDir,
  extractCommandText,
  extractPathField,
  getCommandWorkingDir,
  stripQuoted,
  stripHeredocs,
} from './sandbox.js'

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
  'pkg.publish': 'ask',
  'secret.access': 'ask',
  'fs.write.outside': 'ask',
  'net.exec.remote': 'ask',
  'guard.tamper': 'deny',
}

export interface RuleSettings {
  protectedBranches: string[]
  protectedPaths: string[]
  guardPaths: string[]
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
/**
 * `fs.write.outside` covers the whole write family — the DSH-native `write` and
 * `edit` tools as well as the legacy Maestro writers. Scoping the rule to the
 * legacy names alone is what made the original cwd containment inert: the tools
 * actually in use (`read`/`write`/`edit`) were never matched. The OS temp dir is
 * exempt (`isWithinTempDir`) so scratch work stays frictionless; the runtime
 * spill dir is a subdirectory of it and keeps its explicit exemption. The temp
 * exemption is resolved against the SAME base as the containment test — the
 * session cwd — so the two can never disagree about a relative target.
 */
/** Verbs that actually touch file contents — a protected path next to one is an access. */
const ACCESS_VERBS = /\b(cat|bat|head|tail|less|more|cp|scp|rsync|curl|wget|source|tee|dd|install|xxd|base64|openssl|gpg|tar|zip)\b/
/** Verbs that only scan/print the argument itself — mentioning a path is not reading it. */
const MENTION_VERBS = /^\s*(grep|egrep|fgrep|rg|sed|awk|echo|printf|find|ls|test|wc|sort|uniq|jq)\b/
const REMOTE_EXEC = /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(source|\.)\s*<\(\s*curl\b|\b(ba|z|da)?sh\s*<\(\s*curl\b/
const FORCE_PUSH = /\bgit\s+push\b[^\n]*(--force(-with-lease)?\b|(^|\s)-f\b|\s\+[A-Za-z0-9._\/-]+:)/
const RELEASE_TAG = /refs\/tags\/|\bgit\s+tag\b|(?:^|\s)v?\d+\.\d+\.\d+(?:[-+][0-9a-z.]+)?(?:\s|$)/

const ALLOW = (target: string): Verdict => ({ ruleId: '', tier: 'allow', target })

/**
 * The executed command with quoted spans and heredoc bodies removed.
 * Access detection must run on this surface only: text quoted or piped into a
 * program as data is a mention, not an access. Reuses the single
 * `stripQuoted`/`stripHeredocs` implementations from `sandbox.ts` so the guard
 * has exactly one definition of "what the command actually executes".
 */
function accessSurface(command: string): string {
  return stripHeredocs(stripQuoted(command))
}

/**
 * Classify one tool call into a rule id + default tier.
 *
 * Precision rule: only a real ACCESS is gated. A shell command is judged on the
 * command surface (quotes/heredocs stripped, mention-only verbs skipped); a
 * non-shell tool is judged on the path it targets, never on its content — a
 * document that *discusses* a protected path, or a write that happens to
 * contain secret-looking text, is not an access.
 *
 * `guard.tamper` is the deliberate exception on both counts. It is the only
 * deny rule and the spec treats deny as unappealable self-protection, so there
 * coverage beats precision (fail-closed): it scans the RAW command text, not
 * the stripped surface. Reading the stripped surface would let the cheapest
 * obfuscation (`python -c "open('<guard path>','w')"`, or a heredoc body that
 * rewrites the settings file) erase the evidence, because quoted spans and
 * heredoc bodies are exactly what stripping removes. The raw scan is confined
 * to the command text and the tool's path field — a non-shell tool's content is
 * still never scanned.
 */
export function classify(ctx: ClassifyContext): Verdict {
  const { tool, args, cwd, settings } = ctx
  const command = extractCommandText(args)
  const path = extractPathField(args)
  const target = command ?? path ?? tool
  const surface = command ? accessSurface(command) : (path ?? '')
  const touchesGuardConfig = (text: string) => settings.guardPaths.some((p) => p && text.includes(p))

  // guard.tamper — highest priority, never approvable, RAW text (see above).
  if (WRITE_FILE_TOOLS.has(tool) && path && touchesGuardConfig(path)) {
    return { ruleId: 'guard.tamper', tier: 'deny', target, detail: { reason: 'guard configuration write' } }
  }
  if (command && touchesGuardConfig(command)) {
    return { ruleId: 'guard.tamper', tier: 'deny', target, detail: { reason: 'guard configuration access' } }
  }

  if (FILE_TOOLS.has(tool)) {
    if (path && isBlockedPath(path, settings.protectedPaths)) {
      return { ruleId: 'secret.access', tier: 'ask', target: path }
    }
    if (WRITE_FILE_TOOLS.has(tool) && path && cwd && isOutsideCwd(path, cwd) && !isWithinTempDir(path, cwd) && !isRuntimeSpillPath(path)) {
      return { ruleId: 'fs.write.outside', tier: 'ask', target: path }
    }
    // Tool content is never scanned — an analysis/write call is not an access.
    return ALLOW(target)
  }

  if (command) {
    const segments = surface.split(/\s*(?:&&|\|\||;|\n)+\s*/)
    for (const seg of segments) {
      if (MENTION_VERBS.test(seg)) continue
      if (isBlockedPath(seg, settings.protectedPaths) && ACCESS_VERBS.test(seg)) {
        return { ruleId: 'secret.access', tier: 'ask', target: command }
      }
    }
    if (REMOTE_EXEC.test(surface)) return { ruleId: 'net.exec.remote', tier: 'ask', target: command }
    if (FORCE_PUSH.test(surface)) return { ruleId: 'git.push.force', tier: 'ask', target: command }
    if (/\bgit\s+push\b/.test(surface) && RELEASE_TAG.test(surface)) {
      return { ruleId: 'git.tag.release', tier: 'ask', target: command }
    }
    if (/\bgh\s+pr\s+merge\b/.test(surface)) return { ruleId: 'git.merge.protected', tier: 'journal', target: command }
    if (isBlockedCommand(command)) return { ruleId: 'pkg.publish', tier: 'ask', target: command }
    const repo = getCommandWorkingDir(command, cwd)
    const branch = ctx.branchOf?.(repo ?? '')
    if (isBlockedGitCommand(command, branch, settings.protectedBranches)) {
      return { ruleId: 'git.push.protected', tier: 'ask', target: command, repo, branch }
    }
  }

  return ALLOW(target)
}
