import { homedir } from 'node:os'
import { join, resolve, normalize } from 'node:path'

function expandHome(p: string): string {
  if (!p) return p
  if (p === '~') return homedir()
  if (p.startsWith('~/')) return join(homedir(), p.slice(2))
  if (p.startsWith('$HOME/')) return join(homedir(), p.slice(6))
  if (p.startsWith('${HOME}/')) return join(homedir(), p.slice(8))
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
 * True if path points to a blocked credential / secret location.
 * Covers: ~/.dsh/.credentials.yaml (any expansion), ~/.cloudflared, NPM_TOKEN, .credentials.yaml substring
 * credentialPaths: additional custom paths from config (guard.credentialPaths) — merged with always-blocked defaults.
 * The 3 always-blocked substrings stay blocked even when credentialPaths is empty.
 */
export function isBlockedPath(input: string, credentialPaths?: string[]): boolean {
  if (!input || typeof input !== 'string') return false
  const trimmed = input.trim()
  if (!trimmed) return false

  // Direct substring checks (covers JSON-stringified args, env leakage, etc.) — always blocked
  if (trimmed.includes('.credentials.yaml')) return true
  if (trimmed.includes('.cloudflared')) return true
  if (trimmed.includes('NPM_TOKEN')) return true
  if (trimmed.includes('.dsh') && trimmed.includes('credentials')) return true

  // Normalized expanded check for defaults
  const norm = normalizePath(trimmed)
  if (norm.includes('.credentials.yaml')) return true
  if (norm.includes('.cloudflared')) return true
  // Check absolute homedir variant
  const absCred = join(homedir(), '.dsh', '.credentials.yaml')
  if (norm === absCred || norm.startsWith(absCred)) return true
  const absCf = join(homedir(), '.cloudflared')
  if (norm === absCf || norm.startsWith(absCf + '/') || norm.includes('.cloudflared')) return true

  // Injected credentialPaths from config (additional) — substring + normalized + prefix
  if (credentialPaths && credentialPaths.length > 0) {
    for (const p of credentialPaths) {
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
 * True if command string is a publish command (pnpm|npm publish)
 */
/**
 * Resolve the working directory a command actually executes in, when it names
 * one explicitly (cd <dir> / git -C <dir>). Falls back to the passed cwd when
 * the command has no explicit target — preserving the historical session-cwd
 * semantics for commands that run in place.
 */
export function getCommandWorkingDir(command: string | undefined, cwd: string | undefined): string | undefined {
  if (!command || !cwd) return cwd ?? undefined
  const cd = /\bcd\s+([^\s;&|"'`${}]+)(?:\s*(?:[;&|]|$))/.exec(command)
  const c = /\bgit\s+-C\s+([^\s;&|"'`${}]+)/.exec(command)
  const dir = cd?.[1] ?? c?.[1]
  if (!dir) return cwd
  if (dir === '~') return homedir()
  if (dir.startsWith('~/')) return join(homedir(), dir.slice(2))
  return resolve(cwd, dir)
}

/**
 * Choose the branch used for protected-branch detection: the branch of the repo
 * the command targets (via `getCommandWorkingDir`), falling back to the session
 * cwd when the command runs in place. If the command cd's into a directory that
 * is not a git repo, no protected branch applies (the push would fail there
 * anyway) — do NOT fall back to the session cwd, that reintroduces the
 * false-positive where a feature-branch push inside a sub-repo is blocked
 * because the session cwd repo happens to sit on master.
 */
export function resolveCurrentBranch(
  command: string | undefined,
  sessionCwd: string | undefined,
  branchOf: (dir: string) => string | undefined,
): string | undefined {
  const dir = getCommandWorkingDir(command, sessionCwd)
  if (!dir) return undefined
  return branchOf(dir)
}

/**
 * The executed command surface of a tool call. Shell-style tools carry their
 * script in `args.command` (bash/exec/shell/govard_shell); bare string args are
 * the command itself. Tools with no command field (read/write/memory/...) have
 * no execution surface, so protected-op detection must not apply to their
 * content — that was the source of the analysis-tool false positives.
 */
export function extractCommandText(args: unknown): string | undefined {
  if (args == null) return undefined
  if (typeof args === 'string') return args
  if (typeof args === 'object' && typeof (args as Record<string, unknown>).command === 'string') {
    return (args as Record<string, unknown>).command as string
  }
  return undefined
}

/** Collapse quoted spans — text inside quotes is data (echo/printf/script bodies), not argv. */
function stripQuoted(cmd: string): string {
  return cmd.replace(/"[^"]*"/g, ' ').replace(/'[^']*'/g, ' ')
}

export function isBlockedCommand(cmd: string): boolean {
  if (!cmd || typeof cmd !== 'string') return false
  // package-manager publish verbs as a whole-word sequence
  return /\b(pnpm|npm)\s+publish\b/.test(stripQuoted(cmd))
}

/**
 * True when the command executes a protected git operation. Detection is
 * per-command-segment (split on && / ; / | / newline) so a `gh pr create
 * --base master` mention after a feature push — or quoted text anywhere — does
 * not turn a safe push into a blocked one. Hard rules (gh pr merge, gh release,
 * protection deletion, protected branch words in the push segment, being
 * checked out on a protected branch) keep their unconditional coverage.
 */
export function isBlockedGitCommand(cmd: string, currentBranch?: string, branches?: string[]): boolean {
  if (!cmd || typeof cmd !== 'string') return false
  const effectiveBranches = branches && branches.length > 0 ? branches : ['master', 'main']
  const lowerBranches = effectiveBranches.map((b) => b.toLowerCase())
  const escBranch = (b: string) => b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const segments = cmd.split(/\s*(?:&&|\|\||;|\||\r?\n)+\s*/)
  for (const seg of segments) {
    const lower = stripQuoted(seg).toLowerCase()
    // hard rules are unconditional per segment
    if (/\bgh\s+pr\s+merge\b/.test(lower)) return true
    if (/\bgh\s+release\s+(create|publish)\b/.test(lower)) return true
    for (const b of lowerBranches) {
      const re = new RegExp(`gh\\s+api\\b.*delete.*\\/branches\\/${escBranch(b)}\\/protection`)
      if (re.test(lower)) return true
    }
    // git push: protected branch word in THIS segment, or checked out on one
    if (/\bgit\s+push\b/.test(lower)) {
      for (const b of lowerBranches) {
        if (new RegExp(`\\b${escBranch(b)}\\b`).test(lower)) return true
      }
      if (currentBranch) {
        const curLower = currentBranch.toLowerCase()
        if (lowerBranches.includes(curLower)) return true
      }
    }
  }
  // git tag push that includes protected branch (rare) — already covered by push regex
  return false
}

export function isPublishBlocked(cmd: string, approved: boolean): boolean {
  if (!isBlockedCommand(cmd)) return false
  return !approved
}

/**
 * True if target path is outside cwd (strict containment).
 * Uses resolve for absolute comparison; expanded ~/ handled.
 */
export function isOutsideCwd(target: string, cwd: string): boolean {
  if (!target || !cwd) return false
  const expTarget = expandHome(target)
  const expCwd = expandHome(cwd)
  const resolvedTarget = resolve(expTarget)
  const resolvedCwd = resolve(expCwd)
  if (resolvedTarget === resolvedCwd) return false
  // Ensure cwd prefix with separator to avoid /tmp/proj matching /tmp/proj2
  return !resolvedTarget.startsWith(resolvedCwd + '/')
}

export interface SandboxCheckResult {
  blocked: boolean
  reason?: string
}

export interface CheckSandboxOpts {
  cwd?: string
  currentBranch?: string
  approved?: boolean
  credentialPaths?: string[]
  gitProtection?: { enabled: boolean; branches: string[] }
  publishBlocked?: boolean
  cwdContainment?: boolean
}

/**
 * Central sandbox check. Combines credential-path, git-protection, publish, and cwd containment.
 * @param tool tool name (e.g. maestro_read_file, exec, bash)
 * @param args tool arguments (object, string, or unknown)
 * @param opts.cwd session cwd (exec.agent.session.header.cwd)
 * @param opts.currentBranch git current branch (from getCurrentBranch)
 * @param opts.approved whether publish/git is APPROVED (via ApprovalStore)
 * @param opts.credentialPaths additional blocked credential paths from guard config
 * @param opts.gitProtection git protection toggle + branches from guard config
 * @param opts.publishBlocked whether publish is blocked (default true)
 * @param opts.cwdContainment whether cwd containment is enforced (default true)
 */
export function checkSandbox(
  tool: string,
  args: unknown,
  opts?: CheckSandboxOpts,
): SandboxCheckResult {
  const approved = !!opts?.approved
  const cwd = opts?.cwd
  const currentBranch = opts?.currentBranch
  const credentialPaths = opts?.credentialPaths
  const gitProtection = opts?.gitProtection
  const publishBlocked = opts?.publishBlocked ?? true
  const cwdContainment = opts?.cwdContainment ?? true

  // Serialize args for generic substring checks
  const asText = args != null ? (typeof args === 'string' ? args : JSON.stringify(args)) : ''
  const combined = `${tool ?? ''} ${asText}`
  // Protected-op detection (git/publish) runs on the executed command surface
  // only — non-shell tools (write/read/memory/...) have no command and must not
  // be flagged for text that merely mentions a protected phrase.
  const execText = extractCommandText(args)

  // 1) Block credential paths anywhere in tool+args (always, with injected list)
  if (isBlockedPath(tool, credentialPaths) || isBlockedPath(asText, credentialPaths) || isBlockedPath(combined, credentialPaths)) {
    return { blocked: true, reason: 'credential path blocked: ~/.dsh/.credentials.yaml or ~/.cloudflared or NPM_TOKEN' }
  }

  // 2) Block git push to protected branches without APPROVED (branch-aware, toggle-aware)
  const gitEnabled = gitProtection?.enabled ?? true
  const branches = gitProtection?.branches ?? ['master', 'main']
  if (gitEnabled && execText && isBlockedGitCommand(execText, currentBranch, branches) && !approved) {
    return { blocked: true, reason: 'git push to master/main blocked without APPROVED: ' + execText.slice(0, 300) }
  }

  // 3) Block publish without APPROVED (toggle-aware)
  if (publishBlocked && execText && isBlockedCommand(execText) && !approved) {
    return { blocked: true, reason: 'publish blocked without APPROVED: pnpm publish requires approval' }
  }

  // 4) Block maestro file tools outside cwd (toggle-aware)
  const fileTools = new Set(['maestro_read_file', 'maestro_write_file', 'fs_read', 'fs_write', 'read_file', 'write_file'])
  if (cwdContainment && cwd && fileTools.has(tool)) {
    let pathVal: string | undefined
    if (typeof args === 'object' && args !== null) {
      const a = args as Record<string, unknown>
      // common keys
      pathVal = (a.path as string) ?? (a.file as string) ?? (a.file_path as string) ?? (a.filePath as string)
      // array-like args: {0: 'path'}
      if (!pathVal && typeof (a as any)[0] === 'string') pathVal = (a as any)[0] as string
      // if args itself has nested command with path
      if (!pathVal && typeof a.command === 'string') {
        // command may contain path; fallback to blocked path check already done, but also cwd check if command contains path
        // no explicit path to check
      }
    } else if (typeof args === 'string') {
      pathVal = args
    }
    if (pathVal) {
      if (isBlockedPath(pathVal, credentialPaths)) {
        return { blocked: true, reason: `credential path blocked: ${pathVal}` }
      }
      if (isOutsideCwd(pathVal, cwd)) {
        return { blocked: true, reason: `path outside cwd: ${pathVal} not in ${cwd}` }
      }
    }
  }

  // Also check generic exec/bash tool with cwd containment if it looks like a file path arg
  // (optional: not strictly required for credential/publish but supports broader sandbox)
  if (cwd && (tool === 'exec' || tool === 'bash' || tool === 'shell')) {
    // already covered publish; for credential path we already blocked above via substring
    // No additional cwd check for shell commands unless they are obvious file paths
  }

  return { blocked: false }
}

/**
 * Simple guard per task 5 snippet: guard(p) => false if blocked, true if allowed.
 * For publish, second arg approved indicates APPROVED.
 */
export function guard(p: string, approved?: boolean): boolean {
  if (!p || typeof p !== 'string') return true
  if (isBlockedPath(p)) return false
  if (isBlockedCommand(p) && !approved) return false
  return true
}

export const sandbox = { isBlockedPath, isBlockedCommand, isBlockedGitCommand, isPublishBlocked, isOutsideCwd, checkSandbox, guard }
