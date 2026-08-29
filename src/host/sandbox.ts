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
 */
export function isBlockedPath(input: string): boolean {
  if (!input || typeof input !== 'string') return false
  const trimmed = input.trim()
  if (!trimmed) return false

  // Direct substring checks (covers JSON-stringified args, env leakage, etc.)
  if (trimmed.includes('.credentials.yaml')) return true
  if (trimmed.includes('.cloudflared')) return true
  if (trimmed.includes('NPM_TOKEN')) return true
  if (trimmed.includes('.dsh') && trimmed.includes('credentials')) return true

  // Normalized expanded check
  const norm = normalizePath(trimmed)
  if (norm.includes('.credentials.yaml')) return true
  if (norm.includes('.cloudflared')) return true
  // Check absolute homedir variant
  const absCred = join(homedir(), '.dsh', '.credentials.yaml')
  if (norm === absCred || norm.startsWith(absCred)) return true
  const absCf = join(homedir(), '.cloudflared')
  if (norm === absCf || norm.startsWith(absCf + '/') || norm.includes('.cloudflared')) return true

  return false
}

/**
 * True if command string is a publish command (pnpm|npm publish)
 */
export function isBlockedCommand(cmd: string): boolean {
  if (!cmd || typeof cmd !== 'string') return false
  // detect "pnpm publish" or "npm publish" as whole word sequence
  return /\b(pnpm|npm)\s+publish\b/.test(cmd)
}

export function isBlockedGitCommand(cmd: string, currentBranch?: string): boolean {
  if (!cmd || typeof cmd !== 'string') return false
  const lower = cmd.toLowerCase()
  // gh pr merge always protected
  if (/\bgh\s+pr\s+merge\b/.test(lower)) return true
  if (/\bgh\s+release\s+(create|publish)\b/.test(lower)) return true
  if (/gh\s+api\b.*delete.*\/branches\/(master|main)\/protection/.test(lower)) return true
  // git push with explicit master/main target
  if (/\bgit\s+push\b/.test(lower)) {
    if (/\b(master|main)\b/.test(lower)) return true
    if (currentBranch && (currentBranch === 'master' || currentBranch === 'main')) return true
  }
  // git tag push that includes master/main (rare) — already covered by push regex
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

/**
 * Central sandbox check. Combines credential-path, git-protection, publish, and cwd containment.
 * @param tool tool name (e.g. maestro_read_file, exec, bash)
 * @param args tool arguments (object, string, or unknown)
 * @param opts.cwd session cwd (exec.agent.session.header.cwd)
 * @param opts.currentBranch git current branch (from getCurrentBranch)
 * @param opts.approved whether publish/git is APPROVED (via ApprovalStore)
 */
export function checkSandbox(
  tool: string,
  args: unknown,
  opts?: { cwd?: string; currentBranch?: string; approved?: boolean },
): SandboxCheckResult {
  const approved = !!opts?.approved
  const cwd = opts?.cwd
  const currentBranch = opts?.currentBranch

  // Serialize args for generic substring checks
  const asText = args != null ? (typeof args === 'string' ? args : JSON.stringify(args)) : ''
  const combined = `${tool ?? ''} ${asText}`

  // 1) Block credential paths anywhere in tool+args
  if (isBlockedPath(tool) || isBlockedPath(asText) || isBlockedPath(combined)) {
    return { blocked: true, reason: 'credential path blocked: ~/.dsh/.credentials.yaml or ~/.cloudflared or NPM_TOKEN' }
  }

  // 2) Block git push to master/main without APPROVED (branch-aware)
  if (isBlockedGitCommand(combined, currentBranch) && !approved) {
    return { blocked: true, reason: 'git push to master/main blocked without APPROVED: ' + combined.slice(0, 300) }
  }

  // 3) Block publish without APPROVED
  if (isBlockedCommand(combined) && !approved) {
    return { blocked: true, reason: 'publish blocked without APPROVED: pnpm publish requires approval' }
  }

  // 4) Block maestro file tools outside cwd
  const fileTools = new Set(['maestro_read_file', 'maestro_write_file', 'fs_read', 'fs_write', 'read_file', 'write_file'])
  if (cwd && fileTools.has(tool)) {
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
      if (isBlockedPath(pathVal)) {
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
