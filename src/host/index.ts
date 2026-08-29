import { execSync } from 'node:child_process'
import type { Context } from '@deepseek-ai/cordis'
import { ApprovalStore } from './approval-store.js'
import { PermissionPolicy } from './permission-policy.js'
import { containsSecret, redact } from './secret-redactor.js'
import { checkSandbox, isBlockedGitCommand } from './sandbox.js'
import { apply as applyFullScan } from './full-scan-tool.js'
import type { GuardToolExecution, GuardPreToolDecision } from './augment.js'

function getCurrentBranch(cwd?: string): string | undefined {
  if (!cwd) return undefined
  try {
    return execSync('git branch --show-current', { cwd, timeout: 800, encoding: 'utf-8' }).trim() || undefined
  } catch {
    return undefined
  }
}

function getSessionCwd(exec: unknown): string | undefined {
  const e: any = exec as any
  return (
    e?.agent?.session?.header?.cwd ??
    e?.session?.header?.cwd ??
    e?.header?.cwd ??
    e?.cwd ??
    undefined
  )
}

export function createGuardHandler(store: ApprovalStore, policy: PermissionPolicy) {
  return async (exec: GuardToolExecution, next: () => Promise<GuardPreToolDecision>): Promise<GuardPreToolDecision> => {
    const tool = (exec as GuardToolExecution).name ?? (exec as GuardToolExecution).tool ?? ''
    const rawArgs = (exec as any)?.args ?? (exec as any)?.arguments

    // Sandbox hard gate: credential paths, ~/.cloudflared, NPM_TOKEN, git-protection, publish, cwd (via checkSandbox)
    const cwd = getSessionCwd(exec)
    const currentBranch = cwd ? getCurrentBranch(cwd) : undefined
    const asTextForSandbox = rawArgs != null ? JSON.stringify(rawArgs) : ''
    const combinedForCheck = `${tool} ${asTextForSandbox}`
    const combinedForPublish = combinedForCheck
    const isPublish = /\b(pnpm|npm)\s+publish\b/.test(combinedForPublish)
    let approvedForPublish = false
    if (isPublish) {
      approvedForPublish =
        (await store.isApproved('publish')) ||
        (await store.isApproved('pnpm-publish')) ||
        (await store.isApproved('pnpm publish')) ||
        (await store.isApproved(tool))
    }
    const isGitProtected = isBlockedGitCommand(combinedForCheck, currentBranch)
    let approvedForGit = false
    if (isGitProtected) {
      approvedForGit =
        (await store.isApproved('git-protection')) ||
        (await store.isApproved('publish')) ||
        (await store.isApproved(tool))
    }
    const sandboxRes = checkSandbox(tool, rawArgs, {
      cwd,
      currentBranch,
      approved: isGitProtected ? approvedForGit : approvedForPublish,
    })
    if (sandboxRes.blocked) {
      throw new Error(`Guard: ${sandboxRes.reason}`)
    }

    if (!policy.isAllowed(tool, rawArgs)) {
      throw new Error(`Guard: tool ${tool} denied by policy`)
    }
    if (tool === 'danger-tool' && !(await store.isApproved(tool))) {
      throw new Error(`Guard: tool ${tool} requires approval`)
    }
    if (rawArgs != null) {
      const asText = JSON.stringify(rawArgs)
      if (containsSecret(asText)) {
        const redacted = JSON.parse(redact(asText))
        if ('args' in exec) (exec as any).args = redacted
        if ('arguments' in exec) (exec as any).arguments = redacted
      }
    }
    return next()
  }
}

export default {
  inject: ['tools'] as const,
  apply(ctx: Context) {
    const store = new ApprovalStore()
    const policy = new PermissionPolicy({ deny: ['danger-tool'] })
    const handler = createGuardHandler(store, policy)
    ctx.effect(() => ctx.on('tools/pre-execute', handler as any))
    // register on-demand full-scan tool (Task 4) alongside guard handler
    applyFullScan(ctx, {})
  }
}
