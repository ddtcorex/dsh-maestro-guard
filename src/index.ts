// src/index.ts
import type { Context } from '@deepseek-ai/cordis'
import { ApprovalStore } from './approval-store.js'
import { PermissionPolicy } from './permission-policy.js'
import { containsSecret, redact } from './secret-redactor.js'
import type { GuardToolExecution, GuardPreToolDecision } from './augment.js'

export function createGuardHandler(store: ApprovalStore, policy: PermissionPolicy) {
  return async (exec: GuardToolExecution, next: () => Promise<GuardPreToolDecision>): Promise<GuardPreToolDecision> => {
    const tool = (exec as GuardToolExecution).name ?? (exec as GuardToolExecution).tool ?? ''
    const rawArgs = (exec as any)?.args ?? (exec as any)?.arguments
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
    ctx.effect(() => ctx.on('tools/pre-execute', handler))
  }
}
