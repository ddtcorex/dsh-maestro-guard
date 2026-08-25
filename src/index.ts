// src/index.ts
import type { Context } from '@deepseek-ai/cordis'
import { ApprovalStore } from './approval-store.js'
import { PermissionPolicy } from './permission-policy.js'
import { redact } from './secret-redactor.js'

export default {
  inject: ['tools'] as const,
  apply(ctx: Context) {
    const store = new ApprovalStore()
    const policy = new PermissionPolicy({ deny: ['danger-tool'] })
    ctx.effect(() => (ctx as any).on('tools/pre-execute', async (payload: any, next: any) => {
      const tool = payload?.name ?? payload?.tool
      if (!policy.isAllowed(tool, payload?.args)) {
        throw new Error(`Guard: tool ${tool} denied by policy`)
      }
      if (tool === 'danger-tool' && !(await store.isApproved(tool))) {
        throw new Error(`Guard: tool ${tool} requires approval`)
      }
      if (payload?.args) {
        const asText = JSON.stringify(payload.args)
        if (asText.includes('glpat-') || asText.includes('sk-')) {
          payload.args = JSON.parse(redact(asText))
        }
      }
      return next()
    }))
  }
}
