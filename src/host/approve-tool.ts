import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { PendingRequest, PendingStore } from './pending.js'

export const name = 'maestro-guard-approve-tools'
export const inject = ['tools'] as const

export interface ApproveResult { ok: boolean; requestId: string; scope: string; status: string; message?: string }
export interface ListResult { ok: true; requests: PendingRequest[] }

export function createApproveTools(deps: { pending: PendingStore }) {
  return {
    async approve(requestId: string): Promise<ApproveResult> {
      if (typeof requestId !== 'string' || requestId.length === 0) {
        return { ok: false, requestId: '', scope: '', status: 'error', message: 'requestId (string) is required' }
      }
      const req = await deps.pending.approve(requestId)
      if (!req) {
        return { ok: false, requestId, scope: '', status: 'error', message: `no pending request with id ${requestId}` }
      }
      return { ok: true, requestId: req.id, scope: req.scope, status: req.status }
    },
    async list(): Promise<ListResult> {
      return { ok: true, requests: await deps.pending.list() }
    },
  }
}

export function applyApproveTools(ctx: Context, deps: { pending: PendingStore }): void {
  const tools = createApproveTools(deps)
  ctx.effect(() => ctx.tools.register(defineTool({
    name: 'maestro_guard_approve',
    description: 'Approve one recorded guard request so its exact blocked operation may run once. Call after the human approves the operation in the conversation.',
    parameters: { requestId: { type: 'string', description: 'the request id from the guard block message or maestro_guard_list' } },
    output: {
      schema: {
        type: 'object', additionalProperties: true,
        properties: { ok: { type: 'boolean', required: true }, requestId: { type: 'string', required: true }, scope: { type: 'string', required: true }, status: { type: 'string', required: true }, message: { type: 'string' } },
      },
      render: (_a: unknown, v: any) => [{ type: 'text', text: v.ok ? `approved request ${v.requestId} (scope ${v.scope})` : `approve failed: ${v.message ?? v.status}` }],
    },
    async execute(args: any) {
      return tools.approve((args as any)?.requestId) as any
    },
  })))
  ctx.effect(() => ctx.tools.register(defineTool({
    name: 'maestro_guard_list',
    description: 'List guard tickets (pending/approved/consumed) with redacted commands. Read-only.',
    parameters: {},
    output: {
      schema: {
        type: 'object', additionalProperties: true,
        properties: { ok: { type: 'boolean', required: true }, requests: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } } },
      },
      render: (_a: unknown, v: any) => [{ type: 'text', text: (v.requests ?? []).map((r: any) => `${r.status} ${r.id} ${r.scope} @${r.requestedAt} ${String(r.command ?? '').slice(0, 80)}`).join('\n') || 'no guard requests' }],
    },
    async execute() {
      return tools.list() as any
    },
  })))
}