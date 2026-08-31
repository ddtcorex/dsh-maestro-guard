import type { ApprovalStore } from './approval-store.js'
import type { PendingStore } from './pending.js'

export type RpcResult<T> = { ok: true; value: T } | { ok: false; error: { code: string; message: string; details: object } }

function ok<T>(value: T): RpcResult<T> { return { ok: true, value } }
function fail(message: string): RpcResult<never> {
  return { ok: false, error: { code: 'bad-request', message, details: { issues: [{ message }] } } }
}

export interface GuardRpcDeps { store: ApprovalStore; pending: PendingStore }

export function createGuardRpcHandler(deps: GuardRpcDeps) {
  return async (endpoint: string, payload: unknown): Promise<RpcResult<unknown>> => {
    const body = (payload ?? {}) as { id?: string; scope?: string }
    if (endpoint === 'list') {
      const requests = await deps.pending.list()
      const grants = await deps.store.load()
      return ok({ requests, grants })
    }
    if (endpoint === 'approve') {
      if (typeof body.id !== 'string' || body.id.length === 0) return fail('id (string) is required')
      const req = await deps.pending.approve(body.id)
      if (!req) return fail(`no pending request with id ${body.id}`)
      await deps.store.approve(req.scope)
      return ok({ id: req.id, scope: req.scope })
    }
    if (endpoint === 'dismiss') {
      if (typeof body.id !== 'string' || body.id.length === 0) return fail('id (string) is required')
      const req = await deps.pending.dismiss(body.id)
      if (!req) return fail(`no pending request with id ${body.id}`)
      return ok({ id: req.id })
    }
    if (endpoint === 'revoke') {
      if (typeof body.scope !== 'string' || body.scope.length === 0) return fail('scope (string) is required')
      await deps.store.revoke(body.scope)
      return ok(null)
    }
    return fail(`unknown endpoint: ${String(endpoint)}`)
  }
}