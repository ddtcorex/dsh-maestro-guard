import { describe, it, expect } from 'vitest'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const PUSH = ['git', 'push', 'origin', 'master'].join(' ')

async function freshHandler(dir: string, now?: () => number) {
  const { ApprovalStore } = await import('../src/host/approval-store.js')
  const { PendingStore } = await import('../src/host/pending.js')
  const { PermissionPolicy } = await import('../src/host/permission-policy.js')
  const { createGuardHandler } = await import('../src/host/index.js')
  const store = new ApprovalStore(dir)
  const pending = new PendingStore(dir, now)
  const policy = new PermissionPolicy({})
  return { store, pending, handler: createGuardHandler(store, policy, pending, async () => ({})) }
}

const payload = (command: string, extras: Record<string, unknown> = {}) => ({
  name: 'bash',
  agent: { session: { id: (extras.sessionId as string) ?? 'S-main' } },
  ...extras,
  arguments: { command, description: (extras.description as string) ?? 'op', cwd: '/tmp/x' },
})

describe('approval lifecycle: canonical hash, TTL, session scope', () => {
  it('a retry that only changes the description consumes the approved ticket', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'al-'))
    const { pending, handler } = await freshHandler(dir)
    try { await handler(payload(PUSH, { description: 'attempt 1' }), async () => ({ kind: 'allow' as const })) } catch {}
    const req = (await pending.list())[0]
    expect(req).toBeDefined()
    expect(req.status).toBe('pending')
    await pending.approve(req.id)

    let nextCalled = false
    await handler(payload(PUSH, { description: 'attempt 2 — wording only' }), async () => { nextCalled = true; return { kind: 'allow' as const } })
    expect(nextCalled).toBe(true)
    const list = await pending.list()
    expect(list.filter((r) => r.status === 'consumed')).toHaveLength(1)
    expect(list.filter((r) => r.status === 'pending')).toHaveLength(0)
  })

  it('an approved ticket expires after APPROVAL_TTL_MS and no longer grants a pass-through', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'al-'))
    let t = 1_700_000_000_000
    const { pending, handler } = await freshHandler(dir, () => t)
    try { await handler(payload(PUSH), async () => ({ kind: 'allow' as const })) } catch {}
    const req = (await pending.list())[0]
    await pending.approve(req.id)
    expect((await pending.findApprovedByHash('git-protection', req.hash, 'S-main'))?.id).toBe(req.id)

    const { APPROVAL_TTL_MS } = await import('../src/host/pending.js')
    t += APPROVAL_TTL_MS + 1
    expect(await pending.findApprovedByHash('git-protection', req.hash)).toBeUndefined()
    let err: any
    try { await handler(payload(PUSH), async () => ({ kind: 'allow' as const })) } catch (e) { err = e }
    expect(err).toBeDefined()
    const statuses = (await pending.list()).map((r) => r.status)
    expect(statuses).toContain('expired')
    expect(statuses).toContain('pending') // fresh ticket for the retry
  })

  it('an approval recorded for session S1 cannot be consumed by a blocked call from session S2', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'al-'))
    const { pending, handler } = await freshHandler(dir)
    try { await handler(payload(PUSH, { sessionId: 'S1' }), async () => ({ kind: 'allow' as const })) } catch {}
    const req = (await pending.list())[0]
    expect(req.sessionId).toBe('S1')
    await pending.approve(req.id)

    let err: any
    try { await handler(payload(PUSH, { sessionId: 'S2' }), async () => ({ kind: 'allow' as const })) } catch (e) { err = e }
    expect(err).toBeDefined() // S2 must not consume S1's approval

    let nextCalled = false
    await handler(payload(PUSH, { sessionId: 'S1' }), async () => { nextCalled = true; return { kind: 'allow' as const } })
    expect(nextCalled).toBe(true) // the owning session still passes on retry
    expect((await pending.list()).filter((r) => r.status === 'consumed')).toHaveLength(1)
  })

  it('stale pending tickets expire too, keeping the store clean', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'al-'))
    let t = 1_700_000_000_000
    const { pending, handler } = await freshHandler(dir, () => t)
    try { await handler(payload(PUSH), async () => ({ kind: 'allow' as const })) } catch {}
    const { APPROVAL_TTL_MS } = await import('../src/host/pending.js')
    t += APPROVAL_TTL_MS + 1
    // any store read that prunes should surface the expired status
    expect((await pending.list()).map((r) => r.status)).toContain('expired')
  })
})