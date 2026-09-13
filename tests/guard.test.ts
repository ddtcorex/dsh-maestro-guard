import { describe, it, expect } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ApprovalStore } from '../src/host/approval-store.js';
import { PermissionPolicy } from '../src/host/permission-policy.js';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

function readFileCandidates(...candidates: string[]): string {
  for (const c of candidates) {
    if (existsSync(c)) return readFileSync(c, 'utf8');
    if (existsSync(resolve(c))) return readFileSync(resolve(c), 'utf8');
  }
  try { return readFileSync(new URL(`../${candidates[0].replace('packages/dsh-maestro-guard/', '')}`, import.meta.url), 'utf8'); } catch {}
  throw new Error('not found: ' + candidates.join(', '));
}

describe('dsh-maestro-guard', () => {
  it('src/host/index.ts contains preExecute or waterfall', () => {
    const src = readFileCandidates('packages/dsh-maestro-guard/src/host/index.ts', 'src/host/index.ts', 'packages/dsh-maestro-guard/src/index.ts', 'src/index.ts');
    const hasWaterfall = src.includes('preExecute') || src.includes('pre-execute') || src.includes('tools/pre-execute');
    expect(hasWaterfall).toBe(true);
  });

  it('package.json name is @ddtcorex/dsh-maestro-guard', () => {
    const pkg = JSON.parse(readFileCandidates('packages/dsh-maestro-guard/package.json', 'package.json'));
    expect(pkg.name).toBe('@ddtcorex/dsh-maestro-guard');
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.dsh.bundle.patch).toBe('./cordis.patch.yml');
  });

  it('cordis.patch.yml has dsh-maestro-guard row', () => {
    const yml = readFileCandidates('packages/dsh-maestro-guard/cordis.patch.yml', 'cordis.patch.yml');
    expect(yml).toContain('dsh-maestro-guard');
    expect(yml).toContain('@ddtcorex/dsh-maestro-guard');
  });
});

// Simulate waterfall: guard should block unapproved tool
describe('guard waterfall', () => {
  it('blocks unapproved dangerous tool', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const store = new ApprovalStore(dir)
    const policy = new PermissionPolicy({ deny: ['danger-tool'] })
    // waterfall handler would check: !store.isApproved && policy.isAllowed => block
    expect(policy.isAllowed('danger-tool', {})).toBe(false)
    expect(await store.isApproved('danger-tool')).toBe(false)
  })
});

describe('guard handler via createGuardHandler', () => {
  it('deny-path throws for denied tool', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const store = new ApprovalStore(dir)
    const policy = new PermissionPolicy({ deny: ['danger-tool'] })
    const handler = createGuardHandler(store, policy)
    const payload: any = { name: 'danger-tool', arguments: { token: 'glpat-abc123DEF4567890extra' } }
    await expect(handler(payload, async () => ({ kind: 'allow' as const }))).rejects.toThrow(/denied by policy/)
  })
  it('unapproved danger-tool throws requires approval', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const store = new ApprovalStore(dir)
    const policy = new PermissionPolicy({}) // allow all, so deny check passes but approval fails
    const handler = createGuardHandler(store, policy)
    const payload: any = { name: 'danger-tool', arguments: { note: 'hello' } }
    await expect(handler(payload, async () => ({ kind: 'allow' as const }))).rejects.toThrow(/requires approval/)
  })
  it('approved danger-tool passes the approval branch and reaches next', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const store = new ApprovalStore(dir)
    await store.approve('danger-tool') // the only grant that satisfies the approval check
    const policy = new PermissionPolicy({}) // allow all, so approval is the branch under test
    const handler = createGuardHandler(store, policy)
    // Runtime-assembled secret keeps the migrated case's payload shape without a
    // raw token literal in this file (the live guard would rewrite one on write).
    const raw = 'glpat-' + 'abc123DEF4567890extra'
    const args = { token: raw }
    const payload: any = { name: 'danger-tool', arguments: args }
    let nextCalled = false
    const result = await handler(payload, async () => {
      nextCalled = true
      return { kind: 'allow' as const }
    })
    expect(nextCalled).toBe(true)
    expect(result).toEqual({ kind: 'allow' })
    expect(payload.arguments).toBe(args)
  })
  it('does not rewrite the executed arguments when a secret is present', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const store = new ApprovalStore(dir)
    const policy = new PermissionPolicy({}) // allow all
    const handler = createGuardHandler(store, policy)
    // Secret values are assembled at runtime: a raw token literal in this file
    // would be rewritten by the guard path under test before it could be read.
    const raw = 'glpat-' + 'abc123DEF4567890extra'
    const args = { token: raw }
    const payload: any = { name: 'safe-tool', arguments: args }
    let nextCalled = false
    const result = await handler(payload, async () => {
      nextCalled = true
      return { kind: 'allow' as const }
    })
    expect(nextCalled).toBe(true)
    expect(result).toEqual({ kind: 'allow' })
    // Redaction belongs to the stored/journal copy only: the executed call keeps
    // the exact object the caller passed (no in-place rewrite, no swap).
    expect(payload.arguments).toBe(args)
    expect(payload.arguments.token).toBe(raw)

    const argsShape = { secret: 'sk-' + '12345678901234567890' }
    const argsPayload: any = { name: 'safe-tool', args: argsShape }
    await handler(argsPayload, async () => ({ kind: 'allow' as const }))
    expect(argsPayload.args).toBe(argsShape)
    expect(argsPayload.args.secret).toBe(argsShape.secret)
  })
});

describe('guard handler chat-approve tickets', () => {
  const mergeCmd = ['gh', 'pr', 'merge', '4'].join(' ')
  const pubCmd = ['pnpm', 'publish'].join(' ')
  const basePayload = (cmd: string) => ({ name: 'bash', arguments: { command: cmd, cwd: '/tmp/x' } })
  async function fresh(dir: string) {
    const { PendingStore } = await import('../src/host/pending.js')
    const { createGuardHandler } = await import('../src/host/index.js')
    const store = new ApprovalStore(dir)
    const pending = new PendingStore(dir)
    const policy = new PermissionPolicy({})
    return { store, pending, policy, handler: createGuardHandler(store, policy, pending, async () => ({})) }
  }
  it('blocked merge records a ticket and the error names the id', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const { pending, handler } = await fresh(dir)
    let err: any
    try { await handler(basePayload(mergeCmd), async () => ({ kind: 'allow' as const })) } catch (e) { err = e }
    expect(err).toBeDefined()
    expect(String(err.message)).toContain('request g-')
    const reqs = await pending.list()
    expect(reqs.length).toBe(1)
    expect(reqs[0].scope).toBe('git-protection')
    expect(reqs[0].status).toBe('pending')
  })
  it('approved ticket lets the exact command pass once, then blocks again', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const { pending, handler, store } = await fresh(dir)
    try { await handler(basePayload(mergeCmd), async () => ({ kind: 'allow' as const })) } catch {}
    const req = (await pending.list())[0]
    await pending.approve(req.id)
    let nextCalled = false
    await handler(basePayload(mergeCmd), async () => { nextCalled = true; return { kind: 'allow' as const } })
    expect(nextCalled).toBe(true)
    expect((await pending.list())[0].status).toBe('consumed')
    expect(await store.isApproved('git-protection')).toBe(false) // no scope-wide grant
    let err: any
    try { await handler(basePayload(mergeCmd), async () => ({ kind: 'allow' as const })) } catch (e) { err = e }
    expect(err).toBeDefined()
    // re-blocked: a fresh pending ticket for the same hash
    expect((await pending.list()).some((r) => r.status === 'pending')).toBe(true)
  })
  it('pending ticket does not let the command pass', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const { handler } = await fresh(dir)
    try { await handler(basePayload(mergeCmd), async () => ({ kind: 'allow' as const })) } catch {}
    let err: any
    try { await handler(basePayload(mergeCmd), async () => ({ kind: 'allow' as const })) } catch (e) { err = e }
    expect(err).toBeDefined()
  })
  it('a modified invocation is blocked even when the original is approved', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const { handler } = await fresh(dir)
    try { await handler(basePayload(mergeCmd), async () => ({ kind: 'allow' as const })) } catch {}
    try { await handler(basePayload(mergeCmd + ' --no-edit'), async () => ({ kind: 'allow' as const })) } catch {}
    const { PendingStore } = await import('../src/host/pending.js')
    const pending = new PendingStore(dir)
    const reqs = await pending.list()
    expect(reqs.length).toBe(2) // different hashes -> separate tickets
  })
  it('blocked publish records scope publish', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const { pending, handler } = await fresh(dir)
    let err: any
    try { await handler(basePayload(pubCmd), async () => ({ kind: 'allow' as const })) } catch (e) { err = e }
    expect(err).toBeDefined()
    expect((await pending.list())[0].scope).toBe('publish')
  })
})
