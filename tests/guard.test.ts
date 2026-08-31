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
    expect(pkg.version).toBe('0.1.0');
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
  it('approved tool with secret in arguments → next receives redacted payload', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const store = new ApprovalStore(dir)
    await store.approve('danger-tool')
    const policy = new PermissionPolicy({}) // allow all
    const handler = createGuardHandler(store, policy)
    const payload: any = { name: 'danger-tool', arguments: { token: 'glpat-abc123DEF4567890extra' } }
    let nextCalled = false
    let nextPayload: any = null
    const next = async () => {
      nextCalled = true
      nextPayload = payload // handler mutates payload in place before calling next
      return { kind: 'allow' as const }
    }
    const result = await handler(payload, next)
    expect(nextCalled).toBe(true)
    expect(result).toEqual({ kind: 'allow' })
    const asText = JSON.stringify(payload.arguments)
    expect(asText).toContain('[REDACTED]')
    expect(asText).not.toContain('glpat-abc123DEF4567890extra')
    // also ensure next saw redacted (if next captured after mutation, same object)
    expect(JSON.stringify(nextPayload.arguments)).toContain('[REDACTED]')
  })
  it('args shape also redacted (backward compat)', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const store = new ApprovalStore(dir)
    const policy = new PermissionPolicy({})
    const handler = createGuardHandler(store, policy)
    const payload: any = { name: 'safe-tool', args: { secret: 'sk-12345678901234567890' } }
    await handler(payload, async () => ({ kind: 'allow' as const }))
    expect(JSON.stringify(payload.args)).toContain('[REDACTED]')
    expect(JSON.stringify(payload.args)).not.toContain('sk-12345678901234567890')
  })
  it('ghp_ token redacted via containsSecret gate (all families)', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    const store = new ApprovalStore(dir)
    const policy = new PermissionPolicy({})
    const handler = createGuardHandler(store, policy)
    const raw = 'ghp_123456789012345678901234567890123456'
    const payload: any = { name: 'safe-tool', arguments: { token: raw } }
    const result = await handler(payload, async () => ({ kind: 'allow' as const }))
    expect(result).toEqual({ kind: 'allow' })
    expect(JSON.stringify(payload.arguments)).toContain('[REDACTED]')
    expect(JSON.stringify(payload.arguments)).not.toContain(raw)
  })
});
