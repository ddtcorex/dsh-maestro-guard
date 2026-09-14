import { describe, it, expect } from 'vitest'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { createGuardHandler } from '../src/host/index.js'
import { Journal } from '../src/host/journal.js'
import { PermissionPolicy } from '../src/host/permission-policy.js'
import { DEFAULT_CONFIG } from '../src/host/config.js'

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

/**
 * The handler's behaviour is pinned by `tests/guard-handler.test.ts` (tiers,
 * journal, native ask). These cases cover the two contracts this file has
 * always owned: a policy-denied tool never reaches the tool, and the executed
 * arguments are never rewritten.
 */
describe('guard handler via createGuardHandler', () => {
  async function handler(policy: PermissionPolicy) {
    const dir = await mkdtemp(join(tmpdir(), 'g-'))
    return createGuardHandler({
      journal: new Journal(dir),
      policy,
      readConfig: async () => DEFAULT_CONFIG,
      requestApproval: async () => 'granted',
    })
  }

  it('denies a policy-denied tool with a reason', async () => {
    const h = await handler(new PermissionPolicy({ deny: ['danger-tool'] }))
    const payload: any = { name: 'danger-tool', arguments: { token: '[REDACTED]' } }
    const res = await h(payload, async () => ({ kind: 'allow' as const }))
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toContain('denied by policy')
  })

  it('passes an allowed tool through without touching the executed arguments', async () => {
    const h = await handler(new PermissionPolicy({}))
    // Secret values are assembled at runtime: a raw token literal in this file
    // would be rewritten by the guard path under test before it could be read.
    const raw = 'glpat-' + 'abc123DEF4567890extra'
    const args = { token: raw }
    const payload: any = { name: 'safe-tool', arguments: args }
    let nextCalled = false
    const result = await h(payload, async () => {
      nextCalled = true
      return { kind: 'allow' as const }
    })
    expect(nextCalled).toBe(true)
    expect(result).toEqual({ kind: 'allow' })
    // Redaction belongs to the journal copy only: the executed call keeps the
    // exact object the caller passed (no in-place rewrite, no swap).
    expect(payload.arguments).toBe(args)
    expect(payload.arguments.token).toBe(raw)

    const argsShape = { secret: 'sk-' + '12345678901234567890' }
    const argsPayload: any = { name: 'safe-tool', args: argsShape }
    await h(argsPayload, async () => ({ kind: 'allow' as const }))
    expect(argsPayload.args).toBe(argsShape)
    expect(argsPayload.args.secret).toBe(argsShape.secret)
  })
});
