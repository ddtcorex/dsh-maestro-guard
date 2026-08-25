import { describe, it, expect } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ApprovalStore } from '../src/approval-store.js';
import { PermissionPolicy } from '../src/permission-policy.js';
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
  it('src/index.ts contains preExecute or waterfall', () => {
    const src = readFileCandidates('packages/dsh-maestro-guard/src/index.ts', 'src/index.ts');
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
