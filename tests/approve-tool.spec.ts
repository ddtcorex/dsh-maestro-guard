import { describe, it, expect } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PendingStore } from '../src/host/pending.js';
import { createApproveTools } from '../src/host/approve-tool.js';

describe('guard approve tools', () => {
  async function setup() {
    const dir = await mkdtemp(join(tmpdir(), 'a-'));
    const pending = new PendingStore(dir);
    return { tools: createApproveTools({ pending }), pending, dir };
  }
  it('approve flips a pending ticket and reports scope', async () => {
    const { tools, pending } = await setup();
    const req = await pending.record({ scope: 'git-protection', tool: 'bash', command: 'c', reason: 'r' });
    const res = await tools.approve(req.id);
    expect(res.ok).toBe(true);
    expect(res.scope).toBe('git-protection');
    expect(res.status).toBe('approved');
  });
  it('approve fails on missing and non-pending ids', async () => {
    const { tools, pending } = await setup();
    expect((await tools.approve('')).ok).toBe(false);
    expect((await tools.approve('nope')).ok).toBe(false);
    const req = await pending.record({ scope: 'publish', tool: 'bash', command: 'c', reason: 'r' });
    await pending.approve(req.id);
    expect((await tools.approve(req.id)).ok).toBe(false);
  });
  it('list returns tickets newest first', async () => {
    const { tools, pending } = await setup();
    await pending.record({ scope: 'git-protection', tool: 'bash', command: 'a', reason: 'r' });
    await pending.record({ scope: 'publish', tool: 'bash', command: 'b', reason: 'r' });
    const res = await tools.list();
    expect(res.ok).toBe(true);
    expect(res.requests.map((r) => r.command)).toEqual(['b', 'a']);
  });
});