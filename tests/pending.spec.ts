import { describe, it, expect } from 'vitest';
import { mkdtemp, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PendingStore, pendingPath, MAX_PENDING, ticketHash } from '../src/host/pending.js';

const base = (scope: 'git-protection' | 'publish') => ({
  scope,
  tool: 'bash',
  command: 'probe command text',
  reason: 'blocked without APPROVED',
});

describe('PendingStore tickets', () => {
  it('records, lists newest-first, persists across instances, mode 600', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    const a = await s.record({ ...base('git-protection'), command: 'cmd-a' });
    const b = await s.record({ ...base('publish'), command: 'cmd-b' });
    expect(a.id).toMatch(/^g-[a-z0-9]+$/);
    expect(a.hash).toBe(ticketHash('git-protection', 'cmd-a'));
    const again = await s.list();
    expect(again.length).toBe(2);
    expect(again[0].id).toBe(b.id);
    expect(again.every((r) => r.status === 'pending')).toBe(true);
    const s2 = new PendingStore(dir);
    expect(await s2.list()).toHaveLength(2);
    const st = await stat(pendingPath(dir));
    expect(st.mode & 0o777).toBe(0o600);
  });

  it('dedupes identical scope+command while pending or approved', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    const r1 = await s.record({ ...base('git-protection'), command: 'same' });
    const r2 = await s.record({ ...base('git-protection'), command: 'same' });
    expect(r1.id).toBe(r2.id);
    expect(await s.list()).toHaveLength(1);
    await s.approve(r1.id);
    const r3 = await s.record({ ...base('git-protection'), command: 'same' });
    expect(r3.id).toBe(r1.id);
  });

  it('approve flips pending only; unknown/already-approved fail', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    const r = await s.record({ ...base('git-protection'), command: 'x' });
    expect((await s.approve(r.id))?.status).toBe('approved');
    expect(await s.approve(r.id)).toBeUndefined();
    expect(await s.approve('nope')).toBeUndefined();
  });

  it('consume flips approved only and returns whether it flipped', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    const r = await s.record({ ...base('publish'), command: 'y' });
    expect(await s.consume(r.id)).toBe(false); // pending cannot be consumed
    await s.approve(r.id);
    expect(await s.consume(r.id)).toBe(true);
    expect(await s.consume(r.id)).toBe(false); // consumed cannot be consumed twice
    expect((await s.list())[0].status).toBe('consumed');
  });

  it('findApprovedByHash returns only the approved ticket for the exact hash', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    const a = await s.record({ ...base('git-protection'), command: 'cmd-1' });
    const b = await s.record({ ...base('git-protection'), command: 'cmd-2' });
    expect(await s.findApprovedByHash('git-protection', a.hash)).toBeUndefined(); // pending
    await s.approve(b.id);
    const found = await s.findApprovedByHash('git-protection', b.hash);
    expect(found?.id).toBe(b.id);
    expect(await s.findApprovedByHash('publish', b.hash)).toBeUndefined(); // scope mismatch
    await s.consume(b.id);
    expect(await s.findApprovedByHash('git-protection', b.hash)).toBeUndefined(); // consumed
  });

  it('caps at MAX_PENDING dropping oldest resolved', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    for (let i = 0; i < MAX_PENDING; i++) {
      const r = await s.record({ ...base('git-protection'), command: `cmd-${i}` });
      if (i % 2 === 0) await s.consume((await s.approve(r.id))!.id);
    }
    const extra = await s.record({ ...base('publish'), command: 'overflow' });
    expect(extra.id).toBeTruthy();
    const list = await s.list();
    expect(list.length).toBeLessThanOrEqual(MAX_PENDING);
    expect(list.some((r) => r.command === 'overflow')).toBe(true);
  });
});