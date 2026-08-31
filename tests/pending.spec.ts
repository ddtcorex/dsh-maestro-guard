import { describe, it, expect } from 'vitest';
import { mkdtemp, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PendingStore, pendingPath, MAX_PENDING } from '../src/host/pending.js';

const base = (scope: 'git-protection' | 'publish') => ({
  scope,
  tool: 'bash',
  command: 'probe command text',
  reason: 'blocked without APPROVED',
});

describe('PendingStore', () => {
  it('records, lists newest-first, and persists across instances', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    const a = await s.record({ ...base('git-protection'), command: 'cmd-a' });
    const b = await s.record({ ...base('publish'), command: 'cmd-b' });
    expect(a.id).toMatch(/^g-[a-z0-9]+$/);
    const again = await s.list();
    expect(again.length).toBe(2);
    expect(again[0].id).toBe(b.id); // newest first
    expect(again.every((r) => r.status === 'pending')).toBe(true);
    const s2 = new PendingStore(dir); // reload from disk
    expect(await s2.list()).toHaveLength(2);
    const st = await stat(pendingPath(dir));
    expect(st.mode & 0o777).toBe(0o600);
  });

  it('dedupes identical scope+command while pending', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    const r1 = await s.record({ ...base('git-protection'), command: 'same' });
    const r2 = await s.record({ ...base('git-protection'), command: 'same' });
    expect(r1.id).toBe(r2.id);
    expect(await s.list()).toHaveLength(1);
  });

  it('approve flips status and is idempotent; unknown id returns undefined', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    const r = await s.record({ ...base('git-protection'), command: 'x' });
    const got = await s.approve(r.id);
    expect(got?.status).toBe('approved');
    expect(await s.approve(r.id)).toBeUndefined();
    expect(await s.approve('nope')).toBeUndefined();
    const list = await s.list();
    expect(list[0].status).toBe('approved');
    // approving does not re-allow a NEW pending entry of the same command
    const r2 = await s.record({ ...base('git-protection'), command: 'x' });
    expect(r2.id).not.toBe(r.id);
  });

  it('dismiss flips status without granting', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    const r = await s.record({ ...base('publish'), command: 'y' });
    const got = await s.dismiss(r.id);
    expect(got?.status).toBe('dismissed');
  });

  it('caps the list at MAX_PENDING dropping oldest resolved', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'p-'));
    const s = new PendingStore(dir);
    for (let i = 0; i < MAX_PENDING; i++) {
      const r = await s.record({ ...base('git-protection'), command: `cmd-${i}` });
      if (i % 2 === 0) await s.approve(r.id);
    }
    const extra = await s.record({ ...base('publish'), command: 'overflow' });
    expect(extra.id).toBeTruthy();
    const list = await s.list();
    expect(list.length).toBeLessThanOrEqual(MAX_PENDING);
    expect(list.some((r) => r.command === 'overflow')).toBe(true);
  });
});