import { describe, it, expect } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ApprovalStore } from '../src/host/approval-store.js';
import { PendingStore } from '../src/host/pending.js';
import { createGuardRpcHandler, type RpcResult } from '../src/host/rpc.js';

describe('guard rpc', () => {
  async function setup() {
    const dir = await mkdtemp(join(tmpdir(), 'r-'));
    const store = new ApprovalStore(dir);
    const pending = new PendingStore(dir);
    return { handler: createGuardRpcHandler({ store, pending }), store, pending, dir };
  }
  it('list returns requests and grants', async () => {
    const { handler, pending, store } = await setup();
    await pending.record({ scope: 'git-protection', tool: 'bash', command: 'c', reason: 'r' });
    await store.approve('publish');
    const res = (await handler('list', {})) as RpcResult<{ requests: unknown[]; grants: Record<string, boolean> }>;
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.requests).toHaveLength(1);
    expect(res.value.grants).toEqual({ publish: true });
  });
  it('approve writes the grant for the request scope', async () => {
    const { handler, pending, store } = await setup();
    const req = await pending.record({ scope: 'git-protection', tool: 'bash', command: 'c', reason: 'r' });
    const res = (await handler('approve', { id: req.id })) as RpcResult<{ scope: string }>;
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.scope).toBe('git-protection');
    expect(await store.isApproved('git-protection')).toBe(true);
    expect((await pending.list())[0].status).toBe('approved');
  });
  it('approve with unknown or missing id fails cleanly', async () => {
    const { handler } = await setup();
    expect(((await handler('approve', {})) as RpcResult<never>).ok).toBe(false);
    expect(((await handler('approve', { id: 'nope' })) as RpcResult<never>).ok).toBe(false);
  });
  it('dismiss marks the request dismissed without granting', async () => {
    const { handler, pending, store } = await setup();
    const req = await pending.record({ scope: 'publish', tool: 'bash', command: 'c', reason: 'r' });
    expect(((await handler('dismiss', { id: req.id })) as RpcResult<unknown>).ok).toBe(true);
    expect(((await handler('dismiss', { id: 'nope' })) as RpcResult<never>).ok).toBe(false);
    expect(await store.isApproved('publish')).toBe(false);
    expect((await pending.list())[0].status).toBe('dismissed');
  });
  it('revoke clears the grant', async () => {
    const { handler, store } = await setup();
    await store.approve('publish');
    expect(((await handler('revoke', { scope: 'publish' })) as RpcResult<unknown>).ok).toBe(true);
    expect(await store.isApproved('publish')).toBe(false);
  });
  it('unknown endpoint fails', async () => {
    const { handler } = await setup();
    expect(((await handler('explode', {})) as RpcResult<never>).ok).toBe(false);
  });
});