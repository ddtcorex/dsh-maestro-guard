import { describe, it, expect, beforeEach } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ApprovalStore } from '../src/approval-store.js'

describe('ApprovalStore', () => {
  let dir: string
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'guard-')); })
  it('returns false for unknown tool', async () => {
    const s = new ApprovalStore(dir)
    expect(await s.isApproved('dangerous-tool')).toBe(false)
  })
  it('persists approve', async () => {
    const s = new ApprovalStore(dir)
    await s.approve('my-tool')
    expect(await s.isApproved('my-tool')).toBe(true)
    const s2 = new ApprovalStore(dir)
    expect(await s2.isApproved('my-tool')).toBe(true)
  })
  it('migrates legacy dsh-maestro-harness approvals.json', async () => {
    const legacy = join(dir, 'dsh-maestro-harness', 'approvals.json')
    const { mkdir, writeFile } = await import('node:fs/promises')
    const { dirname } = await import('node:path')
    await mkdir(dirname(legacy), { recursive: true })
    await writeFile(legacy, JSON.stringify({ 'old-tool': true }), 'utf-8')
    const s = new ApprovalStore(dir)
    // should copy legacy to new location on first load
    expect(await s.isApproved('old-tool')).toBe(true)
  })
  it('revoke on missing dir does not throw', async () => {
    const s = new ApprovalStore(dir)
    // no prior approve, dir dsh-maestro-guard does not exist yet
    await expect(s.revoke('nonexistent-tool')).resolves.toBeUndefined()
    // after revoke, file should exist and isApproved should be false
    expect(await s.isApproved('nonexistent-tool')).toBe(false)
  })
  it('corrupted JSON file -> load returns {} and isApproved false', async () => {
    const { mkdir, writeFile } = await import('node:fs/promises')
    const { approvalsPath } = await import('../src/approval-store.js')
    const p = approvalsPath(dir)
    const { dirname } = await import('node:path')
    await mkdir(dirname(p), { recursive: true })
    await writeFile(p, 'not-json{{{', 'utf-8')
    const s = new ApprovalStore(dir)
    expect(await s.load()).toEqual({})
    expect(await s.isApproved('any-tool')).toBe(false)
  })
  it('after legacy migration, original legacy file still exists (no deletion)', async () => {
    const legacy = join(dir, 'dsh-maestro-harness', 'approvals.json')
    const { mkdir, writeFile, readFile } = await import('node:fs/promises')
    const { dirname } = await import('node:path')
    const { approvalsPath } = await import('../src/approval-store.js')
    await mkdir(dirname(legacy), { recursive: true })
    await writeFile(legacy, JSON.stringify({ 'old-tool': true }), 'utf-8')
    const s = new ApprovalStore(dir)
    expect(await s.isApproved('old-tool')).toBe(true)
    // legacy file should still exist
    const legacyData = await readFile(legacy, 'utf-8')
    expect(JSON.parse(legacyData)).toEqual({ 'old-tool': true })
    // new file should also exist
    const newData = await readFile(approvalsPath(dir), 'utf-8')
    expect(JSON.parse(newData)).toEqual({ 'old-tool': true })
  })
})
