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
})
