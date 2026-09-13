import { describe, it, expect } from 'vitest'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createGuardHandler } from '../src/host/index.js'
import { Journal, journalPath } from '../src/host/journal.js'
import { PermissionPolicy } from '../src/host/permission-policy.js'
import { DEFAULT_CONFIG } from '../src/host/config.js'
import type { AskOutcome } from '../src/host/journal.js'

async function setup(outcome: AskOutcome) {
  const dir = await mkdtemp(join(tmpdir(), 'h-'))
  const journal = new Journal(dir)
  const asked: string[] = []
  const handler = createGuardHandler({
    journal, policy: new PermissionPolicy({}), readConfig: async () => DEFAULT_CONFIG,
    requestApproval: async (req) => { asked.push(req.reason); return outcome },
    branchOf: () => 'feature',
  })
  const next = async () => ({ kind: 'allow' as const })
  return { dir, handler, asked, next, journal }
}

describe('createGuardHandler', () => {
  it('passes an ordinary command through and journals nothing blocking', async () => {
    const { handler, next, dir } = await setup('rejected')
    const res = await handler({ name: 'bash', args: { command: 'ls -la' } } as any, next)
    expect(res.kind).toBe('allow')
    const lines = (await readFile(journalPath(dir), 'utf8').catch(() => '')).trim().split('\n').filter(Boolean)
    expect(lines).toHaveLength(0)
  })

  it('asks before a protected push and allows once on granted', async () => {
    const { handler, next, asked, dir } = await setup('granted')
    const res = await handler({ name: 'bash', args: { command: 'git push origin master' } } as any, next)
    expect(res.kind).toBe('allow')
    expect(asked[0]).toContain('git.push.protected')
    const entry = JSON.parse((await readFile(journalPath(dir), 'utf8')).trim().split('\n')[0])
    expect(entry).toMatchObject({ rule: 'git.push.protected', tier: 'ask', outcome: 'granted' })
    expect(typeof entry.askMs).toBe('number')
  })

  it('denies with the rule reason when the human rejects', async () => {
    const { handler, next, dir } = await setup('rejected')
    const res = await handler({ name: 'bash', args: { command: 'git push origin master' } } as any, next)
    expect(res.kind).toBe('deny')
    expect((res as any).reason).toContain('git.push.protected')
    const entry = JSON.parse((await readFile(journalPath(dir), 'utf8')).trim().split('\n')[0])
    expect(entry.outcome).toBe('rejected')
  })

  it('denies without prompting when no approval channel exists (fail-closed)', async () => {
    const { handler, next, asked } = await setup('unavailable')
    const res = await handler({ name: 'bash', args: { command: 'git push origin master' } } as any, next)
    expect(res.kind).toBe('deny')
    expect((res as any).reason).toMatch(/no approval channel/i)
    expect(asked).toHaveLength(1)
  })

  it('journals but passes a merge (D3) and never asks for it', async () => {
    const { handler, next, asked, dir } = await setup('rejected')
    const res = await handler({ name: 'bash', args: { command: 'gh pr merge 5 --squash' } } as any, next)
    expect(res.kind).toBe('allow')
    expect(asked).toHaveLength(0)
    const entry = JSON.parse((await readFile(journalPath(dir), 'utf8')).trim())
    expect(entry).toMatchObject({ rule: 'git.merge.protected', tier: 'journal' })
  })

  it('still denies a policy-denied tool', async () => {
    const { dir } = await setup('granted')
    const handler = createGuardHandler({
      journal: new Journal(dir), policy: new PermissionPolicy({ deny: ['danger-tool'] }),
      readConfig: async () => DEFAULT_CONFIG, requestApproval: async () => 'granted',
    })
    const res = await handler({ name: 'danger-tool', args: {} } as any, async () => ({ kind: 'allow' as const }))
    expect(res.kind).toBe('deny')
    expect((res as any).reason).toContain('denied by policy')
  })
})
