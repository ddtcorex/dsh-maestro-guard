import { describe, it, expect, beforeAll } from 'vitest'
import { mkdtemp, mkdir, readFile } from 'node:fs/promises'
import { execSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createGuardHandler, branchOf } from '../src/host/index.js'
import { Journal, journalPath } from '../src/host/journal.js'
import { PermissionPolicy } from '../src/host/permission-policy.js'
import { DEFAULT_CONFIG } from '../src/host/config.js'
import { defaultProtectedPaths } from '../src/host/paths.js'
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

  // The deleted `sandbox`/`command-scope` suites exercised the same pipeline
  // through `checkSandbox`; these pin it through the live classify → decide →
  // native-ask path. The protected path comes from `paths.ts`, never a literal.
  it('asks before a protected-path read and allows once the human grants it', async () => {
    const { handler, next, asked } = await setup('granted')
    const res = await handler({ name: 'read', args: { file_path: defaultProtectedPaths()[0] } } as any, next)
    expect(res).toEqual({ kind: 'allow' })
    expect(asked[0]).toContain('secret.access')
  })

  it('denies a protected-path read the human rejects', async () => {
    const { handler, next } = await setup('rejected')
    const res = await handler({ name: 'read', args: { file_path: defaultProtectedPaths()[0] } } as any, next)
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toMatch(/secret\.access/)
  })

  // Deleted `sandbox` suite: its publish ask/grant/deny pair, pinned through the
  // live classify → decide → native-ask path (the mapping in the B4 commit body
  // routes those cases to this suite).
  it('asks before a package publish and allows once the human grants it', async () => {
    const { handler, next, asked, dir } = await setup('granted')
    const res = await handler({ name: 'bash', args: { command: 'pnpm publish' } } as any, next)
    expect(res).toEqual({ kind: 'allow' })
    expect(asked[0]).toContain('pkg.publish')
    const entry = JSON.parse((await readFile(journalPath(dir), 'utf8')).trim().split('\n')[0])
    expect(entry).toMatchObject({ rule: 'pkg.publish', tier: 'ask', outcome: 'granted' })
  })

  it('denies a package publish the human rejects', async () => {
    const { handler, next, asked } = await setup('rejected')
    const res = await handler({ name: 'bash', args: { command: 'npm publish' } } as any, next)
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toMatch(/pkg\.publish/)
    expect(asked).toHaveLength(1)
  })

  it('ignores phrasing that only appears in the description field', async () => {
    const { handler, next, asked } = await setup('rejected')
    const payload: any = {
      name: 'bash',
      args: { command: 'true', description: 'mentions ' + ['pnpm', 'publish'].join(' ') + ' in prose' },
    }
    const res = await handler(payload, next)
    expect(res.kind).toBe('allow')
    expect(asked).toHaveLength(0)
  })
})

/**
 * Task B4 — the deleted `branch-scope` suite's end-to-end pair, ported to the
 * suite that owns handler integration. Real repositories: the session cwd repo
 * sits on `master`, the command's `cd` target on a feature branch.
 */
describe('createGuardHandler — branch scope with real repositories', () => {
  let rootRepo: string
  let featRepo: string
  beforeAll(async () => {
    const dir = await mkdtemp(join(tmpdir(), 'g-scope-'))
    rootRepo = join(dir, 'root')
    featRepo = join(dir, 'jobs')
    await mkdir(rootRepo)
    await mkdir(featRepo)
    execSync('git init -q -b master', { cwd: rootRepo })
    execSync('git -c user.name=t -c user.email=t@t commit --allow-empty -q -m init', { cwd: rootRepo })
    execSync('git init -q -b fix/jobs-x', { cwd: featRepo })
    execSync('git -c user.name=t -c user.email=t@t commit --allow-empty -q -m init', { cwd: featRepo })
  })

  async function handlerFor() {
    const dir = await mkdtemp(join(tmpdir(), 'g-scope-handler-'))
    return createGuardHandler({
      journal: new Journal(dir),
      policy: new PermissionPolicy({}),
      readConfig: async () => DEFAULT_CONFIG,
      requestApproval: async () => 'rejected',
      branchOf,
    })
  }

  it('passes a feature push with a cd target even though the session cwd repo sits on master', async () => {
    const handler = await handlerFor()
    const payload: any = {
      name: 'bash',
      agent: { session: { header: { cwd: rootRepo } } },
      arguments: { command: `cd ${featRepo} && git push -u origin fix/jobs-x 2>&1 | tail -5`, description: 'push fix branch' },
    }
    let nextCalled = false
    const res = await handler(payload, async () => { nextCalled = true; return { kind: 'allow' as const } })
    expect(nextCalled).toBe(true)
    expect(res).toEqual({ kind: 'allow' })
  })

  it('a real master push stays blocked even when the command target is a feature-branch repo', async () => {
    const handler = await handlerFor()
    const payload: any = {
      name: 'bash',
      agent: { session: { header: { cwd: rootRepo } } },
      arguments: { command: `cd ${featRepo} && git push origin master` },
    }
    const res = await handler(payload, async () => ({ kind: 'allow' as const }))
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toMatch(/git\.push\.protected/)
  })

  // Deleted `unknown-working-dir` suite: an unreadable cd target must not
  // inherit the session cwd's protected branch — the repo is unprovable, so the
  // push fails closed. The session cwd repo here really is on `master`.
  it('never inherits the session cwd branch for a quoted, unreadable cd target', async () => {
    const handler = await handlerFor()
    const payload: any = {
      name: 'bash',
      agent: { session: { header: { cwd: rootRepo } } },
      arguments: { command: 'cd "$REPO" && git push', description: 'push feature branch' },
    }
    const res = await handler(payload, async () => ({ kind: 'allow' as const }))
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toMatch(/git\.push\.protected/)
  })

  it('resolves no branch for a directory the caller could not resolve', () => {
    // The empty-directory sentinel: `git -C ""` would silently resolve to the
    // session cwd and re-create the false positives repo resolution removed.
    expect(branchOf('')).toBeUndefined()
  })
})

/**
 * IMPORTANT 5 / 7 and the granted-ask pass-through.
 *
 * Spec §8: an unknown `tools/pre-execute` payload must `deny` + journal
 * `contract-mismatch`. The guard reads `exec.name ?? exec.tool` and
 * `exec.args ?? exec.arguments`; a DSH upgrade that renames either field would
 * otherwise make every command rule read `undefined` and silently allow
 * everything. These cases pin the live shape as KNOWN and the renamed shape as
 * denied.
 */
describe('createGuardHandler — runtime contract and the approval error note', () => {
  it('recognizes the LIVE payload shape (name/arguments/callId) and classifies it', async () => {
    const { handler, asked } = await setup('granted')
    // The real DSH execution carries `name` and `arguments` plus callId/signal —
    // never the `args` alias the guard also accepts.
    const res = await handler(
      { name: 'bash', arguments: { command: 'git push origin master' }, callId: 'call-1', signal: new AbortController().signal } as any,
      async () => ({ kind: 'allow' as const }),
    )
    expect(res).toEqual({ kind: 'allow' })
    expect(asked[0]).toContain('git.push.protected')
  })

  it('denies and journals contract-mismatch when the arguments field is renamed away', async () => {
    const { handler, next, dir } = await setup('granted')
    const res = await handler({ name: 'bash', input: { command: 'git push origin master' } } as any, next)
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toContain('contract-mismatch')
    const entry = JSON.parse((await readFile(journalPath(dir), 'utf8')).trim())
    expect(entry).toMatchObject({ rule: 'contract-mismatch', tier: 'deny', outcome: 'denied' })
    expect(entry.note).toContain('arguments')
  })

  it('denies and journals contract-mismatch when the payload carries no tool name', async () => {
    const { handler, next, dir } = await setup('granted')
    const res = await handler({ args: { command: 'git push origin master' } } as any, next)
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toContain('contract-mismatch')
    const entry = JSON.parse((await readFile(journalPath(dir), 'utf8')).trim())
    expect(entry).toMatchObject({ rule: 'contract-mismatch', tier: 'deny' })
  })

  it('denies a payload that is not an object at all', async () => {
    const { handler, next, dir } = await setup('granted')
    const res = await handler(undefined as any, next)
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toContain('contract-mismatch')
    expect(JSON.parse((await readFile(journalPath(dir), 'utf8')).trim()).rule).toBe('contract-mismatch')
  })

  it('journals the thrown approval message as the note, keeping the deny text honest', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'h-note-'))
    const handler = createGuardHandler({
      journal: new Journal(dir),
      policy: new PermissionPolicy({}),
      readConfig: async () => DEFAULT_CONFIG,
      requestApproval: async () => ({ outcome: 'error', note: 'no open turn: ask from inside the turn' }),
      branchOf: () => 'feature',
    })
    const res = await handler({ name: 'bash', args: { command: 'git push origin master' } } as any, async () => ({ kind: 'allow' as const }))
    expect(res.kind).toBe('deny')
    // The text points at the journal — so the journal must carry the reason.
    expect(String((res as any).reason)).toMatch(/see the guard journal/)
    const entry = JSON.parse((await readFile(journalPath(dir), 'utf8')).trim())
    expect(entry).toMatchObject({ outcome: 'error' })
    expect(entry.note).toContain('no open turn')
  })

  it('runs later pre-execute listeners on a granted ask (returns next(), not a bare allow)', async () => {
    const { handler, asked } = await setup('granted')
    let nextCalled = false
    const res = await handler(
      { name: 'bash', args: { command: 'git push origin master' } } as any,
      async () => { nextCalled = true; return { kind: 'allow' as const } },
    )
    expect(asked).toHaveLength(1)
    expect(nextCalled).toBe(true)
    expect(res).toEqual({ kind: 'allow' })
  })
})
