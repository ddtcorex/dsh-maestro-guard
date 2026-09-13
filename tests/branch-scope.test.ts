import { describe, it, expect, beforeAll } from 'vitest'
import { mkdtemp, mkdir } from 'node:fs/promises'
import { execSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createGuardHandler, branchOf } from '../src/host/index.js'
import { Journal } from '../src/host/journal.js'
import { PermissionPolicy } from '../src/host/permission-policy.js'
import { DEFAULT_CONFIG } from '../src/host/config.js'

// Task 1 (fix guard-protection-precision): resolve the repo the command actually
// runs in (cd / git -C), instead of always using the session cwd. Regression for:
// session cwd = workspace root on master, command cd's into a feature-branch repo.

describe('sandbox: command working-dir resolution', () => {
  it('getCommandWorkingDir extracts an absolute cd target from a chained command', async () => {
    const { getCommandWorkingDir } = await import('../src/host/sandbox.js')
    expect(getCommandWorkingDir('cd /work/repo && git push -u origin feat/x 2>&1 | tail -5', '/work')).toBe('/work/repo')
  })
  it('getCommandWorkingDir resolves a relative cd against the session cwd', async () => {
    const { getCommandWorkingDir } = await import('../src/host/sandbox.js')
    expect(getCommandWorkingDir('cd packages/jobs && git push -u origin feat/x', '/work')).toBe('/work/packages/jobs')
  })
  it('getCommandWorkingDir handles git -C form', async () => {
    const { getCommandWorkingDir } = await import('../src/host/sandbox.js')
    expect(getCommandWorkingDir('git -C /work/repo push origin feat/x', '/work')).toBe('/work/repo')
  })
  it('getCommandWorkingDir falls back to the session cwd when no cd target is present', async () => {
    const { getCommandWorkingDir } = await import('../src/host/sandbox.js')
    expect(getCommandWorkingDir('git push origin feat/x', '/work')).toBe('/work')
    expect(getCommandWorkingDir(undefined, '/work')).toBe('/work')
  })
  it('resolveCurrentBranch asks the branch of the command target, not the session cwd', async () => {
    const { resolveCurrentBranch } = await import('../src/host/sandbox.js')
    const branchOfStub = (dir: string) => (dir === '/work/repo' ? 'feat/x' : dir === '/work' ? 'master' : undefined)
    expect(resolveCurrentBranch('cd /work/repo && git push -u origin feat/x', '/work', branchOfStub)).toBe('feat/x')
    expect(resolveCurrentBranch('git push origin feat/x', '/work', branchOfStub)).toBe('master') // no cd -> session cwd
    expect(resolveCurrentBranch('cd /nowhere && git push', '/work', branchOfStub)).toBeUndefined() // target not a repo
  })
})

describe('guard handler: branch-scope end-to-end (real git repos)', () => {
  let rootRepo: string
  let featRepo: string
  beforeAll(async () => {
    const dir = await mkdtemp(join(tmpdir(), 'g-scope-'))
    rootRepo = join(dir, 'root') // session cwd: a repo checked out on master
    featRepo = join(dir, 'jobs') // command target: a feature-branch repo
    await mkdir(rootRepo)
    await mkdir(featRepo)
    execSync('git init -q -b master', { cwd: rootRepo })
    execSync('git -c user.name=t -c user.email=t@t commit --allow-empty -q -m init', { cwd: rootRepo })
    execSync('git init -q -b fix/jobs-x', { cwd: featRepo })
    execSync('git -c user.name=t -c user.email=t@t commit --allow-empty -q -m init', { cwd: featRepo })
  })

  async function handlerFor(dir: string) {
    return createGuardHandler({
      journal: new Journal(dir),
      policy: new PermissionPolicy({}),
      readConfig: async () => DEFAULT_CONFIG,
      requestApproval: async () => 'rejected',
      branchOf,
    })
  }

  it('feature push with cd target passes even though the session cwd repo sits on master', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'g-handler-'))
    // Hermetic: built-in guard config (git protection enabled) instead of
    // whatever the ambient ~/.dsh settings.json currently says.
    const handler = await handlerFor(dir)
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
    const dir = await mkdtemp(join(tmpdir(), 'g-handler2-'))
    const handler = await handlerFor(dir)
    const payload: any = {
      name: 'bash',
      agent: { session: { header: { cwd: rootRepo } } },
      arguments: { command: `cd ${featRepo} && git push origin master` },
    }
    const res = await handler(payload, async () => ({ kind: 'allow' as const }))
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toMatch(/git\.push\.protected/)
  })
})
