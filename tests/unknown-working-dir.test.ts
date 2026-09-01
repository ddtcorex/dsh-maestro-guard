import { describe, it, expect } from 'vitest'

// Residual false-positive class from the audit: `cd` / `git -C` targets that
// CANNOT be parsed (quoted, $VAR, wildcard) must not fall back to the session
// cwd — otherwise a session whose cwd repo sits on master keeps blocking
// feature pushes written as `cd "$REPO" && git push ...`.

describe('command working-dir: unresolved cd targets', () => {
  it('getCommandWorkingDir returns undefined for a quoted cd target', async () => {
    const { getCommandWorkingDir } = await import('../src/host/sandbox.js')
    expect(getCommandWorkingDir('cd "$REPO" && git push -u origin feat/x', '/work')).toBeUndefined()
  })
  it('getCommandWorkingDir returns undefined for a $VAR cd target', async () => {
    const { getCommandWorkingDir } = await import('../src/host/sandbox.js')
    expect(getCommandWorkingDir('cd $REPO_DIR && git push -u origin feat/x', '/work')).toBeUndefined()
  })
  it('getCommandWorkingDir still resolves a plain absolute cd', async () => {
    const { getCommandWorkingDir } = await import('../src/host/sandbox.js')
    expect(getCommandWorkingDir('cd /work/repo && git push -u origin feat/x', '/work')).toBe('/work/repo')
  })
  it('getCommandWorkingDir still falls back to cwd only when NO cd verb is present', async () => {
    const { getCommandWorkingDir } = await import('../src/host/sandbox.js')
    expect(getCommandWorkingDir('git push origin feat/x', '/work')).toBe('/work')
  })
  it('resolveCurrentBranch makes no protected-branch assumption for an unresolved cd (session cwd on master)', async () => {
    const { resolveCurrentBranch } = await import('../src/host/sandbox.js')
    const branchOf = (dir: string) => (dir === '/work' ? 'master' : 'feat/x')
    expect(resolveCurrentBranch('cd "$REPO" && git push -u origin feat/x', '/work', branchOf)).toBeUndefined()
  })
  it('handler: quoted-cd feature push passes even though the session cwd repo is on master', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const { ApprovalStore } = await import('../src/host/approval-store.js')
    const { PendingStore } = await import('../src/host/pending.js')
    const { PermissionPolicy } = await import('../src/host/permission-policy.js')
    const { mkdtemp } = await import('node:fs/promises')
    const { tmpdir } = await import('node:os')
    const { join } = await import('node:path')
    const dir = await mkdtemp(join(tmpdir(), 'ud-'))
    const handler = createGuardHandler(new ApprovalStore(dir), new PermissionPolicy({}), new PendingStore(dir), async () => ({}))
    // session cwd would resolve to master here; the quoted target must not inherit it
    const payload: any = { name: 'bash', cwd: '/work', arguments: { command: 'cd "$REPO" && git push -u origin feat/x', description: 'push feature branch' } }
    let nextCalled = false
    const res = await handler(payload, async () => { nextCalled = true; return { kind: 'allow' as const } })
    expect(nextCalled).toBe(true)
    expect(res).toEqual({ kind: 'allow' })
  })
})