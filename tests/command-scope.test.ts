import { describe, it, expect } from 'vitest'

// Task 3 (fix/guard-protection-precision): match protected ops on the executed
// command surface only. Text that merely MENTIONS a protected phrase — echo
// strings, script bodies, tool description args, non-shell tool content — must
// not mint a guard ticket. Regression class observed live: six analysis calls
// (node -e scripts, memory writes, write tool) were blocked purely for quoting
// the phrasings being investigated.

const PUBLISH = ['pnpm', 'publish'].join(' ')

describe('command-surface matching', () => {
  it('extractCommandText returns the command field of shell-style args', async () => {
    const { extractCommandText } = await import('../src/host/sandbox.js')
    expect(extractCommandText({ command: 'git push origin master', description: 'x' })).toBe('git push origin master')
  })
  it('extractCommandText passes through bare string args', async () => {
    const { extractCommandText } = await import('../src/host/sandbox.js')
    expect(extractCommandText('git push origin master')).toBe('git push origin master')
  })
  it('extractCommandText returns undefined for non-shell tool args', async () => {
    const { extractCommandText } = await import('../src/host/sandbox.js')
    expect(extractCommandText({ file_path: '/a', content: 'mention git push' })).toBeUndefined()
    expect(extractCommandText(undefined)).toBeUndefined()
  })

  it('a quoted mention of a protected phrase inside echo is not a push', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    expect(isBlockedGitCommand('echo "git push origin master"', 'master')).toBe(false)
    expect(isBlockedGitCommand("echo 'git push origin master'", 'master')).toBe(false)
  })
  it('a master word in a later gh pr create segment does not block a feature push', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    expect(isBlockedGitCommand('cd /w && git push -u origin feat/x && gh pr create --base master --head feat/x --title t', 'feat/x')).toBe(false)
  })
  it('hard protections survive segmentation across && and pipes', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    expect(isBlockedGitCommand('cd /w && git push -u origin feat/x && gh pr merge 6 --merge', 'feat/x')).toBe(true)
    expect(isBlockedGitCommand('git push origin master 2>&1 | tail -5', 'feat/x')).toBe(true)
  })

  it('checkSandbox does not git-block a non-shell tool whose content mentions protected text', async () => {
    const { checkSandbox } = await import('../src/host/sandbox.js')
    const res = checkSandbox('write', { file_path: '/tmp/a', content: 'script mentions git push origin master' }, { cwd: '/tmp', currentBranch: 'master', approved: false })
    expect(res.blocked).toBe(false)
  })

  it('handler: phrasing in the description field neither blocks nor creates a ticket', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const { ApprovalStore } = await import('../src/host/approval-store.js')
    const { PendingStore } = await import('../src/host/pending.js')
    const { PermissionPolicy } = await import('../src/host/permission-policy.js')
    const { mkdtemp } = await import('node:fs/promises')
    const { tmpdir } = await import('node:os')
    const { join } = await import('node:path')
    const dir = await mkdtemp(join(tmpdir(), 'cs-'))
    const pending = new PendingStore(dir)
    const handler = createGuardHandler(new ApprovalStore(dir), new PermissionPolicy({}), pending, async () => ({}))
    const payload: any = { name: 'bash', arguments: { command: 'true', description: 'mentions git push origin master and ' + PUBLISH } }
    let nextCalled = false
    await handler(payload, async () => { nextCalled = true; return { kind: 'allow' as const } })
    expect(nextCalled).toBe(true)
    expect(await pending.list()).toHaveLength(0)
  })

  it('handler: quoted echo of a protected phrase is allowed', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const { ApprovalStore } = await import('../src/host/approval-store.js')
    const { PendingStore } = await import('../src/host/pending.js')
    const { PermissionPolicy } = await import('../src/host/permission-policy.js')
    const { mkdtemp } = await import('node:fs/promises')
    const { tmpdir } = await import('node:os')
    const { join } = await import('node:path')
    const dir = await mkdtemp(join(tmpdir(), 'cs2-'))
    const handler = createGuardHandler(new ApprovalStore(dir), new PermissionPolicy({}), new PendingStore(dir), async () => ({}))
    const payload: any = { name: 'bash', arguments: { command: 'echo "git push origin master"' } }
    let nextCalled = false
    await handler(payload, async () => { nextCalled = true; return { kind: 'allow' as const } })
    expect(nextCalled).toBe(true)
  })

  it('handler: a genuine master push stays blocked', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const { ApprovalStore } = await import('../src/host/approval-store.js')
    const { PendingStore } = await import('../src/host/pending.js')
    const { PermissionPolicy } = await import('../src/host/permission-policy.js')
    const { mkdtemp } = await import('node:fs/promises')
    const { tmpdir } = await import('node:os')
    const { join } = await import('node:path')
    const dir = await mkdtemp(join(tmpdir(), 'cs3-'))
    const handler = createGuardHandler(new ApprovalStore(dir), new PermissionPolicy({}), new PendingStore(dir), async () => ({}))
    const payload: any = { name: 'bash', arguments: { command: 'git push origin master' } }
    let err: any
    try { await handler(payload, async () => ({ kind: 'allow' as const })) } catch (e) { err = e }
    expect(err).toBeDefined()
  })
})