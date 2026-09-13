import { describe, it, expect } from 'vitest'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createGuardHandler } from '../src/host/index.js'
import { Journal } from '../src/host/journal.js'
import { PermissionPolicy } from '../src/host/permission-policy.js'
import { DEFAULT_CONFIG } from '../src/host/config.js'
import type { AskOutcome } from '../src/host/journal.js'

// Task 3 (fix/guard-protection-precision): match protected ops on the executed
// command surface only. Text that merely MENTIONS a protected phrase — echo
// strings, script bodies, tool description args, non-shell tool content — must
// not be gated. Regression class observed live: six analysis calls (node -e
// scripts, memory writes, write tool) were blocked purely for quoting the
// phrasings being investigated.
//
// Task A4 replaced the ticket flow with the native ask, so the handler cases
// below assert on the returned decision instead of on a thrown Guard error.

const PUBLISH = ['pnpm', 'publish'].join(' ')

async function handler(outcome: AskOutcome = 'rejected') {
  const dir = await mkdtemp(join(tmpdir(), 'cs-'))
  return createGuardHandler({
    journal: new Journal(dir),
    policy: new PermissionPolicy({}),
    readConfig: async () => DEFAULT_CONFIG,
    requestApproval: async () => outcome,
    branchOf: () => 'master',
  })
}

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

  it('handler: phrasing in the description field neither blocks nor is gated', async () => {
    const h = await handler()
    const payload: any = { name: 'bash', arguments: { command: 'true', description: 'mentions git push origin master and ' + PUBLISH } }
    let nextCalled = false
    const res = await h(payload, async () => { nextCalled = true; return { kind: 'allow' as const } })
    expect(nextCalled).toBe(true)
    expect(res).toEqual({ kind: 'allow' })
  })

  it('handler: quoted echo of a protected phrase is allowed', async () => {
    const h = await handler()
    const payload: any = { name: 'bash', arguments: { command: 'echo "git push origin master"' } }
    let nextCalled = false
    const res = await h(payload, async () => { nextCalled = true; return { kind: 'allow' as const } })
    expect(nextCalled).toBe(true)
    expect(res).toEqual({ kind: 'allow' })
  })

  it('handler: a genuine master push is denied when the human rejects', async () => {
    const h = await handler('rejected')
    const payload: any = { name: 'bash', arguments: { command: 'git push origin master' } }
    const res = await h(payload, async () => ({ kind: 'allow' as const }))
    expect(res.kind).toBe('deny')
    expect(String((res as any).reason)).toContain('git.push.protected')
  })
})
