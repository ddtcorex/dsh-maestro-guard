import { describe, it, expect } from 'vitest'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import { isBlockedGitCommand } from '../src/host/sandbox.js'

// Task 5: guard blocks ~/.dsh/.credentials.yaml and pnpm publish without APPROVED
// TDD RED phase: these imports will fail until src/host/sandbox.ts is implemented

describe('sandbox: credential path blocking', () => {
  it('blocks ~/.dsh/.credentials.yaml via guard', async () => {
    const { guard } = await import('../src/host/sandbox.js')
    expect(guard('~/.dsh/.credentials.yaml')).toBe(false)
  })
  it('blocks expanded homedir credentials path', async () => {
    const { guard, isBlockedPath } = await import('../src/host/sandbox.js')
    const abs = join(homedir(), '.dsh', '.credentials.yaml')
    expect(isBlockedPath(abs)).toBe(true)
    expect(guard(abs)).toBe(false)
  })
  it('blocks .cloudflared paths', async () => {
    const { isBlockedPath, guard } = await import('../src/host/sandbox.js')
    expect(isBlockedPath('~/.cloudflared/cert.pem')).toBe(true)
    expect(guard('~/.cloudflared/config.yml')).toBe(false)
  })
  it('allows safe paths', async () => {
    const { isBlockedPath, guard } = await import('../src/host/sandbox.js')
    expect(isBlockedPath('/tmp/safe/file.txt')).toBe(false)
    expect(guard('/tmp/safe/file.txt')).toBe(true)
    expect(isBlockedPath(join(tmpdir(), 'my-project/file.ts'))).toBe(false)
  })
})

describe('sandbox: publish blocking', () => {
  it('blocks pnpm publish without APPROVED', async () => {
    const { guard, isPublishBlocked, isBlockedCommand } = await import('../src/host/sandbox.js')
    // simple guard string check
    expect(guard('pnpm publish')).toBe(false)
    expect(isBlockedCommand('pnpm publish --access public')).toBe(true)
    expect(isPublishBlocked('pnpm publish --access public', false)).toBe(true)
  })
  it('blocks npm publish without APPROVED', async () => {
    const { isPublishBlocked } = await import('../src/host/sandbox.js')
    expect(isPublishBlocked('npm publish', false)).toBe(true)
  })
  it('allows publish when APPROVED', async () => {
    const { isPublishBlocked, guard } = await import('../src/host/sandbox.js')
    expect(isPublishBlocked('pnpm publish', true)).toBe(false)
    // guard with approved flag true should allow
    expect(guard('pnpm publish', true as any)).toBe(true)
    expect(guard('npm publish', true as any)).toBe(true)
  })
  it('does not block non-publish pnpm commands', async () => {
    const { isPublishBlocked, isBlockedCommand } = await import('../src/host/sandbox.js')
    expect(isPublishBlocked('pnpm install', false)).toBe(false)
    expect(isBlockedCommand('pnpm test')).toBe(false)
    expect(isPublishBlocked('pnpm run build', false)).toBe(false)
  })
})

describe('sandbox: cwd containment for maestro file tools', () => {
  it('blocks maestro_read_file outside cwd', async () => {
    const { isOutsideCwd, checkSandbox } = await import('../src/host/sandbox.js')
    const cwd = join(tmpdir(), 'proj-cwd-test')
    const outside = join(homedir(), '.dsh', '.credentials.yaml')
    expect(isOutsideCwd(outside, cwd)).toBe(true)
    expect(isOutsideCwd(join(cwd, 'src/file.ts'), cwd)).toBe(false)
    // checkSandbox should block when path outside cwd or credential path
    const blocked = checkSandbox('maestro_read_file', { path: outside }, { cwd })
    expect(blocked.blocked).toBe(true)
    const allowed = checkSandbox('maestro_read_file', { path: join(cwd, 'README.md') }, { cwd })
    expect(allowed.blocked).toBe(false)
  })
  it('blocks maestro_write_file outside cwd', async () => {
    const { checkSandbox } = await import('../src/host/sandbox.js')
    const cwd = '/tmp/workspace/my-project'
    const outside = '/etc/passwd'
    expect(checkSandbox('maestro_write_file', { path: outside }, { cwd }).blocked).toBe(true)
    expect(checkSandbox('maestro_write_file', { path: '/tmp/workspace/my-project/out.txt' }, { cwd }).blocked).toBe(false)
  })
  it('guard handler integration: blocks credentials via handler', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const { ApprovalStore } = await import('../src/host/approval-store.js')
    const { PermissionPolicy } = await import('../src/host/permission-policy.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-sandbox-'))
    const store = new ApprovalStore(dir)
    const policy = new PermissionPolicy({})
    const handler = createGuardHandler(store, policy)
    const payload: any = { name: 'maestro_read_file', arguments: { path: '~/.dsh/.credentials.yaml' } }
    await expect(handler(payload, async () => ({ kind: 'allow' as const }))).rejects.toThrow(/credentials|blocked|denied/i)
  })
  it('guard handler integration: blocks pnpm publish without approval', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const { ApprovalStore } = await import('../src/host/approval-store.js')
    const { PermissionPolicy } = await import('../src/host/permission-policy.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-publish-'))
    const store = new ApprovalStore(dir)
    const policy = new PermissionPolicy({})
    const handler = createGuardHandler(store, policy)
    const payload: any = { name: 'exec', arguments: { command: 'pnpm publish --access public' } }
    await expect(handler(payload, async () => ({ kind: 'allow' as const }))).rejects.toThrow(/publish|approval|blocked|denied/i)
  })
  it('guard handler: allows publish when APPROVED', async () => {
    const { createGuardHandler } = await import('../src/host/index.js')
    const { ApprovalStore } = await import('../src/host/approval-store.js')
    const { PermissionPolicy } = await import('../src/host/permission-policy.js')
    const dir = await mkdtemp(join(tmpdir(), 'g-publish-ok-'))
    const store = new ApprovalStore(dir)
    await store.approve('publish')
    const policy = new PermissionPolicy({})
    const handler = createGuardHandler(store, policy)
    const payload: any = { name: 'exec', arguments: { command: 'pnpm publish --access public' } }
    const result = await handler(payload, async () => ({ kind: 'allow' as const }))
    expect(result).toEqual({ kind: 'allow' })
  })
})

describe('sandbox: git protection', () => {
  it('blocks git push origin master', async () => {
    expect(isBlockedGitCommand('git push origin master')).toBe(true)
  })
  it('blocks bare git push when on master', async () => {
    expect(isBlockedGitCommand('git push', 'master')).toBe(true)
  })
  it('allows git push origin feat/x', async () => {
    expect(isBlockedGitCommand('git push origin feat/x', 'feat/x')).toBe(false)
  })
  it('blocks gh pr merge', async () => {
    expect(isBlockedGitCommand('gh pr merge 123')).toBe(true)
  })
  it('blocks gh release create', async () => {
    expect(isBlockedGitCommand('gh release create v1.2.3')).toBe(true)
  })
  it('blocks DELETE protection', async () => {
    expect(isBlockedGitCommand('gh api -X DELETE repos/ddtcorex/foo/branches/master/protection')).toBe(true)
  })
})
