import { describe, it, expect } from 'vitest'

// Release-tag pushes bypassed git protection: `git push origin v0.2.1` /
// `git push origin refs/tags/v0.2.1` were not caught (only master/main branch
// words were), while the workspace rule requires explicit human approval before
// tagging/releasing — a pushed version tag triggers the CI publish workflow.

describe('sandbox: release-tag push protection', () => {
  it('blocks an explicit version-tag refspec', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    expect(isBlockedGitCommand('git push origin v0.2.1', 'feat/x', ['master', 'main'])).toBe(true)
  })
  it('blocks refs/tags/ refspecs', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    expect(isBlockedGitCommand('git push origin refs/tags/v0.2.1', 'feat/x', ['master', 'main'])).toBe(true)
  })
  it('blocks bare numeric tags and prereleases', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    expect(isBlockedGitCommand('git push origin 1.2.3', 'feat/x', ['master', 'main'])).toBe(true)
    expect(isBlockedGitCommand('git push origin v0.2.1-rc.2', 'feat/x', ['master', 'main'])).toBe(true)
  })
  it('does not block branches whose name merely contains a dotted number', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    expect(isBlockedGitCommand('git push origin feat/1.2.3', 'feat/x', ['master', 'main'])).toBe(false)
    expect(isBlockedGitCommand('git push -u origin feat/jobs-rpc-result-shape', 'feat/x', ['master', 'main'])).toBe(false)
  })
  it('hard rules are unchanged: master push and gh release stay blocked', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    expect(isBlockedGitCommand('git push origin master', 'feat/x', ['master', 'main'])).toBe(true)
    expect(isBlockedGitCommand('gh release create v0.2.1', 'feat/x', ['master', 'main'])).toBe(true)
  })
})