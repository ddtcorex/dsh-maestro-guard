import { describe, it, expect } from 'vitest'

// Defect found by the first real-session probe (guard v0.2.0): quoted DATA that
// spans the segment separators — an instruction prompt or heredoc-ish argument
// mentioning protected phrasings across newlines/&& — was fragmented by the
// &&/;|/\n split BEFORE the per-segment quote-strip, exposing the phrasings.
// Quote stripping must happen on the full command text first (as the supervisor
// self-kill guard does), then segment on the remaining separators.

describe('isBlockedGitCommand: quote-then-segment (multi-line quoted data)', () => {
  it('a multi-line quoted block mentioning protected phrasings is not a push', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    const data = 'pnpm dsh --profile x "TASK\n1) cd /tmp && git push -u origin feat/x\n2) cd /tmp && git push origin master\n4) cd /tmp && git push origin v1.0.0\ndo not retry"'
    expect(isBlockedGitCommand(data, 'feat/x', ['master', 'main'])).toBe(false)
  })
  it('multi-line quoted block mentioning a tag refspec stays data', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    const data = 'node -e "runOne()\nrunTwo()\ngit push origin v1.0.0\nend()"'
    expect(isBlockedGitCommand(data, 'feat/x', ['master', 'main'])).toBe(false)
  })
  it('real protected operations still block after the ordering change', async () => {
    const { isBlockedGitCommand } = await import('../src/host/sandbox.js')
    expect(isBlockedGitCommand('git push origin master', 'feat/x', ['master', 'main'])).toBe(true)
    expect(isBlockedGitCommand('cd /tmp && git push -u origin feat/x', 'feat/x', ['master', 'main'])).toBe(false)
    expect(isBlockedGitCommand('git push origin v1.0.0', 'feat/x', ['master', 'main'])).toBe(true)
    expect(isBlockedGitCommand('echo "git push origin master"', 'feat/x', ['master', 'main'])).toBe(false)
  })
})