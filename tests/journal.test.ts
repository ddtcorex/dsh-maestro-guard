import { describe, it, expect, vi } from 'vitest'
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Journal, journalPath } from '../src/host/journal.js'

describe('journal', () => {
  it('appends one JSON line per decision, mode 0600, redacted marker set', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'j-'))
    const j = new Journal(dir, () => 1_700_000_000_000)
    await j.append({ session: 's1', tool: 'bash', rule: 'git.push.protected', tier: 'ask',
      target: 'git push origin main', outcome: 'rejected', askMs: 1200 })
    const line = JSON.parse((await readFile(journalPath(dir), 'utf8')).trim())
    expect(line.rule).toBe('git.push.protected')
    expect(line.tier).toBe('ask')
    expect(line.redacted).toBe(true)
    expect(line.ts).toBe(new Date(1_700_000_000_000).toISOString())
    expect((await stat(journalPath(dir))).mode & 0o777).toBe(0o600)
  })

  it('never throws when the journal location is unusable', async () => {
    const base = await mkdtemp(join(tmpdir(), 'j-'))
    // A REGULAR FILE where the journal directory must go: mkdir(dirname(p), { recursive: true })
    // cannot succeed, so the write genuinely fails with EEXIST/ENOTDIR.
    await writeFile(join(base, 'dsh-maestro-guard'), 'not a directory', 'utf8')
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const j = new Journal(base)
      await expect(j.append({ tool: 'bash', rule: 'r', tier: 'deny', target: 'x' })).resolves.toBeUndefined()
      expect(spy).toHaveBeenCalledTimes(1)
    } finally {
      spy.mockRestore()
    }
  })

  it('never throws when the entry cannot be serialized', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'j-'))
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const j = new Journal(dir, () => 1_700_000_000_000)
      await expect(
        j.append({ tool: 'bash', rule: 'r', tier: 'journal', target: 'x', note: { big: 1n } as unknown as string }),
      ).resolves.toBeUndefined()
      expect(spy).toHaveBeenCalledTimes(1)
    } finally {
      spy.mockRestore()
    }
  })
})
