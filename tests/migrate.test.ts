import { describe, it, expect } from 'vitest'
import { mkdtemp, mkdir, writeFile, readFile, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Journal, journalDir, journalPath } from '../src/host/journal.js'
import { retireLegacyStore } from '../src/host/migrate.js'

describe('retireLegacyStore', () => {
  it('moves the legacy ticket store out of the active path and journals it', async () => {
    const home = await mkdtemp(join(tmpdir(), 'm-'))
    await mkdir(journalDir(home), { recursive: true, mode: 0o700 })
    await writeFile(join(journalDir(home), 'pending.json'), '{"requests":[]}', { mode: 0o600 })
    const journal = new Journal(home)
    const res = await retireLegacyStore(journal, home)
    expect(res.moved).toBe(true)
    const dest = join(journalDir(home), 'legacy-pending.json')
    expect((await readFile(dest, 'utf8')).length).toBeGreaterThan(0)
    expect((await stat(dest)).mode & 0o777).toBe(0o600)
    expect((await readFile(journalPath(home), 'utf8'))).toContain('guard.migration')
  })

  it('is a no-op when there is nothing to retire', async () => {
    const home = await mkdtemp(join(tmpdir(), 'm-'))
    expect((await retireLegacyStore(new Journal(home), home)).moved).toBe(false)
  })
})
