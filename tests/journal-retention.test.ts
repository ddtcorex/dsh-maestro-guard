import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { Journal, journalDir, journalPath } from '../src/host/journal.js'

/** A fixed clock: the archives below are all dated in August 2026. */
const NOW = Date.parse('2026-09-14T00:00:00Z')
/** The same day, but NOT at midnight: a `retainDays: 0` window then really is empty. */
const NOON = Date.parse('2026-09-14T12:00:00Z')
const ORIGINAL_DSH_HOME = process.env.DSH_HOME

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'jr-'))
}

async function lines(dir: string): Promise<string[]> {
  const raw = await readFile(journalPath(dir), 'utf8').catch(() => '')
  return raw.split('\n').filter(Boolean)
}

/**
 * The store lib is only reached by the boot-wiring test at the bottom; nothing
 * else in this suite reads a config, so the mock stays inert for them.
 */
const store = vi.hoisted(() => ({ guard: undefined as Record<string, unknown> | undefined }))

vi.mock('@ddtcorex/dsh-maestro-config-lib', () => ({
  load: async () => ({ version: 1, domains: { guard: store.guard } }),
}))

/**
 * The two timing seams no real clock can produce deterministically: an append
 * that lands between a roll's rename and the next roll's free-path probe, and a
 * chmod that fails after a successful rename. Every switch is off by default, so
 * the rest of the suite drives the real filesystem.
 */
const fsCtl = vi.hoisted(() => ({
  race: false,
  renames: 0,
  delayMs: 0,
  recreate: null as string | null,
  failChmod: false,
}))

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  return {
    ...actual,
    rename: async (from: any, to: any) => {
      if (!fsCtl.race) return actual.rename(from, to)
      const n = (fsCtl.renames += 1)
      // Hold the FIRST rename so the second overlapping call is guaranteed to
      // probe its free archive path before the destination exists.
      if (n === 1 && fsCtl.delayMs > 0) await new Promise((r) => setTimeout(r, fsCtl.delayMs))
      await actual.rename(from, to)
      // …then simulate the concurrent append that re-creates the live file.
      if (n === 1 && fsCtl.recreate !== null) await actual.writeFile(from, fsCtl.recreate)
    },
    chmod: async (p: any, mode: any) => {
      if (fsCtl.failChmod) throw new Error('chmod denied')
      return actual.chmod(p, mode)
    },
  }
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  fsCtl.race = false
  fsCtl.renames = 0
  fsCtl.delayMs = 0
  fsCtl.recreate = null
  fsCtl.failChmod = false
  store.guard = undefined
  if (ORIGINAL_DSH_HOME === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = ORIGINAL_DSH_HOME
})

/**
 * Boot the real guard plugin on a fake Cordis context and hand back the
 * `tools/pre-execute` listener it registered. `effect` runs its body at once,
 * exactly like the fiber does, and keeps the returned disposer.
 */
async function bootGuard(): Promise<{ call: (exec: unknown, next: () => Promise<unknown>) => Promise<any>; dispose: () => void }> {
  const guard = (await import('../src/host/index.js')).default
  let listener: ((exec: unknown, next: () => Promise<unknown>) => Promise<any>) | undefined
  const disposers: Array<() => void> = []
  const ctx: any = {
    get: () => undefined,
    on: (event: string, fn: any) => {
      if (event === 'tools/pre-execute') listener = fn
      return () => { listener = undefined }
    },
    effect: (fn: () => unknown) => {
      const disposer = fn()
      if (typeof disposer === 'function') disposers.push(disposer as () => void)
      return () => {}
    },
    tools: { register: () => () => {} },
  }
  await guard.apply(ctx)
  return {
    call: (exec, next) => listener!(exec, next),
    dispose: () => { for (const d of disposers) d() },
  }
}

describe('journal counters and retention', () => {
  it('flushes allow counters as one aggregate line', async () => {
    const dir = await tempDir()
    const j = new Journal(dir)
    j.count('', 'allow')
    j.count('', 'allow')
    j.count('git.push.protected', 'ask')
    await j.flushCounters()
    const entry = JSON.parse((await readFile(journalPath(dir), 'utf8')).trim().split('\n').pop()!)
    expect(entry).toMatchObject({ rule: 'counters', tier: 'allow', target: 'counters' })
    expect(entry.note).toBe('allow=2,ask=1')
    // The aggregate is an ordinary entry, so it inherits the journal choke point.
    expect(entry.redacted).toBe(true)
    expect(typeof entry.ts).toBe('string')
    // …and the map is cleared, so an idle flush writes nothing at all.
    await j.flushCounters()
    expect(await lines(dir)).toHaveLength(1)
  })

  it('rotates the current file into a dated archive', async () => {
    const dir = await tempDir()
    const j = new Journal(dir, () => NOW)
    await j.append({ tool: 'bash', rule: 'r', tier: 'ask', target: 'x', outcome: 'granted' })
    const removed = await j.rotate()
    // Nothing was beyond the retention window: the new archive is not a removal.
    expect(removed).toEqual([])
    const files = await readdir(journalDir(dir))
    expect(files.some((f) => f.startsWith('journal-2026-09-14'))).toBe(true)
    // The live file was rolled away, not copied.
    expect(files).not.toContain('journal.jsonl')
    const archived = JSON.parse((await readFile(join(journalDir(dir), files.find((f) => f.startsWith('journal-'))!), 'utf8')).trim())
    expect(archived).toMatchObject({ rule: 'r', tier: 'ask', outcome: 'granted' })
  })

  it('applies the retention window', async () => {
    const dir = await tempDir()
    const archives = journalDir(dir)
    await mkdir(archives, { recursive: true })
    for (let day = 1; day <= 20; day++) {
      await writeFile(join(archives, `journal-2026-08-${String(day).padStart(2, '0')}.jsonl`), '{}\n')
    }
    const j = new Journal(dir, () => NOW)
    const removed = await j.rotate({ retainFiles: 14 })
    // Now = 2026-09-14, so the 30-day window reaches back to 2026-08-15: the
    // six archives outside BOTH windows go, the newest 14 stay.
    expect(removed.map((p) => basename(p))).toEqual([
      'journal-2026-08-01.jsonl',
      'journal-2026-08-02.jsonl',
      'journal-2026-08-03.jsonl',
      'journal-2026-08-04.jsonl',
      'journal-2026-08-05.jsonl',
      'journal-2026-08-06.jsonl',
    ])
    expect((await readdir(archives)).filter((f) => f.startsWith('journal-'))).toHaveLength(14)
    for (const p of removed) await expect(readFile(p, 'utf8')).rejects.toThrow()
  })

  it('keeps the newer of the file and day windows', async () => {
    const dir = await tempDir()
    const archives = journalDir(dir)
    await mkdir(archives, { recursive: true })
    for (let day = 7; day <= 20; day++) {
      await writeFile(join(archives, `journal-2026-08-${String(day).padStart(2, '0')}.jsonl`), '{}\n')
    }
    const j = new Journal(dir, () => NOW)
    // retainFiles = 0 empties the file window, but the 30-day window still
    // reaches 2026-08-15 — the newer of the two windows is the one that keeps.
    const removed = await j.rotate({ retainFiles: 0, retainDays: 30 })
    expect(removed.map((p) => basename(p))).toEqual([
      'journal-2026-08-07.jsonl',
      'journal-2026-08-08.jsonl',
      'journal-2026-08-09.jsonl',
      'journal-2026-08-10.jsonl',
      'journal-2026-08-11.jsonl',
      'journal-2026-08-12.jsonl',
      'journal-2026-08-13.jsonl',
      'journal-2026-08-14.jsonl',
    ])
    expect((await readdir(archives)).filter((f) => f.startsWith('journal-'))).toHaveLength(6)
  })

  it('reads the newest archive and the live file, newest entry first', async () => {
    const dir = await tempDir()
    const j = new Journal(dir, () => NOW)
    await j.append({ tool: 'bash', rule: 'old', tier: 'journal', target: 'a', outcome: 'passed' })
    await j.rotate()
    await j.append({ tool: 'bash', rule: 'new', tier: 'ask', target: 'b', outcome: 'granted' })
    const entries = await j.read()
    expect(entries.map((e) => e.rule)).toEqual(['new', 'old'])
    expect(Date.parse(entries[0].ts)).toBeGreaterThanOrEqual(Date.parse(entries[1].ts))
    expect((await j.read(1)).map((e) => e.rule)).toEqual(['new'])
    // An empty journal location is not an error.
    expect(await new Journal(await tempDir()).read()).toEqual([])
  })

  it('flushes on an interval and stops on dispose', async () => {
    const dir = await tempDir()
    const j = new Journal(dir)
    vi.useFakeTimers()
    const flush = vi.spyOn(j, 'flushCounters').mockResolvedValue(undefined)
    const stop = j.startFlush(1000)
    vi.advanceTimersByTime(3500)
    expect(flush).toHaveBeenCalledTimes(3)
    stop()
    stop() // idempotent
    vi.advanceTimersByTime(3500)
    expect(flush).toHaveBeenCalledTimes(3)
  })

  it('never prunes the archive it just created', async () => {
    const dir = await tempDir()
    const archives = journalDir(dir)
    await mkdir(archives, { recursive: true })
    await writeFile(join(archives, 'journal-2026-01-01.jsonl'), '{"rule":"ancient"}\n')
    const j = new Journal(dir, () => NOON)
    await j.append({ tool: 'bash', rule: 'rolled', tier: 'journal', target: 'a', outcome: 'passed' })
    // Both windows are empty: without the guard the call would unlink the whole
    // rolled history it just created, in the same call.
    const removed = await j.rotate({ retainFiles: 0, retainDays: 0 })
    expect(removed.map((p) => basename(p))).toEqual(['journal-2026-01-01.jsonl'])
    const files = await readdir(archives)
    expect(files).toContain('journal-2026-09-14.jsonl')
    expect(await readFile(join(archives, 'journal-2026-09-14.jsonl'), 'utf8')).toContain('"rule":"rolled"')
    await expect(readFile(join(archives, 'journal-2026-01-01.jsonl'), 'utf8')).rejects.toThrow()
  })

  it('serializes overlapping rotations so neither archive is lost', async () => {
    const dir = await tempDir()
    const archives = journalDir(dir)
    const j = new Journal(dir, () => NOON)
    await j.append({ tool: 'bash', rule: 'early', tier: 'journal', target: 'a', outcome: 'passed' })
    fsCtl.race = true
    fsCtl.renames = 0
    fsCtl.delayMs = 30
    fsCtl.recreate = '{"rule":"late"}\n'
    const first = j.rotate()
    const second = j.rotate()
    const results = await Promise.all([first, second])
    // Default retention removes nothing, so both calls report an empty removal.
    expect(results.flat()).toEqual([])
    const rolled = (await readdir(archives)).filter((f) => f !== 'journal.jsonl')
    expect(rolled).toHaveLength(2)
    const payloads = (await Promise.all(rolled.map((f) => readFile(join(archives, f), 'utf8')))).join('')
    expect(payloads).toContain('"rule":"early"')
    expect(payloads).toContain('"rule":"late"')
    // `read()` reaches the newest archive only; both archives on disk is the
    // no-data-loss contract this test is about.
    expect((await j.read()).map((e) => e.rule)).toEqual(['late'])
  })

  it('keeps the collision fallback archive readable', async () => {
    const dir = await tempDir()
    const archives = journalDir(dir)
    await mkdir(archives, { recursive: true })
    for (let seq = 0; seq < 1000; seq++) {
      const name = seq === 0 ? 'journal-2026-09-14.jsonl' : `journal-2026-09-14-${seq}.jsonl`
      await writeFile(join(archives, name), '{}\n')
    }
    // A non-integer clock is what exposes the raw-interpolation fallback name.
    const j = new Journal(dir, () => NOON + 0.5)
    await j.append({ tool: 'bash', rule: 'fallback', tier: 'journal', target: 'a', outcome: 'passed' })
    await j.rotate({ retainFiles: 100_000, retainDays: 100_000 })
    expect((await j.read()).some((e) => e.rule === 'fallback')).toBe(true)
  })

  it('still prunes when the archive chmod fails', async () => {
    const dir = await tempDir()
    const archives = journalDir(dir)
    await mkdir(archives, { recursive: true })
    await writeFile(join(archives, 'journal-2026-01-01.jsonl'), '{}\n')
    const j = new Journal(dir, () => NOON)
    await j.append({ tool: 'bash', rule: 'rolled', tier: 'journal', target: 'a', outcome: 'passed' })
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    fsCtl.failChmod = true
    const removed = await j.rotate({ retainFiles: 0, retainDays: 0 })
    expect(removed.map((p) => basename(p))).toEqual(['journal-2026-01-01.jsonl'])
    // A failed chmod is logged, but it does not abandon the rotation outcome.
    expect(errors.mock.calls.some((c) => String(c[0]).includes('chmod'))).toBe(true)
    const files = await readdir(archives)
    expect(files.filter((f) => f.startsWith('journal-2026-'))).toHaveLength(1)
    expect(files).toContain('journal-2026-09-14.jsonl')
  })

  it('writes nothing and starts no flush when journal.enabled is false', async () => {
    const dir = await tempDir()
    const j = new Journal(dir, () => NOW, { enabled: false })
    await j.append({ tool: 'bash', rule: 'r', tier: 'journal', target: 'a', outcome: 'passed' })
    expect(existsSync(journalPath(dir))).toBe(false)
    j.count('r', 'allow')
    await j.flushCounters()
    expect(existsSync(journalPath(dir))).toBe(false)
    vi.useFakeTimers()
    const flush = vi.spyOn(j, 'flushCounters').mockResolvedValue(undefined)
    const stop = j.startFlush(1000)
    vi.advanceTimersByTime(3000)
    expect(flush).not.toHaveBeenCalled()
    stop()
  })

  it('makes count a no-op when allowCounters is false', async () => {
    const dir = await tempDir()
    const j = new Journal(dir, () => NOW, { allowCounters: false })
    j.count('r', 'allow')
    await j.flushCounters()
    expect(existsSync(journalPath(dir))).toBe(false)
    // Only the counters are off: an ordinary journal-tier append still lands.
    await j.append({ tool: 'bash', rule: 'r', tier: 'journal', target: 'a', outcome: 'passed' })
    expect(await lines(dir)).toHaveLength(1)
  })

  it('uses the constructor retention knobs as the rotate defaults', async () => {
    const dir = await tempDir()
    const archives = journalDir(dir)
    await mkdir(archives, { recursive: true })
    for (let day = 1; day <= 5; day++) {
      await writeFile(join(archives, `journal-2026-08-${String(day).padStart(2, '0')}.jsonl`), '{}\n')
    }
    const j = new Journal(dir, () => NOW, { retainFiles: 2, retainDays: 0 })
    const removed = await j.rotate()
    expect(removed.map((p) => basename(p))).toEqual([
      'journal-2026-08-01.jsonl',
      'journal-2026-08-02.jsonl',
      'journal-2026-08-03.jsonl',
    ])
  })

  it('applies domains.guard.journal from the boot config', async () => {
    const home = await tempDir()
    process.env.DSH_HOME = home
    const exec = { name: 'danger-tool', args: {}, agent: { session: { id: 's1', header: { cwd: home } } } }
    const deny = async () => ({ kind: 'allow' as const })

    // Default document: the policy denial is journaled.
    store.guard = {}
    const live = await bootGuard()
    expect((await live.call(exec, deny)).kind).toBe('deny')
    expect(await lines(home)).toHaveLength(1)
    live.dispose()

    // `journal.enabled: false` reaches the boot Journal: the same denial writes nothing.
    const quietHome = await tempDir()
    process.env.DSH_HOME = quietHome
    store.guard = { journal: { enabled: false } }
    const quiet = await bootGuard()
    expect((await quiet.call(exec, deny)).kind).toBe('deny')
    expect(existsSync(journalPath(quietHome))).toBe(false)
    quiet.dispose()
  })
})
