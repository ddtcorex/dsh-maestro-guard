import { appendFile, chmod, mkdir, readFile, readdir, rename, stat, unlink } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { TIERS, type Tier } from './tiers.js'
import { redact } from './redact.js'

export type AskOutcome = 'granted' | 'rejected' | 'cancelled' | 'unavailable' | 'error'

export interface JournalEntry {
  ts: string
  session?: string
  tool: string
  rule: string
  tier: Tier
  target: string
  repo?: string
  branch?: string
  cwd?: string
  outcome?: AskOutcome | 'passed' | 'denied'
  askMs?: number
  redacted: true
  note?: string
}

/** Retention knobs. Count and age are BOTH windows; the larger one wins. */
export interface RotateOptions {
  /** Keep at least the newest N archive files (default 14). */
  retainFiles?: number
  /** Keep at least archives newer than N days (default 30). */
  retainDays?: number
}

/**
 * The journal block of `domains.guard`, read ONCE when the guard boots. These
 * are boot-time knobs: unlike the per-call rule config the handler re-reads on
 * every decision, changing them requires a host restart. Every field defaults
 * to the built-in behaviour (enabled, counters on, 14 files / 30 days).
 */
export interface JournalOptions {
  /** `false` → `append()` writes nothing and `startFlush()` never starts. */
  enabled?: boolean
  /** `false` → `count()` is a no-op, so allow decisions never reach disk. */
  allowCounters?: boolean
  /** Default `retainFiles` for `rotate()`. */
  retainFiles?: number
  /** Default `retainDays` for `rotate()`. */
  retainDays?: number
}

/** The rule id of the periodic aggregate line (see `flushCounters`). */
export const COUNTERS_RULE = 'counters'

const DEFAULT_RETAIN_FILES = 14
const DEFAULT_RETAIN_DAYS = 30
const DEFAULT_READ_LIMIT = 200
const DAY_MS = 86_400_000

/** `journal-2026-09-14.jsonl`, plus `-<n>` for a second roll on the same day. */
const ARCHIVE_RE = /^journal-(\d{4}-\d{2}-\d{2})(?:-(\d+))?\.jsonl$/

interface ArchiveRef {
  name: string
  /** The date carried by the file name (`YYYY-MM-DD`). */
  date: string
  /** 0 for the plain dated name; the collision counter otherwise. */
  seq: number
}

function parseArchive(name: string): ArchiveRef | undefined {
  const m = ARCHIVE_RE.exec(name)
  if (!m) return undefined
  return { name, date: m[1], seq: m[2] === undefined ? 0 : Number(m[2]) }
}

/** Oldest → newest, so the retention window can count from the end. */
function byAge(a: ArchiveRef, b: ArchiveRef): number {
  if (a.date !== b.date) return a.date < b.date ? -1 : 1
  return a.seq - b.seq
}

function resolveHome(dshHome?: string): string {
  return dshHome ?? process.env.DSH_HOME ?? join(homedir(), '.dsh')
}
export function journalDir(dshHome?: string): string {
  return join(resolveHome(dshHome), 'dsh-maestro-guard')
}
export function journalPath(dshHome?: string): string {
  return join(journalDir(dshHome), 'journal.jsonl')
}

/**
 * Rotations are serialized through one in-flight promise chain (the idiom the
 * deleted `pending.ts` used for its store writes). `freeArchivePath` is a
 * stat-then-rename, so two overlapping calls would both pick the same free
 * candidate and POSIX `rename` would replace the destination — destroying the
 * first call's archive. Nothing calls `rotate()` concurrently today, but the
 * status tools add a second caller, and a name collision must never cost a day
 * of history.
 */
let _rotationQueue: Promise<unknown> = Promise.resolve()
function enqueueRotation<T>(fn: () => Promise<T>): Promise<T> {
  const p = _rotationQueue.then(fn, fn) as Promise<T>
  _rotationQueue = p.catch(() => {})
  return p
}

export class Journal {
  /**
   * Decisions per `${rule}|${tier}` since the last flush. `allow` is the tier
   * that lives only here: it is counted in memory and reaches disk as one
   * aggregate line, so an ordinary command costs no journal I/O.
   */
  private counters = new Map<string, number>()

  /** Boot-time gates derived from {@link JournalOptions}. */
  private readonly enabled: boolean
  private readonly allowCounters: boolean

  constructor(private dshHome?: string, private now: () => number = Date.now, private opts: JournalOptions = {}) {
    this.enabled = opts.enabled !== false
    this.allowCounters = opts.allowCounters !== false
  }

  async append(entry: Omit<JournalEntry, 'ts' | 'redacted'>): Promise<void> {
    if (!this.enabled) return
    try {
      // Serialization is inside the try too: an unserializable field (BigInt, a
      // circular reference) or a throwing clock must not break the never-throw
      // guarantee any more than a filesystem failure may.
      const line = JSON.stringify({ ...redactEntry(entry), ts: new Date(this.now()).toISOString(), redacted: true })
      const p = journalPath(this.dshHome)
      await mkdir(dirname(p), { recursive: true, mode: 0o700 })
      await appendFile(p, line + '\n', { encoding: 'utf8', mode: 0o600 })
      await chmod(p, 0o600)
    } catch (e) {
      // A journal failure must never change a decision.
      console.error('[dsh-maestro-guard] journal write failed:', (e as Error)?.message)
    }
  }

  /**
   * Count one decision. Synchronous and I/O-free on purpose: this runs inside
   * the decision path, so it must never cost more than two Map operations. The
   * `rule` is part of the key (a later reader can break the aggregate down by
   * rule) even though the flushed note reports tier totals.
   */
  count(rule: string, tier: Tier): void {
    if (!this.allowCounters) return
    const key = `${rule}|${tier}`
    this.counters.set(key, (this.counters.get(key) ?? 0) + 1)
  }

  /**
   * Persist the pending counters as ONE ordinary journal entry and clear them.
   * The counters are drained before the write is awaited, so a decision counted
   * during the write lands in the next flush rather than being lost or doubled.
   * An empty map writes nothing — flushes are periodic, quiet ones are free.
   */
  async flushCounters(): Promise<void> {
    if (this.counters.size === 0) return
    const drained = this.counters
    this.counters = new Map()
    await this.append({
      tool: 'guard',
      rule: COUNTERS_RULE,
      tier: 'allow',
      target: COUNTERS_RULE,
      note: renderCounters(drained),
    })
  }

  /**
   * The recent journal, NEWEST FIRST. The live file is the newest source, so it
   * is read after the newest archive; `limit` keeps the most recent entries
   * only. A missing directory, a missing file or a torn line is skipped rather
   * than thrown — a reader must not be able to break the guard.
   */
  async read(limit: number = DEFAULT_READ_LIMIT): Promise<JournalEntry[]> {
    if (!Number.isFinite(limit) || limit <= 0) return []
    const dir = journalDir(this.dshHome)
    const sources: string[] = []
    try {
      const archives = (await readdir(dir)).map(parseArchive).filter((a): a is ArchiveRef => a !== undefined).sort(byAge)
      const newest = archives[archives.length - 1]
      if (newest) sources.push(join(dir, newest.name))
    } catch {
      // No journal directory yet: the live read below still applies.
    }
    sources.push(journalPath(this.dshHome))
    const entries: JournalEntry[] = []
    for (const p of sources) {
      let text: string
      try {
        text = await readFile(p, 'utf8')
      } catch {
        continue
      }
      for (const line of text.split('\n')) {
        if (!line.trim()) continue
        try {
          entries.push(JSON.parse(line) as JournalEntry)
        } catch {
          // A half-written trailing line is not an error for a reader.
        }
      }
    }
    // `entries` is chronological (oldest archive first, live file last); keep
    // the newest `limit` and reverse them into the newest-first contract.
    return entries.slice(-limit).reverse()
  }

  /**
   * Roll `journal.jsonl` into a dated archive, then enforce retention and
   * return the REMOVED archive paths (the new archive is not a removal).
   * Retention keeps an archive that is inside the file window OR inside the day
   * window — i.e. the newer of the two — so a quiet month never prunes a busy
   * fortnight. Never throws.
   *
   * Overlapping calls are serialized (see {@link enqueueRotation}) and the
   * archive a call just created is never a retention candidate: with both
   * windows empty the call would otherwise unlink the entire rolled history it
   * had just renamed into place.
   */
  async rotate(opts: RotateOptions = {}): Promise<string[]> {
    return enqueueRotation(() => this.rotateOnce(opts))
  }

  private async rotateOnce(opts: RotateOptions): Promise<string[]> {
    const removed: string[] = []
    try {
      const dir = journalDir(this.dshHome)
      await mkdir(dir, { recursive: true, mode: 0o700 })
      const live = journalPath(this.dshHome)
      let liveSize: number | undefined
      try {
        liveSize = (await stat(live)).size
      } catch {
        // Nothing to roll.
      }
      // An empty live file carries no decision; rolling it would only grow the
      // archive set that the retention window then has to pay for.
      let rolled: string | undefined
      if (liveSize !== undefined && liveSize > 0) {
        const target = await this.freeArchivePath(dir)
        await rename(live, target)
        rolled = target
        // The rename already happened, so a failed chmod must not escape to the
        // outer catch: that would abandon retention and report no removals for
        // a rotation that in fact succeeded. Log it and carry on.
        try {
          await chmod(target, 0o600)
        } catch (e) {
          console.error('[dsh-maestro-guard] journal archive chmod failed:', (e as Error)?.message)
        }
      }
      const retainFiles = opts.retainFiles ?? this.opts.retainFiles ?? DEFAULT_RETAIN_FILES
      const retainDays = opts.retainDays ?? this.opts.retainDays ?? DEFAULT_RETAIN_DAYS
      const dayCutoff = this.now() - retainDays * DAY_MS
      const archives = (await readdir(dir)).map(parseArchive).filter((a): a is ArchiveRef => a !== undefined).sort(byAge)
      for (let i = 0; i < archives.length; i++) {
        const archive = archives[i]
        const inFileWindow = i >= archives.length - retainFiles
        const inDayWindow = Date.parse(`${archive.date}T00:00:00.000Z`) >= dayCutoff
        if (inFileWindow || inDayWindow) continue
        const p = join(dir, archive.name)
        // The archive THIS call created holds the whole rolled history.
        if (p === rolled) continue
        try {
          await unlink(p)
          removed.push(p)
        } catch {
          // Already gone (or unreadable): retention is best-effort.
        }
      }
    } catch (e) {
      console.error('[dsh-maestro-guard] journal rotate failed:', (e as Error)?.message)
    }
    return removed
  }

  /**
   * Flush the counters every `intervalMs` and return the disposer that stops
   * it. The flush is periodic by design: the decision path only ever touches
   * the in-memory map. The timer is unref'd so a pending flush never keeps the
   * host process alive. A disabled journal starts no timer at all.
   */
  startFlush(intervalMs: number): () => void {
    if (!this.enabled) return () => {}
    const timer = setInterval(() => {
      void this.flushCounters()
    }, intervalMs)
    ;(timer as { unref?: () => void }).unref?.()
    let stopped = false
    return () => {
      if (stopped) return
      stopped = true
      clearInterval(timer)
    }
  }

  /** The first unused `journal-<today>[-<n>].jsonl` under `dir`. */
  private async freeArchivePath(dir: string): Promise<string> {
    const date = new Date(this.now()).toISOString().slice(0, 10)
    for (let seq = 0; seq < 1000; seq++) {
      const name = seq === 0 ? `journal-${date}.jsonl` : `journal-${date}-${seq}.jsonl`
      const candidate = join(dir, name)
      try {
        await stat(candidate)
      } catch {
        return candidate
      }
    }
    // 1000 collisions in one day is unreachable, but the fallback must still be
    // a name this module can READ and PRUNE: interpolating the raw clock put a
    // fractional millisecond into the name (`journal-<date>-<n>.<n>.jsonl`),
    // which ARCHIVE_RE does not match, so such an archive would be invisible to
    // `read()` and to retention forever. Truncate to a positive integer so the
    // name always lands in the `-<n>` slot.
    const seq = Math.max(1, Math.floor(this.now()))
    return join(dir, `journal-${date}-${seq}.jsonl`)
  }
}

/**
 * `allow=2,ask=1` — tier totals in tier order, present tiers only. The rule is
 * deliberately absent: the note is the tier roll-up, and a rule named after a
 * secret would otherwise ride an aggregate line.
 */
function renderCounters(counters: Map<string, number>): string {
  const perTier = new Map<Tier, number>()
  for (const [key, n] of counters) {
    const tier = key.slice(key.lastIndexOf('|') + 1) as Tier
    perTier.set(tier, (perTier.get(tier) ?? 0) + n)
  }
  return TIERS.filter((tier) => (perTier.get(tier) ?? 0) > 0)
    .map((tier) => `${tier}=${perTier.get(tier)}`)
    .join(',')
}

/**
 * The single redaction choke point for the stored record. The `redacted: true`
 * stamp is not a decoration: it is true only because every string this entry
 * carries passes through the widened redactor here. Call sites stay free to pass
 * raw verdict fields — a future caller that forgets cannot leak, and a
 * non-string value (the throwaway object the never-throw test passes as `note`)
 * is left untouched so serialization still fails exactly as before.
 */
function redactEntry(entry: Omit<JournalEntry, 'ts' | 'redacted'>): Omit<JournalEntry, 'ts' | 'redacted'> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(entry)) {
    out[key] = typeof value === 'string' ? redact(value) : value
  }
  return out as Omit<JournalEntry, 'ts' | 'redacted'>
}
