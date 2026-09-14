import { appendFile, chmod, mkdir } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import type { Tier } from './tiers.js'
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

function resolveHome(dshHome?: string): string {
  return dshHome ?? process.env.DSH_HOME ?? join(homedir(), '.dsh')
}
export function journalDir(dshHome?: string): string {
  return join(resolveHome(dshHome), 'dsh-maestro-guard')
}
export function journalPath(dshHome?: string): string {
  return join(journalDir(dshHome), 'journal.jsonl')
}

export class Journal {
  constructor(private dshHome?: string, private now: () => number = Date.now) {}

  async append(entry: Omit<JournalEntry, 'ts' | 'redacted'>): Promise<void> {
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
