import { chmod, mkdir, rename, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { Journal, journalDir } from './journal.js'

/**
 * Retire the legacy ticket store (Task A4). The guard no longer reads tickets —
 * the human answers through DSH's native approval service — so the old
 * `pending.json` is moved out of its active path into the journal directory,
 * where it is kept for reference but never consulted again.
 *
 * This runs once per boot inside `ctx.effect`; it is idempotent (a missing
 * source is a no-op) and never throws, because a failed retirement must not
 * stop the guard from booting.
 */
export async function retireLegacyStore(journal: Journal, dshHome?: string): Promise<{ moved: boolean; to?: string }> {
  const dir = journalDir(dshHome)
  const from = join(dir, 'pending.json')
  const to = join(dir, 'legacy-pending.json')
  try {
    await stat(from)
  } catch {
    return { moved: false }
  }
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 })
    await rename(from, to)
    await chmod(to, 0o600)
    await journal.append({
      tool: 'guard',
      rule: 'guard.migration',
      tier: 'journal',
      target: to,
      outcome: 'passed',
      note: 'legacy ticket store retired; retained for reference, no longer read by the guard',
    })
    return { moved: true, to }
  } catch (e) {
    console.error('[dsh-maestro-guard] legacy store retirement failed:', (e as Error)?.message)
    return { moved: false }
  }
}
