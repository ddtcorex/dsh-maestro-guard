import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { COUNTERS_RULE, type Journal, type JournalEntry } from './journal.js'
import type { GuardConfigV2 } from './config.js'
import type { Tier } from './tiers.js'

/** How many recent decisions `maestro_guard_status` returns. */
export const RECENT_LIMIT = 20
/**
 * How many journal entries `maestro_guard_stats` folds. `Journal.read` walks
 * the archives newest → oldest, so this really is the last N decisions rather
 * than whatever the newest archive happens to hold.
 */
export const STATS_LIMIT = 1000

export interface StatusResult {
  ok: true
  recent: JournalEntry[]
  rules: Record<string, Tier>
  journalPath: string
  enabled: boolean
}

export interface StatsResult {
  ok: true
  byRule: Record<string, number>
  byTier: Record<string, number>
  byOutcome: Record<string, number>
  askMs: { p50: number; p90: number; max: number }
  /** Timestamp of the oldest folded entry — the start of the counted window. */
  since?: string
}

export interface StatusDeps {
  journal: Journal
  config: () => Promise<GuardConfigV2>
}

/** Nearest-rank percentile over an ASCENDING numeric array (must be non-empty). */
function percentile(sorted: number[], q: number): number {
  const rank = Math.ceil(q * sorted.length)
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1]
}

function bump(bag: Record<string, number>, key: string | undefined): void {
  if (key === undefined) return
  bag[key] = (bag[key] ?? 0) + 1
}

/**
 * The two READ-ONLY journal tools. Every result is a fresh plain object built
 * from leaf fields (never a live `Journal`), every failure is swallowed into an
 * empty-but-`ok` answer, and neither tool can write, approve or re-decide
 * anything: an operator can inspect the guard without being able to change it.
 */
export function createStatusTools(deps: StatusDeps): { status(): Promise<StatusResult>; stats(): Promise<StatsResult> } {
  return {
    async status(): Promise<StatusResult> {
      const cfg = await deps.config().catch(() => undefined)
      return {
        ok: true,
        recent: await deps.journal.read(RECENT_LIMIT),
        // A copy: the caller must not be able to mutate the live config table.
        rules: { ...(cfg?.rules ?? {}) },
        journalPath: deps.journal.path,
        enabled: deps.journal.enabled,
      }
    },

    async stats(): Promise<StatsResult> {
      const entries = await deps.journal.read(STATS_LIMIT)
      const byRule: Record<string, number> = {}
      const byTier: Record<string, number> = {}
      const byOutcome: Record<string, number> = {}
      const asks: number[] = []
      for (const entry of entries) {
        // `read()` keeps any line that parses, and `null` parses: a non-object
        // entry carries no field at all, so reading `entry.rule` off it would
        // throw out of a tool that promises an empty-but-`ok` answer.
        if (entry === null || typeof entry !== 'object') continue
        // The periodic counter aggregate is a METRICS row, not a decision: its
        // rule id is `counters` and its tier `allow` is synthetic (allow
        // decisions never reach the journal individually), so folding it in
        // would invent one decision per flush and attribute it to a rule that
        // does not exist in the rule table.
        if (entry.rule !== COUNTERS_RULE) {
          bump(byRule, entry.rule)
          bump(byTier, entry.tier)
        }
        bump(byOutcome, entry.outcome)
        if (typeof entry.askMs === 'number' && Number.isFinite(entry.askMs)) asks.push(entry.askMs)
      }
      asks.sort((a, b) => a - b)
      const oldest = entries[entries.length - 1]
      const result: StatsResult = {
        ok: true,
        byRule,
        byTier,
        byOutcome,
        askMs: asks.length === 0
          ? { p50: 0, p90: 0, max: 0 }
          : { p50: percentile(asks, 0.5), p90: percentile(asks, 0.9), max: asks[asks.length - 1] },
      }
      // `read()` keeps any line that parses, so the oldest entry in the window
      // can be a foreign `{}` with no `ts`, or one whose `ts` is not a string.
      // Assigning that would create an OWN `since: undefined` (or a non-string
      // one), and `@deepseek-ai/dsh-tools` rejects both: it snapshots every
      // successful body with `snapshotJsonValue` before schema validation, so
      // an own undefined property fails as "value is not lossless JSON" instead
      // of answering `ok: true`. Omit the field — `output.schema` requires only
      // `ok`. (No other property here is conditionally assigned: `byRule`,
      // `byTier` and `byOutcome` only ever take numeric values from `bump()`,
      // and `askMs` only takes numbers.)
      if (typeof oldest?.ts === 'string') result.since = oldest.ts
      return result
    },
  }
}

function formatCounts(bag: Record<string, number>): string {
  const keys = Object.keys(bag).sort()
  return keys.length === 0 ? '(none)' : keys.map((k) => `${k}=${bag[k]}`).join(', ')
}

function renderStatus(v: any): string {
  const lines = [
    `guard status — journal ${v.journalPath} (${v.enabled ? 'enabled' : 'disabled'}), ${v.recent.length} recent decision(s)`,
  ]
  for (const raw of v.recent) {
    // A foreign or half-written line parses to `{}` — or to a bare `null`,
    // which `JSON.parse` accepts — and `read()` deliberately keeps whatever
    // parses: presentation must degrade, never throw.
    const e = raw !== null && typeof raw === 'object' ? raw : {}
    const tier = typeof e.tier === 'string' ? e.tier.padEnd(7) : '?      '
    const rule = typeof e.rule === 'string' ? e.rule : '?'
    const ask = typeof e.askMs === 'number' ? ` ${e.askMs}ms` : ''
    const outcome = e.outcome === undefined ? '' : ` ${e.outcome}`
    lines.push(`${e.ts}  ${tier} ${rule}  ${e.tool}  ${e.target}${outcome}${ask}`)
  }
  lines.push(`rules: ${formatCounts(v.rules)}`)
  return lines.join('\n').slice(0, 4000)
}

function renderStats(v: any): string {
  const ask = v.askMs
  return [
    `guard stats${v.since === undefined ? '' : ` since ${v.since}`}`,
    `byRule: ${formatCounts(v.byRule)}`,
    `byTier: ${formatCounts(v.byTier)}`,
    `byOutcome: ${formatCounts(v.byOutcome)}`,
    `askMs: p50=${ask.p50} p90=${ask.p90} max=${ask.max}`,
  ].join('\n').slice(0, 4000)
}

/**
 * Register the read-only journal tools on the host tool registry. Each
 * registration is its own reversible effect, matching `full-scan-tool.ts`;
 * neither tool declares parameters, and both carry the `output: { schema,
 * render }` pair the registry requires (a definition without it fails to
 * register).
 */
export function applyStatusTools(ctx: Context, deps: StatusDeps): void {
  const tools = createStatusTools(deps)
  ctx.effect(() => ctx.tools.register(defineTool({
    name: 'maestro_guard_status',
    description: 'Show the guard journal: the most recent decisions, the effective rule tiers, and where the journal lives. Read-only.',
    parameters: {},
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ok: { type: 'boolean', required: true },
          recent: { type: 'array', required: true },
          rules: { type: 'object', additionalProperties: true, required: true },
          journalPath: { type: 'string', required: true },
          enabled: { type: 'boolean', required: true },
        },
      },
      render: (_args: any, value: any) => [{ type: 'text', text: renderStatus(value) }],
    },
    async execute(): Promise<any> {
      return tools.status()
    },
  })), 'guard-status-tool')

  ctx.effect(() => ctx.tools.register(defineTool({
    name: 'maestro_guard_stats',
    description: 'Aggregate the guard journal by rule, tier and outcome, with the ask-approval latency percentiles. Read-only.',
    parameters: {},
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ok: { type: 'boolean', required: true },
          byRule: { type: 'object', additionalProperties: true, required: true },
          byTier: { type: 'object', additionalProperties: true, required: true },
          byOutcome: { type: 'object', additionalProperties: true, required: true },
          askMs: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              p50: { type: 'number', required: true },
              p90: { type: 'number', required: true },
              max: { type: 'number', required: true },
            },
          },
          since: { type: 'string' },
        },
      },
      render: (_args: any, value: any) => [{ type: 'text', text: renderStats(value) }],
    },
    async execute(): Promise<any> {
      return tools.stats()
    },
  })), 'guard-stats-tool')
}
