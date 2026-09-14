import { describe, it, expect } from 'vitest'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { validateJsonSchemaValue } from '@deepseek-ai/dsh-tools'
import { Journal, COUNTERS_RULE, journalPath } from '../src/host/journal.js'
import { applyStatusTools, createStatusTools } from '../src/host/status-tool.js'
import { DEFAULT_CONFIG, type GuardConfigV2 } from '../src/host/config.js'

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'st-'))
}

/**
 * Every own-property path whose value is `undefined`. `@deepseek-ai/dsh-tools`
 * snapshots each successful body with `snapshotJsonValue` BEFORE schema
 * validation, and that walk rejects any own enumerable property holding
 * `undefined` — so an own `since: undefined` is a registry error
 * (`value is not lossless JSON`), not a harmless absent field.
 */
function undefinedPaths(value: unknown, path = '$'): string[] {
  if (Array.isArray(value)) return value.flatMap((v, i) => undefinedPaths(v, `${path}[${i}]`))
  if (value === null || typeof value !== 'object') return []
  return Object.entries(value as Record<string, unknown>)
    .flatMap(([k, v]) => (v === undefined ? [`${path}.${k}`] : undefinedPaths(v, `${path}.${k}`)))
}

/**
 * A journal whose OLDEST line is `junk` and whose two newer lines are real
 * decisions. `read()` is newest-first, so the file's first line is the last
 * entry handed back — the one `stats()` takes `since` from.
 */
async function setupWithOldestLine(junk: string) {
  const dir = await tempDir()
  const journal = new Journal(dir)
  await mkdir(dirname(journalPath(dir)), { recursive: true })
  await writeFile(journalPath(dir), `${junk}\n`)
  await journal.append({ tool: 'bash', rule: 'git.push.protected', tier: 'ask', target: 'git push origin master', outcome: 'granted', askMs: 900 })
  await journal.append({ tool: 'bash', rule: 'git.merge.protected', tier: 'journal', target: 'gh pr merge 5', outcome: 'passed' })
  return { dir, journal, tools: createStatusTools({ journal, config: async () => CONFIG }) }
}

/**
 * A config whose tiers DIFFER from `DEFAULT_TIERS`: `status()` must report the
 * effective table it was handed, not the built-in default (a stub returning
 * `DEFAULT_CONFIG.rules` would pass against the default table and fail here).
 */
const CONFIG: GuardConfigV2 = {
  ...DEFAULT_CONFIG,
  rules: { ...DEFAULT_CONFIG.rules, 'git.merge.protected': 'journal', 'git.push.protected': 'deny' },
}

/** Two decisions, oldest first: an ask with an `askMs`, then a journal pass. */
async function setup() {
  const dir = await tempDir()
  const journal = new Journal(dir)
  await journal.append({ tool: 'bash', rule: 'git.push.protected', tier: 'ask', target: 'git push origin master', outcome: 'granted', askMs: 900 })
  await journal.append({ tool: 'bash', rule: 'git.merge.protected', tier: 'journal', target: 'gh pr merge 5', outcome: 'passed' })
  return { dir, journal, tools: createStatusTools({ journal, config: async () => CONFIG }) }
}

/** The two decisions above plus the periodic counter aggregate line. */
async function setupWithCounters() {
  const built = await setup()
  built.journal.count('git.push.protected', 'allow')
  built.journal.count('git.push.protected', 'allow')
  await built.journal.flushCounters()
  return built
}

describe('guard status tools', () => {
  it('reports the recent decisions newest-first and the effective rule tiers', async () => {
    const { tools } = await setup()
    const res = await tools.status()
    expect(res.ok).toBe(true)
    expect(res.recent.map((e) => e.rule)).toEqual(['git.merge.protected', 'git.push.protected'])
    expect(Date.parse(res.recent[0].ts)).toBeGreaterThanOrEqual(Date.parse(res.recent[1].ts))
    // The tier comes from the injected config, which overrides the defaults.
    expect(res.rules['git.merge.protected']).toBe('journal')
    expect(res.rules['git.push.protected']).toBe('deny')
  })

  it('reports the journal file it reads and whether that journal writes', async () => {
    const { dir, tools } = await setup()
    const res = await tools.status()
    expect(res.journalPath).toBe(journalPath(dir))
    expect(res.enabled).toBe(true)

    const quiet = new Journal(await tempDir(), Date.now, { enabled: false })
    const off = await createStatusTools({ journal: quiet, config: async () => CONFIG }).status()
    // The boot flag is the truth about this instance, so it is read from the
    // journal rather than re-derived from the config block.
    expect(off.enabled).toBe(false)
  })

  it('folds the counters per rule, tier and outcome', async () => {
    const { tools } = await setupWithCounters()
    const res = await tools.stats()
    expect(res.ok).toBe(true)
    expect(res.byRule).toEqual({ 'git.push.protected': 1, 'git.merge.protected': 1 })
    expect(res.byTier).toEqual({ ask: 1, journal: 1 })
    expect(res.byOutcome).toEqual({ granted: 1, passed: 1 })
    expect(typeof res.since).toBe('string')
  })

  it('keeps the counters aggregate line out of the decision counts', async () => {
    const { journal, tools } = await setupWithCounters()
    // The aggregate row is really there…
    expect((await journal.read()).some((e) => e.rule === COUNTERS_RULE)).toBe(true)
    const res = await tools.stats()
    // …and it is a metrics row, not a decision: neither its rule id nor the
    // synthetic `allow` tier may inflate the decision fold.
    expect(res.byRule[COUNTERS_RULE]).toBeUndefined()
    expect(res.byTier['allow']).toBeUndefined()
    expect(Object.values(res.byRule)).not.toContain(2)
  })

  it('computes askMs percentiles over the entries that carry one', async () => {
    const { journal, tools } = await setup()
    for (const askMs of [100, 200, 300, 400]) {
      await journal.append({ tool: 'bash', rule: 'git.tag.release', tier: 'ask', target: `git tag v${askMs}`, outcome: 'granted', askMs })
    }
    const res = await tools.stats()
    // Samples are [100, 200, 300, 400, 900] — nearest rank. The `passed` entry
    // carries no `askMs`, so it must not be folded in as a zero.
    expect(res.askMs).toEqual({ p50: 300, p90: 900, max: 900 })
  })

  it('returns empty results and ok:true for a missing journal and a throwing config', async () => {
    const missing = new Journal(join(await tempDir(), 'absent'))
    const tools = createStatusTools({ journal: missing, config: async () => DEFAULT_CONFIG })
    const status = await tools.status()
    expect(status.ok).toBe(true)
    expect(status.recent).toEqual([])
    expect(status.enabled).toBe(true)

    const stats = await tools.stats()
    expect(stats.ok).toBe(true)
    expect(stats.byRule).toEqual({})
    expect(stats.byTier).toEqual({})
    expect(stats.byOutcome).toEqual({})
    expect(stats.askMs).toEqual({ p50: 0, p90: 0, max: 0 })
    expect(stats.since).toBeUndefined()
    // Omitted, not `since: undefined`: an own undefined property is what the
    // registry's lossless-JSON snapshot rejects.
    expect('since' in stats).toBe(false)

    const boom = createStatusTools({ journal: missing, config: async () => { throw new Error('config read failed') } })
    expect((await boom.status()).ok).toBe(true)
    expect(await boom.status()).toMatchObject({ rules: {}, recent: [] })
    expect((await boom.stats()).ok).toBe(true)
  })

  it('registers both tools with an output contract that renders', async () => {
    const { journal } = await setup()
    const regs: any[] = []
    const ctx: any = {
      tools: { register: (d: any) => { regs.push(d); return () => {} } },
      effect: (fn: () => unknown) => { fn(); return () => {} },
    }
    applyStatusTools(ctx, { journal, config: async () => CONFIG })
    expect(regs.map((r) => r.name)).toEqual(['maestro_guard_status', 'maestro_guard_stats'])
    for (const r of regs) {
      // A tool without the `output` pair fails to register in the real registry.
      expect(r.output?.schema?.type).toBe('object')
      expect(typeof r.output?.render).toBe('function')
      // Both tools are argument-free; `defineTool` compiles that to an open
      // object root with no declared property.
      expect(r.parameters.properties).toEqual({})
    }

    const statusValue: any = await regs[0].execute({}, {})
    expect(statusValue.ok).toBe(true)
    const statusText = regs[0].output.render({}, statusValue)
    expect(statusText[0].type).toBe('text')
    expect(statusText[0].text).toContain('git.merge.protected')

    const statsText = regs[1].output.render({}, await regs[1].execute({}, {}))
    expect(statsText[0].text).toContain('byTier')
  })

  it('renders a journal holding a foreign, parseable-but-empty line without throwing', async () => {
    const { dir, journal } = await setup()
    // `read()` keeps whatever parses, so a `{}` line left by another writer
    // reaches `recent` with no rule and no tier.
    await writeFile(journalPath(dir), '{}\n', { flag: 'a' })
    const regs: any[] = []
    const ctx: any = {
      tools: { register: (d: any) => { regs.push(d); return () => {} } },
      effect: (fn: () => unknown) => { fn(); return () => {} },
    }
    applyStatusTools(ctx, { journal, config: async () => CONFIG })
    const value: any = await regs[0].execute({}, {})
    expect(value.recent).toHaveLength(3)
    expect(value.recent[0]).toEqual({}) // newest-first: the junk line is first
    expect(() => regs[0].output.render({}, value)).not.toThrow()
    // The aggregate fold skips the fields the junk line does not carry.
    const stats: any = await regs[1].execute({}, {})
    expect(stats.byRule).toEqual({ 'git.push.protected': 1, 'git.merge.protected': 1 })
    expect(stats.byTier).toEqual({ ask: 1, journal: 1 })
  })

  it('omits `since` when a foreign line is the OLDEST entry in the window', async () => {
    // The junk line is written first, so it is the oldest entry — unlike the
    // test above, where it is newest and never reaches `entries[last]`.
    const { journal, tools } = await setupWithOldestLine('{}')
    const stats: any = await tools.stats()
    expect(stats.ok).toBe(true)
    expect(stats.byRule).toEqual({ 'git.push.protected': 1, 'git.merge.protected': 1 })
    // `{}` has no `ts`; assigning it would create an own `since: undefined`.
    expect('since' in stats).toBe(false)
    expect(undefinedPaths(stats)).toEqual([])
    // A lossless JSON round trip: nothing the registry's snapshot would drop.
    expect(JSON.parse(JSON.stringify(stats))).toEqual(stats)
  })

  it('omits `since` for a non-string `ts` on the oldest entry', async () => {
    // Guards the fix against a weaker `!== undefined` reading: a corrupt line
    // can carry a null or numeric `ts`, which the string-typed schema rejects.
    const { tools } = await setupWithOldestLine('{"ts":null,"rule":"git.push.protected"}')
    const stats: any = await tools.stats()
    expect(stats.ok).toBe(true)
    expect('since' in stats).toBe(false)
    expect(undefinedPaths(stats)).toEqual([])
  })

  it('returns lossless, undefined-free values from status() over the same corrupt journal', async () => {
    const { tools } = await setupWithOldestLine('{}')
    const status: any = await tools.status()
    expect(status.ok).toBe(true)
    expect(status.recent).toHaveLength(3)
    expect(status.recent[2]).toEqual({}) // oldest entry, verbatim
    expect(undefinedPaths(status)).toEqual([])
    expect(JSON.parse(JSON.stringify(status))).toEqual(status)
  })

  it('keeps answering when a parseable line is not an object', async () => {
    // `JSON.parse('null')` succeeds, so `read()` keeps the line — but a null
    // entry has no `.rule` to read, which used to throw straight out of
    // `stats()` (the module contract is empty-but-`ok`, never a throw).
    const { journal } = await setupWithOldestLine('null')
    const regs: any[] = []
    const ctx: any = {
      tools: { register: (d: any) => { regs.push(d); return () => {} } },
      effect: (fn: () => unknown) => { fn(); return () => {} },
    }
    applyStatusTools(ctx, { journal, config: async () => CONFIG })

    const statusValue: any = await regs[0].execute({}, {})
    expect(statusValue.ok).toBe(true)
    expect(statusValue.recent).toHaveLength(3)
    expect(statusValue.recent[2]).toBeNull() // oldest entry, verbatim
    expect(() => regs[0].output.render({}, statusValue)).not.toThrow()
    expect(validateJsonSchemaValue(regs[0].output.schema, statusValue, 'value')).toEqual([])

    const statsValue: any = await regs[1].execute({}, {})
    expect(statsValue.ok).toBe(true)
    expect(statsValue.byRule).toEqual({ 'git.push.protected': 1, 'git.merge.protected': 1 })
    expect('since' in statsValue).toBe(false)
    expect(validateJsonSchemaValue(regs[1].output.schema, statsValue, 'value')).toEqual([])
  })

  it("passes dsh-tools' own output validator for both registered tools over a corrupt journal", async () => {
    // The whole `ToolRuntime.createSuccessResult` path needs a Cordis
    // `systemPrompt` service, but its two checkable halves are reachable here:
    // the registered body value, and dsh-tools' exported schema validator —
    // the exact call the runtime makes after snapshotting the body.
    const { journal } = await setupWithOldestLine('{}')
    const regs: any[] = []
    const ctx: any = {
      tools: { register: (d: any) => { regs.push(d); return () => {} } },
      effect: (fn: () => unknown) => { fn(); return () => {} },
    }
    applyStatusTools(ctx, { journal, config: async () => CONFIG })
    for (const r of regs) {
      const value = await r.execute({}, {})
      expect(validateJsonSchemaValue(r.output.schema, value, 'value')).toEqual([])
    }
  })
})

/**
 * IMPORTANT minor — `byRule`/`byTier` are documented as the DECISION fold, but
 * they also counted the guard's own bookkeeping rows (`config-legacy`,
 * `guard.migration`, `policy.deny`), inventing decisions attributed to ids that
 * are not in the rule table. Only rows whose `rule` is one of the closed
 * `RULE_IDS` are decisions now.
 */
describe('guard stats — non-decision rows', () => {
  it('keeps the guard internal rows out of byRule and byTier', async () => {
    const { journal, tools } = await setup()
    for (const [rule, tier] of [
      ['config-legacy', 'journal'],
      ['guard.migration', 'journal'],
      ['policy.deny', 'deny'],
    ] as const) {
      await journal.append({ tool: 'guard', rule, tier, target: rule, outcome: 'passed' })
    }
    const res = await tools.stats()
    expect(res.byRule).toEqual({ 'git.push.protected': 1, 'git.merge.protected': 1 })
    expect(res.byTier).toEqual({ ask: 1, journal: 1 })
    // byOutcome still counts every row: an operator must see that a policy deny
    // happened even though it is not a rule decision.
    expect(res.byOutcome).toEqual({ granted: 1, passed: 4 })
  })
})
