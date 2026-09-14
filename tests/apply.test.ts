import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import guardPlugin from '../src/host/index.js'
import { journalPath } from '../src/host/journal.js'

/**
 * IMPORTANT 6 — `apply()` was only reachable through the live host, so the
 * fail-closed matrix lived in an unexported closure with no test: dropping the
 * `tools/pre-execute` registration, or any one of the four denial branches, left
 * the suite green. This suite drives the REAL `apply()` against a minimal fake
 * ctx and pins the actionable message of every fail-closed path rather than
 * leaving it incidental.
 *
 * The boot-time config read goes through the real `@ddtcorex/dsh-maestro-config-lib`
 * (this file does not mock it, unlike `config.test.ts`), so `DSH_HOME` points at a
 * private temp dir: an absent store resolves to the built-in defaults and the
 * journal lands there too.
 */
let home: string
let previousHome: string | undefined

beforeAll(async () => {
  previousHome = process.env.DSH_HOME
  home = await mkdtemp(join(tmpdir(), 'guard-apply-'))
  process.env.DSH_HOME = home
})

afterAll(() => {
  if (previousHome === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = previousHome
})

interface FakeCtx {
  tools: { register(def: unknown): () => void }
  get(name: string): unknown
  on(event: string, handler: (...args: any[]) => unknown): () => void
  effect(fn: () => unknown, label?: string): () => void
}

/** The smallest ctx `apply()` needs: a tool registry, `get`, `on` and `effect`. */
function fakeCtx(approval?: unknown) {
  const listeners = new Map<string, (...args: any[]) => unknown>()
  const tools: any[] = []
  const labels: string[] = []
  const ctx: FakeCtx = {
    tools: { register: (def: unknown) => { tools.push(def); return () => {} } },
    get: (name: string) => (name === 'approval' ? approval : undefined),
    on: (event, handler) => { listeners.set(event, handler); return () => listeners.delete(event) },
    effect: (fn, label) => { labels.push(label ?? ''); const d = fn(); return typeof d === 'function' ? (d as () => void) : () => {} },
  }
  return { ctx, listeners, tools, labels }
}

/** Run the real `apply()` and hand back the registered pre-execute handler. */
async function applied(approval?: unknown) {
  const fake = fakeCtx(approval)
  await (guardPlugin as any).apply(fake.ctx)
  return { ...fake, handler: fake.listeners.get('tools/pre-execute')! }
}

const next = async () => ({ kind: 'allow' as const })
const pushCall = (agent: unknown) => ({ name: 'bash', args: { command: 'git push origin master' }, agent } as any)
const withAgent = { session: { id: 's1', header: { cwd: '/repo' } } }

/** The newest journal line, which is the decision this call just made. */
async function lastEntry(): Promise<any> {
  const lines = (await readFile(journalPath(home), 'utf8')).trim().split('\n').filter(Boolean)
  return JSON.parse(lines[lines.length - 1] ?? '{}')
}

describe('apply() wiring', () => {
  it('registers the tools/pre-execute handler', async () => {
    const { listeners, handler } = await applied({ request: async () => 'allowed-once' })
    expect(typeof handler).toBe('function')
    expect([...listeners.keys()]).toEqual(['tools/pre-execute'])
  })

  it('registers the three read-only tools and their reversible effects', async () => {
    const { tools, labels } = await applied({ request: async () => 'allowed-once' })
    expect(tools.map((t) => t.name).sort()).toEqual(['maestro_full_scan', 'maestro_guard_stats', 'maestro_guard_status'])
    expect(labels).toContain('guard-journal-counter-flush')
    expect(labels).toContain('guard-journal-rotation')
  })
})

describe('apply() fail-closed matrix (spec §9.4)', () => {
  it('denies with the actionable message when no approval service is composed', async () => {
    const { handler } = await applied(undefined)
    const res: any = await handler(pushCall(withAgent), next)
    expect(res.kind).toBe('deny')
    expect(String(res.reason)).toMatch(/git\.push\.protected/)
    expect(String(res.reason)).toMatch(/no approval channel is available/i)
    expect(String(res.reason)).toMatch(/full-access-ask/)
    expect(await lastEntry()).toMatchObject({ rule: 'git.push.protected', tier: 'ask', outcome: 'unavailable' })
  })

  it('denies when the execution carries no agent, even with a service present', async () => {
    const { handler } = await applied({ request: async () => 'allowed-once' })
    const res: any = await handler(pushCall(undefined), next)
    expect(res.kind).toBe('deny')
    expect(String(res.reason)).toMatch(/no approval channel is available/i)
    expect(String(res.reason)).toMatch(/full-access-ask/)
    expect(await lastEntry()).toMatchObject({ outcome: 'unavailable' })
  })

  it('denies and journals the thrown message when request() rejects', async () => {
    const { handler } = await applied({
      request: async () => { throw new Error('approval.request() outside an open turn') },
    })
    const res: any = await handler(pushCall(withAgent), next)
    expect(res.kind).toBe('deny')
    expect(String(res.reason)).toMatch(/the approval request failed/i)
    // The deny text points at the journal, so the record must actually carry it.
    expect(String(res.reason)).toMatch(/see the guard journal/i)
    const entry = await lastEntry()
    expect(entry).toMatchObject({ tier: 'ask', outcome: 'error' })
    expect(entry.note).toContain('outside an open turn')
  })

  it("denies an approval-policy `never` session with the preset fix in the message", async () => {
    // DSH's approval service resolves `never` deterministically to `rejected`,
    // before any answerer is dispatched, so the guard observes a rejection. The
    // message must still name the fix, or a `never` session gets a bare "the
    // user rejected this" with no human anywhere in the loop.
    const { handler } = await applied({ request: async () => 'rejected' })
    const res: any = await handler(pushCall(withAgent), next)
    expect(res.kind).toBe('deny')
    expect(String(res.reason)).toMatch(/git\.push\.protected/)
    expect(String(res.reason)).toMatch(/full-access-ask/)
    expect(await lastEntry()).toMatchObject({ tier: 'ask', outcome: 'rejected' })
  })

  it('lets a granted ask run the tool and calls next()', async () => {
    const { handler } = await applied({ request: async () => 'allowed-once' })
    const res: any = await handler(pushCall(withAgent), next)
    expect(res).toEqual({ kind: 'allow' })
    expect(await lastEntry()).toMatchObject({ tier: 'ask', outcome: 'granted' })
  })
})
