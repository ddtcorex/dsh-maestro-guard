import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { classify, RULE_IDS } from '../src/host/rules.js'
import { decide } from '../src/host/decide.js'
import { defaultProtectedPaths, guardConfigPaths } from '../src/host/paths.js'

/**
 * The golden corpus: every row is a real event (a bypass the legacy matchers
 * let through, an over-block they caused, or a true positive that must keep
 * firing), stated as the `{ ruleId, tier }` the pipeline must produce.
 *
 * A row is never edited to make the suite pass. A failing row is a rule bug,
 * or — when the expectation itself contradicts the spec — a decision that has
 * to be re-argued in the row's `note` and in the task report first.
 */
interface CorpusRow {
  name: string
  tool: string
  args: Record<string, unknown>
  cwd?: string
  branch?: string
  expectedRule: string
  expectedTier: string
  note?: string
}

const corpus = JSON.parse(
  readFileSync(fileURLToPath(new URL('./fixtures/guard-corpus.json', import.meta.url)), 'utf8'),
) as CorpusRow[]

/** A fixed DSH home so the protected-path rows never depend on this machine. */
const DSH_HOME = '/home/u/.dsh'

const settings = {
  protectedBranches: ['master', 'main'],
  protectedPaths: defaultProtectedPaths(DSH_HOME),
  guardPaths: guardConfigPaths(DSH_HOME),
}

function verdictOf(row: CorpusRow): { ruleId: string; tier: string } {
  const v = classify({
    tool: row.tool,
    args: row.args,
    cwd: row.cwd ?? '/repo',
    settings,
    branchOf: () => row.branch ?? 'feature',
  })
  return { ruleId: v.ruleId, tier: decide(v, {}).tier }
}

/**
 * Protected-path rows are assembled HERE from the runtime path primitives, not
 * written into the fixture: the credential and guard-config literals must live
 * in exactly one place (`paths.ts`), and a raw copy in a data file would be one
 * more string a future reader has to keep in sync.
 */
const CREDENTIAL_FILE = defaultProtectedPaths(DSH_HOME)[0]
const GUARD_SETTINGS = guardConfigPaths(DSH_HOME)[0]

const builtRows: CorpusRow[] = [
  {
    name: 'protected path: credential read',
    tool: 'bash',
    args: { command: `cat ${CREDENTIAL_FILE}` },
    cwd: '/repo',
    expectedRule: 'secret.access',
    expectedTier: 'ask',
    note: 'An access verb next to a protected path is an access, not a mention.',
  },
  {
    name: 'protected path: guard configuration write',
    tool: 'write',
    args: { file_path: GUARD_SETTINGS, content: '{}' },
    cwd: '/repo',
    expectedRule: 'guard.tamper',
    expectedTier: 'deny',
    note: 'The only deny rule: self-protection cannot be downgraded by configuration.',
  },
  {
    name: 'containment: write outside the session cwd',
    tool: 'write',
    args: { file_path: '/var/lib/app/config.json', content: '{}' },
    cwd: '/repo',
    expectedRule: 'fs.write.outside',
    expectedTier: 'ask',
  },
  {
    name: 'containment: temp-dir write is exempt',
    tool: 'write',
    args: { file_path: '/tmp/scratch-notes.md', content: 'scratch' },
    cwd: '/repo',
    expectedRule: '',
    expectedTier: 'allow',
    note: 'Scratch work under the OS temp dir is not a filesystem escape.',
  },
  {
    name: 'mention: memory entry that names a credential path',
    tool: 'memory',
    args: {
      action: 'add',
      target: 'daily',
      content: `[2026-09-14] incident: ${CREDENTIAL_FILE} was world-readable; redact instead of blocking`,
    },
    cwd: '/repo',
    expectedRule: '',
    expectedTier: 'allow',
    note:
      'A non-shell tool is judged on the path it targets, never on its content — a memory entry that NAMES a '
      + 'protected path is a mention, not an access. Measured over 1,434 session logs: the 0.2.3 text scanner '
      + 'blocked 13 memory writes of exactly this shape between 2026-08-25 and 2026-09-14, so an incident lesson '
      + 'naming the path could not be recorded at all. This row keeps that over-block from returning.',
  },
]

const allRows = [...corpus, ...builtRows]

describe('golden corpus', () => {
  for (const row of allRows) {
    it(`${row.name} → ${row.expectedRule || 'allow'}/${row.expectedTier}`, () => {
      expect(verdictOf(row)).toEqual({ ruleId: row.expectedRule, tier: row.expectedTier })
    })
  }

  it('names every row uniquely and pins only real rule ids', () => {
    const names = allRows.map((r) => r.name)
    expect(new Set(names).size).toBe(names.length)
    for (const row of allRows) {
      if (row.expectedRule !== '') {
        expect(RULE_IDS as readonly string[]).toContain(row.expectedRule)
      }
    }
  })
})
