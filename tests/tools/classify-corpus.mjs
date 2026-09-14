#!/usr/bin/env node
/**
 * Reproducible classify-corpus driver.
 *
 * Prints the `classify` verdict (`ruleId`/`tier`) for every row of
 * `tests/fixtures/guard-corpus.json` and compares it with the row's expectation,
 * so a reviewer can see a behaviour change with their own eyes instead of
 * trusting a throwaway script (an earlier task justified its "exactly one
 * behaviour change" claim with a `/tmp` script that no longer exists).
 *
 * Usage:
 *   pnpm --dir packages/dsh-maestro-guard build
 *   node tests/tools/classify-corpus.mjs              # reads ./lib
 *   node tests/tools/classify-corpus.mjs <rules.js>   # reads another build
 *
 * The optional argument points at an alternative built `rules.js`; `decide.js`
 * and `paths.js` are loaded from the same directory, so a second checkout's
 * `lib/` can be diffed against this one:
 *   node tests/tools/classify-corpus.mjs /tmp/old-build/lib/rules.js
 *
 * Reproducing the task B5 claim (publish-runner positional fix = exactly one
 * row changes, allow → pkg.publish/ask):
 *   pnpm build && node tests/tools/classify-corpus.mjs > /tmp/new.txt
 *   git stash && pnpm build && node tests/tools/classify-corpus.mjs > /tmp/old.txt
 *   git stash pop && pnpm build
 *   diff /tmp/old.txt /tmp/new.txt
 *
 * Exit codes: 0 = every row matches, 1 = at least one diff, 2 = stale build.
 *
 * This file is NOT a vitest suite (no `.test.` in its name), so `pnpm test`
 * never picks it up.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const pkgRoot = resolve(here, '..', '..')

/**
 * The driver reads the BUILT modules, so a source edit that was never compiled
 * would print yesterday's verdicts. Refuse to run on a stale `lib/` instead.
 */
function assertBuildIsFresh() {
  const srcDir = join(pkgRoot, 'src', 'host')
  const libDir = join(pkgRoot, 'lib')
  const stale = []
  for (const f of readdirSync(srcDir)) {
    if (!f.endsWith('.ts') || f.endsWith('.d.ts')) continue
    const out = join(libDir, f.replace(/\.ts$/, '.js'))
    let built
    try {
      built = statSync(out).mtimeMs
    } catch {
      stale.push(`${f} (no ${f.replace(/\.ts$/, '.js')})`)
      continue
    }
    if (built < statSync(join(srcDir, f)).mtimeMs) stale.push(f)
  }
  if (stale.length > 0) {
    console.error(`lib/ is older than src/host/ (${stale.join(', ')}) — run \`pnpm build\` first.`)
    process.exit(2)
  }
}

const rulesArg = process.argv[2]
if (rulesArg === undefined) assertBuildIsFresh()
const rulesUrl = pathToFileURL(rulesArg === undefined ? join(pkgRoot, 'lib', 'rules.js') : resolve(rulesArg)).href

const { classify } = await import(rulesUrl)
const { decide } = await import(new URL('./decide.js', rulesUrl).href)
const { DEFAULT_CONFIG } = await import(new URL('./config.js', rulesUrl).href)
const { defaultProtectedPaths, guardConfigPaths } = await import(new URL('./paths.js', rulesUrl).href)

// Mirrors tests/corpus.test.ts: a fixed DSH home and a branch reader that
// returns the row's `branch` (default `feature`).
const DSH_HOME = '/home/u/.dsh'
const settings = {
  protectedBranches: ['master', 'main'],
  protectedPaths: defaultProtectedPaths(DSH_HOME),
  guardPaths: guardConfigPaths(DSH_HOME),
}

const rows = JSON.parse(readFileSync(join(pkgRoot, 'tests', 'fixtures', 'guard-corpus.json'), 'utf8'))

console.log(`golden corpus — classify verdicts (module: ${rulesUrl})`)
console.log('')

let diffs = 0
for (const row of rows) {
  const v = classify({
    tool: row.tool,
    args: row.args,
    cwd: row.cwd ?? '/repo',
    settings,
    branchOf: () => row.branch ?? 'feature',
  })
  // The SAME decision call the handler makes (`decide(v, cfg.rules)`), with the
  // fully-populated default table. `decide(v, {})` was a shape no production
  // code used and hid the `--dry-run` regression.
  const tier = decide(v, DEFAULT_CONFIG.rules).tier
  const got = `${v.ruleId || 'allow'}/${tier}`
  const want = `${row.expectedRule || 'allow'}/${row.expectedTier}`
  const ok = got === want
  if (!ok) diffs++
  console.log(`  ${ok ? 'PASS' : 'DIFF'}  ${row.name.padEnd(58)} ${ok ? got : `expected ${want}, got ${got}`}`)
}

console.log('')
console.log(`${rows.length} rows: ${rows.length - diffs} pass, ${diffs} diff`)
process.exit(diffs === 0 ? 0 : 1)
