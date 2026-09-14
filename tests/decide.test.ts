import { describe, it, expect } from 'vitest'
import { decide, renderReason } from '../src/host/decide.js'
import { DEFAULT_CONFIG } from '../src/host/config.js'

const verdict = { ruleId: 'git.push.protected', tier: 'ask' as const, target: 'git push origin master', repo: '/repo', branch: 'master' }

describe('decide', () => {
  it('honours a config override', () => {
    expect(decide(verdict, { 'git.push.protected': 'journal' }).tier).toBe('journal')
  })
  it('never downgrades the deny tier', () => {
    const v = { ...verdict, ruleId: 'guard.tamper', tier: 'deny' as const }
    expect(decide(v, { 'guard.tamper': 'allow' }).tier).toBe('deny')
  })
  it('renders the rule id, target and repo', () => {
    const reason = renderReason(verdict, (s) => s)
    expect(reason).toContain('git.push.protected')
    expect(reason).toContain('git push origin master')
    expect(reason).toContain('/repo')
  })

  /**
   * IMPORTANT 3 — the production call is `decide(verdict, cfg.rules)` and
   * `cfg.rules` is the FULL default table, so an entry that merely echoes the
   * rule's built-in tier must not count as an override. Otherwise the
   * `--dry-run` → `journal` refinement never reaches production.
   */
  it('keeps a classify-level refinement when the table only echoes the built-in tier', () => {
    const dryRun = { ruleId: 'pkg.publish', tier: 'journal' as const, target: 'pnpm publish --dry-run' }
    expect(decide(dryRun, DEFAULT_CONFIG.rules).tier).toBe('journal')
  })

  it('applies an explicit override in BOTH directions', () => {
    const publish = { ruleId: 'pkg.publish', tier: 'ask' as const, target: 'pnpm publish' }
    expect(decide(publish, { 'pkg.publish': 'journal' }).tier).toBe('journal') // lower
    expect(decide(publish, { 'pkg.publish': 'deny' }).tier).toBe('deny') // raise
    const merge = { ruleId: 'git.merge.protected', tier: 'journal' as const, target: 'gh pr merge 5' }
    expect(decide(merge, { 'git.merge.protected': 'ask' }).tier).toBe('ask') // raise
  })

  it('leaves a rule with no entry at its classified tier', () => {
    expect(decide(verdict, {}).tier).toBe('ask')
    expect(decide({ ruleId: 'pkg.publish', tier: 'journal' as const, target: 'x' }, {}).tier).toBe('journal')
  })
})
