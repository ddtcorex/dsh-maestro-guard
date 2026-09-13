import { describe, it, expect } from 'vitest'
import { decide, renderReason } from '../src/host/decide.js'

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
})
