import type { Tier } from './tiers.js'
import type { Verdict } from './rules.js'

/**
 * Resolve a classified verdict to the tier actually enforced, after per-rule
 * config overrides. `deny` is a structural floor: a rule that is never
 * approvable cannot be downgraded by configuration, or the guard's tamper
 * protection would be one settings edit away from disappearing.
 */
export function decide(v: Verdict, overrides: Partial<Record<string, Tier>>): { tier: Tier; ruleId: string } {
  if (v.tier === 'deny') return { tier: 'deny', ruleId: v.ruleId }
  return { tier: overrides[v.ruleId] ?? v.tier, ruleId: v.ruleId }
}

/**
 * Human-readable reason for a blocked/asked call: the rule id plus where it
 * happened, then the (redacted, truncated) target. The rule id is the stable
 * contract other surfaces key on; the prose after `::` is presentation only.
 */
export function renderReason(v: Verdict, redactFn: (s: string) => string): string {
  const where = [v.repo, v.branch].filter(Boolean).join(':')
  const head = `${v.ruleId}${where ? ` (${where})` : ''}`
  return `${head} :: ${redactFn(v.target).slice(0, 300)}`
}
