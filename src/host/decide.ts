import type { Tier } from './tiers.js'
import { DEFAULT_TIERS, type Verdict } from './rules.js'

/**
 * Resolve a classified verdict to the tier actually enforced, after per-rule
 * config overrides.
 *
 * `deny` is a structural floor: a rule that is never approvable cannot be
 * downgraded by configuration, or the guard's tamper protection would be one
 * settings edit away from disappearing.
 *
 * An entry that merely ECHOES the rule's built-in tier is not an override. The
 * handler passes `cfg.rules`, which is the fully-populated table
 * `DEFAULT_CONFIG` carries — every rule id appears there whether the user wrote
 * one or not. Honouring those entries as overrides made every classify-level
 * tier refinement unreachable: `pkg.publish` classifies a `--dry-run` as
 * `journal`, but the table's `pkg.publish: ask` default then won, so production
 * asked for a dry run while the corpus (asserting through `decide(v, {})`, a
 * shape no production code used) reported `journal`. An entry that DIFFERS from
 * `DEFAULT_TIERS` is an explicit user choice, and it raises or lowers the tier.
 */
export function decide(v: Verdict, overrides: Partial<Record<string, Tier>>): { tier: Tier; ruleId: string } {
  if (v.tier === 'deny') return { tier: 'deny', ruleId: v.ruleId }
  const override = overrides[v.ruleId]
  if (override === undefined || override === DEFAULT_TIERS[v.ruleId]) {
    return { tier: v.tier, ruleId: v.ruleId }
  }
  return { tier: override, ruleId: v.ruleId }
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
