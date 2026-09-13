import { execSync } from 'node:child_process'
import type { Context } from '@deepseek-ai/cordis'
import { PermissionPolicy } from './permission-policy.js'
import { Journal, type AskOutcome } from './journal.js'
import { redact } from './redact.js'
import { classify } from './rules.js'
import { decide, renderReason } from './decide.js'
import { DEFAULT_CONFIG, loadGuardConfig, type GuardConfigV2 } from './config.js'
import { retireLegacyStore } from './migrate.js'
import { apply as applyFullScan } from './full-scan-tool.js'
import type { GuardToolExecution, GuardPreToolDecision } from './augment.js'

export interface GuardDeps {
  journal: Journal
  policy: PermissionPolicy
  readConfig: () => Promise<GuardConfigV2>
  branchOf?: (dir: string) => string | undefined
  requestApproval: (req: { agent?: unknown; toolName: string; callId?: string; reason: string; signal?: AbortSignal }) => Promise<AskOutcome>
  now?: () => number
}

/**
 * Outcome vocabulary for the deny message. `unavailable` is the fail-closed
 * case that matters most: no answerer is attached to this session, so the
 * operation cannot be approved and must not silently proceed.
 */
const EXPLAIN: Record<AskOutcome, string> = {
  granted: 'granted once',
  rejected: 'the user rejected this operation',
  cancelled: 'the approval prompt was cancelled',
  unavailable: 'no approval channel is available for this session (start a session under the full-access-ask preset)',
  error: 'the approval request failed (see the guard journal)',
}

/**
 * The guard pipeline: classify the call into a rule id, resolve the rule's tier,
 * journal the decision, then act — `next()` for allow/journal, a deny decision
 * for deny, and for ask a NATIVE approval request to DSH's `approval` service.
 *
 * Every branch journals before it returns, and the journal is optional in the
 * failure direction only: a journal write that fails is logged and changes no
 * decision (see `Journal.append`).
 */
export function createGuardHandler(deps: GuardDeps) {
  const now = deps.now ?? Date.now
  return async (exec: GuardToolExecution, next: () => Promise<GuardPreToolDecision>): Promise<GuardPreToolDecision> => {
    const tool = exec.name ?? exec.tool ?? ''
    const args = exec.args ?? exec.arguments
    const cwd = exec.agent?.session?.header?.cwd
    const session = exec.agent?.session?.id
    const cfg = await deps.readConfig().catch(() => DEFAULT_CONFIG)
    const settings = {
      protectedBranches: cfg.protectedBranches,
      protectedPaths: cfg.protectedPaths,
      guardPaths: cfg.guardPaths,
    }
    const verdict = classify({ tool, args, cwd, settings, branchOf: deps.branchOf })
    const { tier } = decide(verdict, cfg.rules)

    if (!deps.policy.isAllowed(tool, args)) {
      await deps.journal.append({ session, tool, rule: 'policy.deny', tier: 'deny', target: verdict.target, cwd, outcome: 'denied' })
      return { kind: 'deny', reason: `tool ${tool} denied by policy` }
    }
    if (tier === 'allow') return next()
    if (tier === 'journal') {
      await deps.journal.append({ session, tool, rule: verdict.ruleId, tier, target: verdict.target, repo: verdict.repo, branch: verdict.branch, cwd, outcome: 'passed' })
      return next()
    }
    const reason = renderReason(verdict, redact)
    if (tier === 'deny') {
      await deps.journal.append({ session, tool, rule: verdict.ruleId, tier, target: verdict.target, cwd, outcome: 'denied' })
      return { kind: 'deny', reason }
    }
    const t0 = now()
    const outcome = await deps.requestApproval({
      agent: exec.agent, toolName: tool, callId: exec.callId, reason, signal: exec.signal,
    })
    await deps.journal.append({
      session, tool, rule: verdict.ruleId, tier, target: verdict.target, repo: verdict.repo,
      branch: verdict.branch, cwd, outcome, askMs: now() - t0,
    })
    return outcome === 'granted' ? { kind: 'allow' } : { kind: 'deny', reason: `${reason} — ${EXPLAIN[outcome]}` }
  }
}

/**
 * Branch of the repo a command targets. The caller resolves the repo directory
 * itself (`git -C` / `cd` handling lives in `rules.ts`); an EMPTY directory is
 * the "no resolvable repo" sentinel and must never be turned into
 * `git -C ""`, which would silently resolve to the session cwd and re-create
 * the false positives the repo resolution exists to remove.
 */
export function branchOf(dir: string): string | undefined {
  if (!dir) return undefined
  try {
    return execSync('git branch --show-current', { cwd: dir, timeout: 800, encoding: 'utf-8' }).trim() || undefined
  } catch {
    return undefined
  }
}

/** The DSH approval service, structurally typed (the guard never imports it). */
interface NativeApproval {
  request(req: { agent: unknown; toolName: string; callId?: string; reason: string; signal?: AbortSignal }): Promise<string>
}

export default {
  inject: ['tools'] as const,
  apply(ctx: Context) {
    const journal = new Journal()
    const policy = new PermissionPolicy({ deny: ['danger-tool'] })
    const requestApproval = async (req: { agent?: unknown; toolName: string; callId?: string; reason: string; signal?: AbortSignal }): Promise<AskOutcome> => {
      const approval = ctx.get('approval') as NativeApproval | undefined
      if (!approval || req.agent === undefined) return 'unavailable'
      try {
        const outcome = await approval.request({
          agent: req.agent, toolName: req.toolName, callId: req.callId, reason: req.reason, signal: req.signal,
        })
        return outcome === 'allowed-once' ? 'granted' : (outcome as AskOutcome)
      } catch (e) {
        console.error('[dsh-maestro-guard] approval request failed:', (e as Error)?.message)
        return 'error'
      }
    }
    const handler = createGuardHandler({ journal, policy, readConfig: loadGuardConfig, branchOf, requestApproval })
    ctx.effect(() => ctx.on('tools/pre-execute', handler as any))
    ctx.effect(() => { void retireLegacyStore(journal); return () => {} }, 'guard-retire-legacy-store')
    // register on-demand full-scan tool (Task 4) alongside guard handler
    applyFullScan(ctx, {})
  },
}
