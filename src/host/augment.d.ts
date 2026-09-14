import '@deepseek-ai/cordis'

/**
 * The tool-execution payload the guard's waterfall listener receives. Only the
 * fields the guard actually reads are declared — this is a local structural
 * type, deliberately not an import from `deepseek-harness` (the workspace
 * excludes it).
 *
 * `agent`, `callId` and `signal` were added in Task A4: the native approval
 * service needs the agent (routing + audit), the exact tool call id, and the
 * live cancellation signal.
 */
export interface GuardToolExecution {
  name: string
  tool?: string
  args?: unknown
  arguments?: unknown
  agent?: { session?: { id?: string; header?: { cwd?: string } } }
  callId?: string
  signal?: AbortSignal
}

/**
 * A deny carries the human-readable reason the guard rendered (rule id plus
 * redacted target); an allow is bare.
 */
export type GuardPreToolDecision = { kind: 'allow' } | { kind: 'deny'; reason?: string }

declare module '@deepseek-ai/cordis' {
  interface Events {
    'tools/pre-execute'(exec: GuardToolExecution, next: () => Promise<GuardPreToolDecision>): Promise<GuardPreToolDecision>
  }
}
