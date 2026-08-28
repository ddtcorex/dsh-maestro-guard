import '@deepseek-ai/cordis'

export interface GuardToolExecution { name: string; tool?: string; args?: unknown; arguments?: unknown }
export interface GuardPreToolDecision { kind: 'allow' | 'deny' }

declare module '@deepseek-ai/cordis' {
  interface Events {
    'tools/pre-execute'(exec: GuardToolExecution, next: () => Promise<GuardPreToolDecision>): Promise<GuardPreToolDecision>
  }
}
