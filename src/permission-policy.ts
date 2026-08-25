export interface GuardPolicy { allow?: string[]; deny?: string[] }
export class PermissionPolicy {
  constructor(private policy: GuardPolicy) {}
  isAllowed(tool: string, _args: unknown): boolean {
    if (this.policy.deny?.includes(tool)) return false
    if (this.policy.allow && this.policy.allow.length > 0) return this.policy.allow.includes(tool)
    return true
  }
  check(tool: string): 'allow'|'deny'|'ask' {
    if (this.policy.deny?.includes(tool)) return 'deny'
    const hasAllow = Array.isArray(this.policy.allow) && this.policy.allow.length > 0
    if (hasAllow && !this.policy.allow!.includes(tool)) return 'ask'
    return 'allow'
  }
}
