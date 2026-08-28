export const DEFAULT_PATTERNS: RegExp[] = [
  /glpat-[A-Za-z0-9_-]{10,}/g,
  /sk-[A-Za-z0-9]{20,}/g,
  /ghp_[A-Za-z0-9]{30,}/g,
  /xox[bpras]-[A-Za-z0-9-]+/g,
]
export function containsSecret(text: string): boolean {
  return DEFAULT_PATTERNS.some(r => { r.lastIndex=0; return r.test(text) })
}
export function redact(text: string): string {
  let out = text
  for (const r of DEFAULT_PATTERNS) { r.lastIndex=0; out = out.replace(r, '[REDACTED]') }
  return out
}
