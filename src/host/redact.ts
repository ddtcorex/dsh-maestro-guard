/**
 * Secret families redacted from every copy the guard persists (pending tickets,
 * the decision journal). Redaction applies to the stored copy only — the guard
 * never rewrites the arguments a tool actually executes.
 *
 * The table is split in two on purpose. `SECRET_PATTERNS` are full-replace
 * patterns: the whole match becomes `[REDACTED]`. `PREFIX_KEEPING_PATTERNS` are
 * patterns whose leading capture groups must stay readable (a variable name, an
 * auth scheme); `keepGroups` says how many leading groups are copied verbatim.
 * Nothing infers that decision from a pattern's source text.
 */
export const SECRET_PATTERNS: readonly RegExp[] = [
  /glpat-[A-Za-z0-9_-]{10,}/g,
  /sk-[A-Za-z0-9]{20,}/g,
  /ghp_[A-Za-z0-9]{30,}/g,
  /xox[bpras]-[A-Za-z0-9-]+/g,
  /\bnpm_[A-Za-z0-9]{20,}/g,
  /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g, // bot-style tokens
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
]

/** A secret pattern whose leading capture groups are kept verbatim. */
export interface PrefixKeepingPattern {
  readonly re: RegExp
  /** Number of leading capture groups preserved; the matched value is redacted. */
  readonly keepGroups: number
}

export const PREFIX_KEEPING_PATTERNS: readonly PrefixKeepingPattern[] = [
  // Env assignment keeps the variable name: DEPLOY_TOKEN=secret -> DEPLOY_TOKEN=[REDACTED]
  { re: /([A-Z0-9_]{3,}_(?:TOKEN|SECRET|PASSWORD|KEY)\s*[=:]\s*)(\S+)/g, keepGroups: 1 },
  // Auth header keeps the scheme: Authorization: Bearer <value>
  { re: /((?:Authorization|Proxy-Authorization)\s*:\s*\S+\s+)(\S+)/gi, keepGroups: 1 },
]

const REDACTED = '[REDACTED]'

const ALL_PATTERNS: readonly RegExp[] = [...SECRET_PATTERNS, ...PREFIX_KEEPING_PATTERNS.map((p) => p.re)]

export function containsSecret(text: string): boolean {
  return ALL_PATTERNS.some((re) => {
    re.lastIndex = 0
    return re.test(text)
  })
}

export function redact(text: string): string {
  let out = text
  for (const re of SECRET_PATTERNS) {
    // Shared /g regexes carry lastIndex across calls; String.replace resets it,
    // but be explicit so a future non-replace use cannot inherit stale state.
    re.lastIndex = 0
    out = out.replace(re, REDACTED)
  }
  for (const { re, keepGroups } of PREFIX_KEEPING_PATTERNS) {
    re.lastIndex = 0
    out = out.replace(re, (...match: string[]) => `${match.slice(1, 1 + keepGroups).join('')}${REDACTED}`)
  }
  return out
}
