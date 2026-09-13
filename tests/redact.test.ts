import { describe, it, expect } from 'vitest'
import { redact, containsSecret } from '../src/host/redact.js'

// Secret values are assembled at runtime. A raw token literal in this file would
// be rewritten by the guard's own pre-execute path before the test could read it
// (observed live while writing this suite) — which is exactly the mutation this
// module's guard-side change removes.
const GLPAT = 'glpat-' + 'abc123DEF4567890extra'
const SK = 'sk-' + '12345678901234567890'
const SK_LONG = 'sk-' + '1234567890123456789012345'
const GHP = 'ghp_' + 'a'.repeat(36)
const NPM = 'registry=npm_' + 'a1B2c3D4e5F6g7H8i9J0k1'
const ENV_ASSIGN = 'DEPLOY_' + 'TOKEN=' + 'supersecretvalue'
const AUTH_HEADER = 'Authorization' + ': Bearer ' + 'abcdef123456'
const PRIVATE_KEY = '-----BEGIN RSA ' + 'PRIVATE KEY-----\nMIIabc\n-----END RSA ' + 'PRIVATE KEY-----'

describe('redact', () => {
  it('keeps the pre-existing families covered', () => {
    expect(redact('token ' + GLPAT)).toBe('token [REDACTED]')
    expect(redact(GHP)).not.toContain('ghp_')
    // Redaction is idempotent: already-redacted text stays stable.
    expect(redact('token [REDACTED]')).toBe('token [REDACTED]')
  })

  it('covers registry tokens, env assignments, auth headers and private keys', () => {
    expect(redact(NPM)).toContain('[REDACTED]')
    expect(redact(ENV_ASSIGN)).toBe('DEPLOY_TOKEN=[REDACTED]')
    expect(redact(AUTH_HEADER)).toBe('Authorization: Bearer [REDACTED]')
    expect(redact(PRIVATE_KEY)).toBe('[REDACTED]')
  })

  it('leaves ordinary prose untouched', () => {
    const s = 'the docs mention the DSH home and a token variable name'
    expect(redact(s)).toBe(s)
    expect(containsSecret(s)).toBe(false)
  })
})

describe('containsSecret', () => {
  it('detects known families and ignores ordinary text', () => {
    expect(containsSecret('Bearer ' + SK)).toBe(true)
    expect(containsSecret(GLPAT)).toBe(true)
    expect(containsSecret(ENV_ASSIGN)).toBe(true)
    expect(containsSecret(AUTH_HEADER)).toBe(true)
    expect(containsSecret(PRIVATE_KEY)).toBe(true)
    expect(containsSecret('hello world')).toBe(false)
  })

  it('resets lastIndex so repeated calls on the same text agree', () => {
    const text = 'token ' + GLPAT
    expect(containsSecret(text)).toBe(true)
    expect(containsSecret(text)).toBe(true)
    const text2 = 'Bearer ' + SK
    expect(containsSecret(text2)).toBe(true)
    expect(containsSecret(text2)).toBe(true)
  })

  it('ignores tokens below the length thresholds and leaves them unredacted', () => {
    expect(containsSecret('glpat-short1')).toBe(false)
    expect(containsSecret('sk-123')).toBe(false)
    expect(redact('token glpat-short1 here')).toBe('token glpat-short1 here')
    expect(redact('token sk-123 here')).toBe('token sk-123 here')
  })

  it('redacts every family present in one string', () => {
    expect(redact('a ' + GLPAT + ' b ' + SK_LONG)).toBe('a [REDACTED] b [REDACTED]')
  })
})
