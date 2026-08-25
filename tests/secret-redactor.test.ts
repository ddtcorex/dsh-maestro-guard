import { describe, it, expect } from 'vitest'
import { redact, containsSecret } from '../src/secret-redactor.js'

describe('secret-redactor', () => {
  it('redacts gitlab token', () => {
    expect(redact('token glpat-abc123DEF4567890extra')).toBe('token [REDACTED]')
  })
  it('detects secret', () => {
    expect(containsSecret('Bearer sk-12345678901234567890')).toBe(true)
    expect(containsSecret('hello world')).toBe(false)
  })
  it('redacts multiple', () => {
    expect(redact('a glpat-1234567890abc b sk-1234567890123456789012345')).toContain('[REDACTED]')
  })
  it('sequential containsSecret calls on same text both return true (lastIndex reset)', () => {
    const text = 'token glpat-abc123DEF4567890extra'
    expect(containsSecret(text)).toBe(true)
    expect(containsSecret(text)).toBe(true)
    const text2 = 'Bearer sk-12345678901234567890'
    expect(containsSecret(text2)).toBe(true)
    expect(containsSecret(text2)).toBe(true)
  })
  it('short tokens below thresholds are not detected and not redacted', () => {
    expect(containsSecret('glpat-short1')).toBe(false)
    expect(containsSecret('sk-123')).toBe(false)
    expect(redact('token glpat-short1 here')).toBe('token glpat-short1 here')
    expect(redact('token sk-123 here')).toBe('token sk-123 here')
  })
})
