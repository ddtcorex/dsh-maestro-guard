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
})
