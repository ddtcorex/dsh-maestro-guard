import { describe, it, expect } from 'vitest'
import { PermissionPolicy } from '../src/permission-policy.js'

describe('PermissionPolicy', () => {
  it('deny list blocks', () => {
    const p = new PermissionPolicy({ deny: ['danger-tool'] })
    expect(p.isAllowed('danger-tool', {})).toBe(false)
  })
  it('allow list restricts', () => {
    const p = new PermissionPolicy({ allow: ['safe-tool'] })
    expect(p.isAllowed('safe-tool', {})).toBe(true)
    expect(p.isAllowed('other', {})).toBe(false)
  })
  it('allow empty means all allowed except deny', () => {
    const p = new PermissionPolicy({ deny: ['bad'] })
    expect(p.isAllowed('good', {})).toBe(true)
  })
})
