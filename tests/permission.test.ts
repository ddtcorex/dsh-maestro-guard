import { describe, it, expect } from 'vitest'
import { PermissionPolicy } from '../src/host/permission-policy.js'

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
  it('deny wins when tool in both allow and deny (isAllowed)', () => {
    const p = new PermissionPolicy({ allow: ['shared-tool'], deny: ['shared-tool'] })
    expect(p.isAllowed('shared-tool', {})).toBe(false)
  })
  it('deny wins when tool in both allow and deny (check)', () => {
    const p = new PermissionPolicy({ allow: ['shared-tool'], deny: ['shared-tool'] })
    expect(p.check('shared-tool')).toBe('deny')
  })
  it('check mapping table: allow/deny/ask incl empty allow [] -> allow', () => {
    const pAllow = new PermissionPolicy({ allow: ['safe-tool'] })
    expect(pAllow.check('safe-tool')).toBe('allow')
    expect(pAllow.check('other')).toBe('ask')
    const pDeny = new PermissionPolicy({ deny: ['danger-tool'] })
    expect(pDeny.check('danger-tool')).toBe('deny')
    expect(pDeny.check('other')).toBe('allow')
    const pEmptyAllow = new PermissionPolicy({ allow: [] })
    expect(pEmptyAllow.check('anything')).toBe('allow')
    expect(pEmptyAllow.isAllowed('anything', {})).toBe(true)
    const pNone = new PermissionPolicy({})
    expect(pNone.check('anything')).toBe('allow')
    expect(pNone.isAllowed('anything', {})).toBe(true)
  })
  it('undefined args accepted', () => {
    const p = new PermissionPolicy({ deny: ['danger-tool'] })
    expect(p.isAllowed('good', undefined)).toBe(true)
    expect(p.isAllowed('danger-tool', undefined)).toBe(false)
    const p2 = new PermissionPolicy({ allow: ['safe-tool'] })
    expect(p2.isAllowed('safe-tool', undefined)).toBe(true)
    expect(p2.isAllowed('other', undefined)).toBe(false)
  })
})
