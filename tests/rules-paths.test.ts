import { describe, it, expect } from 'vitest'
import { classify } from '../src/host/rules.js'
import { defaultProtectedPaths, guardConfigPaths } from '../src/host/paths.js'

/**
 * Task B4 — the path rules through `classify`, with every value under test
 * derived from the `paths.ts` factories. No protected path is written literally:
 * the classifier is fed exactly what `config.ts` would hand it in production.
 *
 * These are the access/mention and tamper cases that used to be reachable only
 * through the deleted `sandbox.ts` shim (`checkSandbox`/`guard`); the pipeline
 * decision they pin is now `classify`'s.
 */
const settings = {
  protectedBranches: ['master'],
  protectedPaths: defaultProtectedPaths('/home/u/.dsh'),
  guardPaths: guardConfigPaths('/home/u/.dsh'),
}
const run = (tool: string, args: unknown) => classify({ tool, args, cwd: '/repo', settings })

describe('path rules', () => {
  it('never gates prose that mentions a protected path', () => {
    expect(run('write', { file_path: '/repo/doc.md', content: settings.protectedPaths[0] }).tier).toBe('allow')
    expect(run('memory', { action: 'add', content: settings.protectedPaths[0] }).tier).toBe('allow')
  })

  it('gates an executing read of a protected path', () => {
    expect(run('bash', { command: `cat ${settings.protectedPaths[0]}` })).toMatchObject({
      ruleId: 'secret.access',
      tier: 'ask',
    })
  })

  it('does not gate a mention-only verb that scans the same path', () => {
    expect(run('bash', { command: `grep -rn ${settings.protectedPaths[0]} docs/` }).tier).toBe('allow')
  })

  it('denies a write to the guard configuration', () => {
    expect(run('write', { file_path: settings.guardPaths[0], content: '{}' })).toMatchObject({
      ruleId: 'guard.tamper',
      tier: 'deny',
    })
  })

  it('denies a raw command that rewrites the guard configuration', () => {
    expect(run('bash', { command: `cp /tmp/x ${settings.guardPaths[0]}` })).toMatchObject({
      ruleId: 'guard.tamper',
      tier: 'deny',
    })
  })

  it('gates a file write outside the session cwd', () => {
    expect(run('write', { file_path: '/etc/hosts', content: 'x' })).toMatchObject({
      ruleId: 'fs.write.outside',
      tier: 'ask',
    })
  })

  it('allows a file write inside the session cwd', () => {
    expect(run('write', { file_path: '/repo/docs/notes.md', content: 'x' }).tier).toBe('allow')
  })
})
