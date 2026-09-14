import { describe, it, expect } from 'vitest'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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

/**
 * Task C3 fix round 1 — `domains.guard.workingDirContainment` used to be inert:
 * the README documented it, but `classify` never read it and hardcoded the
 * temp/spill exemptions. These cases pin the wired contract: containment is ON
 * unless `enabled` is explicitly false, and the runtime-spill exemption applies
 * only while `spillReads` is on (the OS temp exemption is unaffected).
 */
describe('workingDirContainment', () => {
  const outside = { file_path: '/etc/hosts', content: 'x' }
  const spill = { file_path: join(tmpdir(), 'dsh-spill-abc', 'session-1', 'x.txt'), content: 'x' }
  const withContainment = (args: unknown, workingDirContainment: { enabled?: boolean; spillReads?: boolean }) =>
    classify({ tool: 'write', args, cwd: '/repo', settings: { ...settings, workingDirContainment } })

  it('gates an outside-cwd write by default (no workingDirContainment block)', () => {
    expect(run('write', outside)).toMatchObject({ ruleId: 'fs.write.outside', tier: 'ask' })
  })

  it('gates an outside-cwd write when containment is explicitly enabled', () => {
    expect(withContainment(outside, { enabled: true, spillReads: true })).toMatchObject({
      ruleId: 'fs.write.outside',
      tier: 'ask',
    })
  })

  it('does not gate an outside-cwd write when enabled is false', () => {
    expect(withContainment(outside, { enabled: false }).tier).toBe('allow')
  })

  it('keeps the protected-path rule live when containment is disabled', () => {
    // `enabled: false` disables the outside-cwd write rule only — it is not a
    // blanket write amnesty: secret.access still fires on the protected path.
    const protectedPath = settings.protectedPaths[0]
    expect(withContainment({ file_path: protectedPath, content: 'x' }, { enabled: false })).toMatchObject({
      ruleId: 'secret.access',
      tier: 'ask',
    })
  })

  it('exempts a runtime-spill write while spillReads is on (default)', () => {
    expect(withContainment(spill, { enabled: true, spillReads: true }).tier).toBe('allow')
  })

  it('gates a runtime-spill write when spillReads is false', () => {
    expect(withContainment(spill, { enabled: true, spillReads: false })).toMatchObject({
      ruleId: 'fs.write.outside',
      tier: 'ask',
    })
  })

  it('keeps the OS temp exemption when spillReads is false', () => {
    // The spill switch removes the spill exemption, not the temp exemption:
    // ordinary scratch work under os.tmpdir() stays allowed.
    expect(withContainment({ file_path: join(tmpdir(), 'scratch-notes.md'), content: 'x' }, { spillReads: false }).tier).toBe('allow')
  })
})
