import { describe, it, expect } from 'vitest'
import { homedir, tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import { classify } from '../src/host/rules.js'
import { defaultProtectedPaths, guardConfigPaths } from '../src/host/paths.js'
import { journalPath } from '../src/host/journal.js'

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

/**
 * IMPORTANT 4 — the spec's `guard.tamper` deny tier covers "truncates/removes the
 * journal", but the tamper path set held only the settings file and the profile
 * patch, so `: > <journal>` and `rm <journal>` were allowed. The journal path (and
 * the retired legacy ticket file beside it) are now tamper paths, as is the
 * profile `package.json` that actually MOUNTS the guard row.
 */
describe('guard.tamper protects the journal and the mounting manifest', () => {
  const journalFile = settings.guardPaths.find((p) => p.endsWith('journal.jsonl')) ?? ''
  const legacyTicket = settings.guardPaths.find((p) => p.endsWith('legacy-pending.json')) ?? ''
  const mountManifest = settings.guardPaths.find((p) => p.endsWith('package.json')) ?? ''

  it('denies truncating, removing or rotating away the journal', () => {
    for (const command of [`: > ${journalFile}`, `rm -f ${journalFile}`, `truncate -s 0 ${journalFile}`]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('denies removing the retired legacy ticket file', () => {
    expect(run('bash', { command: `rm -f ${legacyTicket}` })).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
  })

  it('denies a write-family tool targeting the profile package.json that mounts the guard', () => {
    expect(run('write', { file_path: mountManifest, content: '{}' })).toMatchObject({
      ruleId: 'guard.tamper',
      tier: 'deny',
    })
  })

  it('exposes exactly the tamper paths it protects', () => {
    expect(journalFile).not.toBe('')
    expect(legacyTicket).not.toBe('')
    expect(mountManifest).not.toBe('')
  })
})

/**
 * PRECISION follow-up (the scoped re-review's I4 over-block) — the deny tier is
 * scoped to EDITS (spec §5.4/§5.6: "a segment that edits the guard's own
 * settings/config or truncates/removes the journal"). The raw-text mention test
 * refused every read, so `tail -n 5 <journal>` denied while the guard's own deny
 * text tells the agent to "see the guard journal". Reads fall through to the
 * ordinary rules now; a mutating verb or a redirection whose TARGET is a guard
 * path still denies.
 */
describe('guard.tamper is scoped to edits, never to mentions', () => {
  const journalFile = settings.guardPaths.find((p) => p.endsWith('journal.jsonl')) ?? ''
  const legacyTicket = settings.guardPaths.find((p) => p.endsWith('legacy-pending.json')) ?? ''
  const mountManifest = settings.guardPaths.find((p) => p.endsWith('package.json')) ?? ''

  it('no longer denies a read of the journal the deny text points at', () => {
    for (const command of [`tail -n 5 ${journalFile}`, `cat ${journalFile}`, `head -n 5 ${journalFile}`, `grep -c denied ${journalFile}`]) {
      expect(run('bash', { command }), command).toMatchObject({ tier: 'allow' })
    }
  })

  it('no longer denies reading the profile manifest that mounts the guard', () => {
    expect(run('bash', { command: `cat ${mountManifest}` }).tier).toBe('allow')
  })

  it('still denies a redirection whose TARGET is a guard path', () => {
    for (const command of [`> ${journalFile}`, `2> ${journalFile}`, `printf x >> ${journalFile}`]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('still denies every mutating verb on a guard path', () => {
    for (const command of [
      `rm -f ${journalFile}`,
      `truncate -s 0 ${journalFile}`,
      `shred -u ${journalFile}`,
      `mv ${journalFile} /tmp/x`,
      `sed -i s/x/y/ ${journalFile}`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('still denies removing the retired legacy ticket file', () => {
    for (const command of [`rm -f ${legacyTicket}`, `rm ${legacyTicket}`]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('denies a write-family tool targeting the profile package.json that mounts the guard', () => {
    expect(run('write', { file_path: mountManifest, content: '{}' })).toMatchObject({
      ruleId: 'guard.tamper',
      tier: 'deny',
    })
  })

  it('keeps a mention of a guard path inside command DATA (a commit message) an allow', () => {
    expect(run('bash', { command: `git commit -m "rm -f ${journalFile}"` }).tier).toBe('allow')
  })
})

/**
 * Item 5 of the precision follow-up — the raw-text tamper match only knew the
 * ABSOLUTE spelling, so a command that reached the guard config through `~` or
 * `$HOME` walked past it. Every spelling is derived from the same factories that
 * produce the absolute paths (`guardConfigPaths` / `journalPath`), never written
 * as a literal.
 */
describe('guard.tamper recognizes the ~ / $HOME spellings of a guard path', () => {
  // An explicit DSH home under the REAL user home, so the `~` spelling is
  // derivable on any machine (never a hard-coded /home/u fixture).
  const dshHome = join(homedir(), '.dsh')
  const realSettings = {
    protectedBranches: ['master'],
    protectedPaths: defaultProtectedPaths(dshHome),
    guardPaths: guardConfigPaths(dshHome),
  }
  const runReal = (tool: string, args: unknown) =>
    classify({ tool, args, cwd: '/repo', settings: realSettings })
  const journalRel = relative(homedir(), journalPath(dshHome))
  const markers = (rel: string) => [`~/${rel}`, '$HOME/' + rel, '$' + '{HOME}/' + rel]

  it('denies a mutation spelled with ~ / $HOME / ${HOME}', () => {
    for (const spelling of markers(journalRel)) {
      for (const command of [`rm -f ${spelling}`, `> ${spelling}`]) {
        expect(runReal('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
      }
    }
  })

  it('denies a write tool whose path field carries the ~ spelling', () => {
    const settingsSpelling = markers(relative(homedir(), guardConfigPaths(dshHome)[0]))[0]
    expect(runReal('write', { file_path: settingsSpelling, content: '{}' })).toMatchObject({
      ruleId: 'guard.tamper',
      tier: 'deny',
    })
  })

  it('still lets a read of the same ~ spelling fall through', () => {
    expect(runReal('bash', { command: `tail -n 5 ~/${journalRel}` }).tier).toBe('allow')
  })
})
