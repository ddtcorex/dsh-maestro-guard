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
 * Fix wave after the scoped re-review — narrowing the deny tier to EDITS left a
 * set of mutation SHAPES it no longer saw, because the mutation verb was not the
 * segment's own verb: it sat behind an exec wrapper (`nice`/`timeout`/`flock`/
 * `ssh`/`doas`/`xargs`/`eval`), inside the command `find -exec`/`-execdir`/`-ok`
 * runs, inside a `-c` script handed to a shell, or behind a clobber redirect the
 * tokenizer split at the `|`. Every one of them was an ALLOW — a wipe of the
 * guard's own journal with no prompt — where the pre-fix build denied even the
 * bare mention. `ln` (a symlink swap in place of the journal) joins the mutating
 * verbs for the same reason.
 *
 * The other direction stays pinned: a mention-led read of the same path is still
 * an allow, so the exemption that made the journal readable cannot be re-broken
 * by this wave.
 */
describe('guard.tamper sees a mutation the segment verb does not name', () => {
  const journalFile = settings.guardPaths.find((p) => p.endsWith('journal.jsonl')) ?? ''
  const mountManifest = settings.guardPaths.find((p) => p.endsWith('package.json')) ?? ''
  const settingsFile = settings.guardPaths.find((p) => p.endsWith('settings.json')) ?? ''

  it('denies a mutation hidden behind an exec wrapper', () => {
    for (const command of [
      `nice rm -f ${journalFile}`,
      `timeout 5 rm -f ${journalFile}`,
      `flock /tmp/l rm -f ${journalFile}`,
      `ssh host rm -f ${journalFile}`,
      `doas rm -f ${journalFile}`,
      `xargs rm -f ${journalFile}`,
      `eval rm -f ${journalFile}`,
      `nice truncate -s 0 ${settingsFile}`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('denies a mutation inside a -c script the segment hands to a shell', () => {
    for (const command of [
      `timeout 5 bash -c "rm -f ${journalFile}"`,
      `find . -exec bash -c "rm -f ${journalFile}" +`,
      `find . -exec sh -c "mv ${journalFile} /tmp/x" +`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('denies a mutation find hands to -exec, -execdir or -ok', () => {
    for (const command of [
      `find . -exec rm -f ${journalFile} +`,
      `find . -execdir rm -f ${journalFile} +`,
      `find . -ok rm -f ${journalFile} +`,
      `find . -exec truncate -s 0 ${mountManifest} +`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('denies an opaque verb whose target arrives through the pipeline', () => {
    for (const command of [`echo ${journalFile} | xargs rm -f`, `cat ${journalFile} | xargs shred -u`]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('denies a clobber redirect and a symlink swap', () => {
    for (const command of [`echo x >| ${journalFile}`, `ln -sf /tmp/x ${journalFile}`, `ln -f /tmp/x ${settingsFile}`]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('keeps a mention-led READ of the same path an allow', () => {
    for (const command of [
      `rg rm ${journalFile}`,
      `grep -c rm ${journalFile}`,
      `echo rm -f ${journalFile}`,
      `timeout 5 cat ${journalFile}`,
      `find . -exec cat ${journalFile} +`,
      `find . -execdir sh -c "cat ${journalFile}" +`,
      `xargs cat ${journalFile}`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ tier: 'allow' })
    }
  })

  it('reads a mutation word as a command only where a segment can run one', () => {
    // The descendant scan must not turn a mutation WORD in a data position into an
    // edit: the first fix wave read every token of a non-mention segment, which
    // denied `less -p rm <journal>` — a read the README promises falls through —
    // and a few semantically wrong but harmless shapes. Only the parser's own
    // "runs a trailing command" class (EXEC_WRAPPERS ∪ OPAQUE_VERBS) descends.
    for (const command of [
      `less -p rm ${journalFile}`,
      `ag rm ${journalFile}`,
      `git commit -m rm ${journalFile}`,
      `tar -cf /tmp/x.tar rm ${journalFile}`,
      `docker rm ${journalFile}`,
      `node -e rm ${journalFile}`,
      `gcc -c "rm -f ${journalFile}"`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ tier: 'allow' })
    }
  })

  it('does not let an unrelated opaque segment borrow a path named elsewhere', () => {
    // The opaque-verb rule exists for a PIPELINE (`echo <path> | xargs rm -f`),
    // where the target really does arrive from the sibling segment. Keying it on
    // "any segment names a guard path" denied ordinary compounds whose `&&`
    // sibling happened to run `xargs rm` on something else.
    for (const command of [
      `tail ${journalFile} && xargs rm -rf /tmp/junk`,
      `grep -c x ${journalFile} || xargs rm -f /tmp/junk`,
      `diff ${journalFile} /tmp/copy; eval hostname`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ tier: 'allow' })
    }
  })

  it('ignores an xargs substitution that never consumes its input', () => {
    // `-I{}` replaces the input line only where the placeholder appears, so a
    // command that never writes it does not touch the path the pipeline names.
    expect(run('bash', { command: `echo ${journalFile} | xargs -I{} rm -rf /tmp/junk` }).tier).toBe('allow')
    expect(run('bash', { command: `echo ${journalFile} | xargs -I{} rm -f {}` })).toMatchObject({
      ruleId: 'guard.tamper',
      tier: 'deny',
    })
  })

  it('follows a pipeline through the segments between the path and the opaque verb', () => {
    // The borrow used to look only at the IMMEDIATELY preceding segment, so any
    // pass-through command in between reopened the shape the first wave closed.
    for (const command of [
      `cat ${journalFile} | xargs rm -f`,
      `cat ${journalFile} | tee /tmp/x | xargs rm -f`,
      `cat ${journalFile} | grep x | xargs rm -f`,
      `cat ${journalFile} | sort | xargs rm -f`,
      `cat ${journalFile} 2>/dev/null | grep x | xargs rm -f`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
    // …and a chain broken by any other operator still cannot carry the path.
    for (const command of [
      `tail ${journalFile} && xargs rm -rf /tmp/junk`,
      `cat ${journalFile}; xargs rm -rf /tmp/junk`,
      `cat ${journalFile} | tee /tmp/x && xargs rm -rf /tmp/junk`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ tier: 'allow' })
    }
  })

  it('descends through every wrapper in the parser set, not a hand-picked sample', () => {
    // `descendantStarts` keys on EXEC_WRAPPERS ∪ OPAQUE_VERBS by name, so the
    // boundary is that SET; a representative from each shape keeps it honest.
    for (const wrapper of [
      'watch',
      'setsid',
      'stdbuf',
      'strace',
      'parallel',
      'chroot',
      'runuser',
      'script',
      'bwrap',
      'systemd-run',
      'taskset',
      'ionice',
      'ltrace',
      'su',
      'doas',
      'xargs -n1',
    ]) {
      expect(run('bash', { command: `${wrapper} rm -f ${journalFile}` }), wrapper).toMatchObject({
        ruleId: 'guard.tamper',
        tier: 'deny',
      })
    }
  })

  it('denies every other writer that destroys the file it names', () => {
    // The verb family is the deny tier's weak spot: a closed list missed the
    // transfers and editors that write or remove their target, all of which were
    // an allow while the journal/settings could be overwritten with no prompt.
    for (const command of [
      `rsync -a /tmp/x ${journalFile}`,
      `scp /tmp/x ${journalFile}`,
      `curl -o ${journalFile} https://example.invalid/j`,
      `curl --output=${journalFile} https://example.invalid/j`,
      `wget -O ${journalFile} https://example.invalid/j`,
      `wget --output-document=${journalFile} https://example.invalid/j`,
      `printf x | sponge ${journalFile}`,
      `patch ${settingsFile} < /tmp/p.diff`,
      `unlink ${journalFile}`,
      `rmdir ${journalFile}`,
      `vi ${settingsFile}`,
      `vim -c wq ${settingsFile}`,
      `ed ${journalFile}`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
  })

  it('reads through the dual-use verbs instead of denying their READ shape', () => {
    // `curl`/`wget`/`rsync`/`scp`/`vi`/`nano` are dual-use: a bare membership in
    // the writer family made every read form an unappealable deny, contradicting
    // the same release's "a read of the guard path falls through" contract.
    for (const command of [
      `curl ${journalFile}`,
      `curl -I ${journalFile}`,
      `curl -s ${journalFile}`,
      `curl -d @${journalFile} https://example.invalid/u`,
      `wget -q -O - ${journalFile}`,
      `rsync --list-only ${journalFile} /tmp/`,
      `rsync ${journalFile} /tmp/x`,
      `scp -r host:${journalFile} /tmp/`,
      `vi -R ${journalFile}`,
      `vim -R ${journalFile}`,
      `vim -M ${journalFile}`,
      `nano -v ${journalFile}`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ tier: 'allow' })
    }
  })

  it('denies the write shape of a dual-use verb even when flags follow the path', () => {
    for (const command of [
      `rsync -a /tmp/x ${journalFile} --delete`,
      `rsync -a --exclude x /tmp/y ${journalFile}`,
      `timeout 5 vi ${journalFile}`,
      `find . -exec curl -o ${journalFile} https://example.invalid/j +`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    }
    // A guard path in the SOURCE position of a transfer is not a write …
    expect(run('bash', { command: `rsync -a --exclude ${journalFile} /tmp/x /tmp/y` }).tier).toBe('allow')
    // … and `ed` has no read-only mode, so it stays an unconditional writer.
    expect(run('bash', { command: `ed -l ${journalFile}` })).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
  })

  it('keeps a transfer that names no guard path an allow', () => {
    for (const command of [
      'rsync -a /tmp/x /tmp/y',
      'curl -o /tmp/x https://example.invalid/j',
      'wget -O /tmp/x https://example.invalid/j',
      `curl -T /tmp/x https://example.invalid/upload`,
    ]) {
      expect(run('bash', { command }), command).toMatchObject({ tier: 'allow' })
    }
  })

  it('records the script-depth boundary instead of leaving it silent', () => {
    // `mutatesGuardPath` reads a `-c` script to a depth of two: two levels deny
    // (pinned above), a third is not read. Exotic enough to accept as a boundary,
    // but it is a boundary, so it is pinned rather than implied.
    const deep = `find . -exec bash -c "bash -c 'bash -c \\"rm -f ${journalFile}\\""' +`
    expect(run('bash', { command: deep }).tier).toBe('allow')
  })

  it('deliberately does not treat touch on a guard path as an edit', () => {
    // Documented ruling: `touch` changes mtime and destroys no content, and an
    // empty config loads as the built-in defaults. The deny tier's bar is
    // "edits the config or truncates/removes the journal".
    expect(run('bash', { command: `touch ${journalFile}` }).tier).toBe('allow')
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
