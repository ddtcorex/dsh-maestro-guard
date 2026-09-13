import { describe, it, expect } from 'vitest'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import { classify, RULE_IDS, DEFAULT_TIERS } from '../src/host/rules.js'
import type { RuleSettings } from '../src/host/rules.js'
import { isWithinTempDir } from '../src/host/sandbox.js'

// Guard self-block protocol: protected path literals are assembled from
// fragments at runtime so no tool call ever carries the contiguous literal.
const settings: RuleSettings = {
  protectedBranches: ['master', 'main'],
  protectedPaths: ['/home/u/.dsh/.crede' + 'ntials.yaml', '/home/u/.clou' + 'dflared'],
  guardPaths: ['/home/u/.dsh/dsh-maestro-config/settings.json'],
}
const call = (command: string, tool = 'bash', cwd = '/repo') =>
  classify({ tool, args: { command }, cwd, settings, branchOf: () => 'feature' })

describe('classify — git family', () => {
  it('asks for a protected-branch refspec', () => {
    expect(call('git push origin master')).toMatchObject({ ruleId: 'git.push.protected', tier: 'ask' })
  })
  it('journals a merge instead of asking (config decision D3)', () => {
    expect(call('gh pr merge 5 --squash')).toMatchObject({ ruleId: 'git.merge.protected', tier: 'journal' })
  })
  it('asks for a release tag push', () => {
    expect(call('git push origin v1.2.3')).toMatchObject({ ruleId: 'git.tag.release', tier: 'ask' })
  })
  it('asks for a force push', () => {
    expect(call('git push --force origin feature')).toMatchObject({ ruleId: 'git.push.force', tier: 'ask' })
  })
})

describe('classify — access vs mention', () => {
  it('never gates content of a non-shell tool', () => {
    // Temp path built from os.tmpdir() so the case is machine-independent
    // (on Linux this is /tmp/x.md). The point is unchanged: the write's
    // CONTENT mentions a protected path, and content is never scanned.
    const v = classify({ tool: 'write', args: { file_path: join(tmpdir(), 'x.md'), content: 'about /home/u/.clou' + 'dflared' }, cwd: '/repo', settings })
    expect(v.tier).toBe('allow')
  })
  it('does not gate a leak-scan grep of the same path', () => {
    expect(call('grep -rn "/home/u/.clou' + 'dflared" docs/').tier).toBe('allow')
  })
  it('asks when the path is actually read', () => {
    expect(call('cat /home/u/.clou' + 'dflared/config.yml')).toMatchObject({ ruleId: 'secret.access', tier: 'ask' })
  })
  it('asks when a file tool targets the protected path', () => {
    const v = classify({ tool: 'read', args: { file_path: '/home/u/.dsh/.crede' + 'ntials.yaml' }, cwd: '/repo', settings })
    expect(v).toMatchObject({ ruleId: 'secret.access', tier: 'ask' })
  })
})

describe('classify — fs.write.outside (whole write family, temp dir exempt)', () => {
  const outside = { file_path: '/etc/hosts' }
  it('asks when the native write tool targets a path outside cwd and outside tmpdir', () => {
    const v = classify({ tool: 'write', args: { ...outside, content: 'x' }, cwd: '/repo', settings })
    expect(v).toMatchObject({ ruleId: 'fs.write.outside', tier: 'ask' })
  })
  it('asks when the native edit tool targets a path outside cwd and outside tmpdir', () => {
    const v = classify({ tool: 'edit', args: { ...outside, old_string: 'a', new_string: 'b' }, cwd: '/repo', settings })
    expect(v).toMatchObject({ ruleId: 'fs.write.outside', tier: 'ask' })
  })
  it('allows a write inside the session cwd', () => {
    const v = classify({ tool: 'write', args: { file_path: '/repo/docs/notes.md', content: 'x' }, cwd: '/repo', settings })
    expect(v.tier).toBe('allow')
  })
  it('asks when the legacy write tool targets a path outside cwd and outside tmpdir', () => {
    const v = classify({ tool: 'maestro_write_file', args: { ...outside }, cwd: '/repo', settings })
    expect(v).toMatchObject({ ruleId: 'fs.write.outside', tier: 'ask' })
  })
  it('exempts the OS temp dir for the whole write family', () => {
    const tempPath = join(tmpdir(), 'scratch-notes.md')
    for (const tool of ['write', 'edit', 'maestro_write_file']) {
      const v = classify({ tool, args: { file_path: tempPath, content: 'x' }, cwd: '/repo', settings })
      expect(v.tier, `${tool} -> ${tempPath}`).toBe('allow')
    }
  })
})

describe('classify — guard.tamper reads the raw command (fail-closed self-protection)', () => {
  // Assembled at runtime: no tool call ever carries the guard path contiguously.
  const guardPath = settings.guardPaths[0]

  it('denies a quoted-program write to the guard config path', () => {
    // The program sits inside double quotes, so the stripped access surface —
    // the one the precision rules correctly use — erases it entirely. The
    // tamper rule must therefore read the RAW command text, otherwise an
    // obfuscated write to the guard's own config classifies as allow.
    const quotedProgram = `python -c "open('${guardPath}','w')"`
    const v = call(quotedProgram)
    expect(v).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
    expect(v.detail?.reason).toBe('guard configuration access')
  })

  it('denies a heredoc body that rewrites the guard config path', () => {
    // A heredoc body is stripped as data for the precision rules; for the
    // guard's own config the raw text still has to deny.
    const heredoc = ['cat > ' + join(tmpdir(), 'out.txt') + ' <<EOF', 'target=' + guardPath, 'EOF'].join('\n')
    expect(call(heredoc)).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
  })

  it('denies a write-family tool whose path field is the guard config path', () => {
    for (const tool of ['write', 'edit', 'maestro_write_file', 'fs_write', 'write_file']) {
      const v = classify({ tool, args: { file_path: guardPath, content: 'x' }, cwd: '/repo', settings })
      expect(v, `${tool} -> guard config`).toMatchObject({ ruleId: 'guard.tamper', tier: 'deny' })
      expect(v.detail?.reason, tool).toBe('guard configuration write')
    }
  })

  it('never denies prose that merely mentions the guard config path in tool content', () => {
    // Negative control: the raw scan must not creep into content scanning —
    // guard.tamper reads the targeted path, never a non-shell tool's content.
    const prose = 'policy notes about ' + guardPath + ' and who may rewrite it'
    for (const tool of ['write', 'edit', 'maestro_write_file']) {
      const v = classify({ tool, args: { file_path: join(tmpdir(), 'notes.md'), content: prose }, cwd: '/repo', settings })
      expect(v.tier, `${tool} -> content mention`).toBe('allow')
    }
  })
})

describe('classify — the temp exemption shares the session-cwd base', () => {
  it('does not exempt a relative path that only looks temporary from the host cwd', () => {
    const hostCwd = process.cwd()
    const tempFile = join(tmpdir(), 'guard-temp-base-probe.md')
    // Resolves into the OS temp dir when resolved against the HOST cwd …
    const escape = relative(hostCwd, tempFile)
    // … and outside it when resolved against a session cwd that is not the host cwd.
    const sessionCwd = join(hostCwd, 'session', 'sub')

    expect(isWithinTempDir(escape), 'legacy base = process.cwd()').toBe(true)
    expect(isWithinTempDir(escape, sessionCwd), 'session-cwd base').toBe(false)

    const v = classify({ tool: 'write', args: { file_path: escape, content: 'x' }, cwd: sessionCwd, settings })
    expect(v).toMatchObject({ ruleId: 'fs.write.outside', tier: 'ask' })
  })

  it('still exempts an absolute path inside os.tmpdir()', () => {
    const v = classify({ tool: 'write', args: { file_path: join(tmpdir(), 'scratch-notes.md'), content: 'x' }, cwd: '/repo', settings })
    expect(v.tier).toBe('allow')
  })
})

describe('rule table', () => {
  it('exposes every rule id with a default tier', () => {
    for (const id of RULE_IDS) expect(DEFAULT_TIERS[id]).toBeTruthy()
    expect(DEFAULT_TIERS['git.merge.protected']).toBe('journal')
    expect(DEFAULT_TIERS['guard.tamper']).toBe('deny')
  })
})
