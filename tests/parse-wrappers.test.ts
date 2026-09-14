import { describe, it, expect } from 'vitest'
import { parseCommand, unwrapSegments, MAX_WRAP_DEPTH } from '../src/host/parse.js'

// Task B2: the rule layer must never read `bash -c 'git push …'` as a bare
// `bash` again. `unwrapSegments` removes the wrappers that only change WHO runs
// a command, replaces a wrapper segment with the script it runs, and marks every
// form it cannot resolve ambiguous instead of guessing.
//
// A wrapper the guard cannot read is the interesting case: `bash script.sh`,
// `bash -c` with a missing argument and a nest deeper than the budget all run
// code the guard never sees, so each of them must set `ambiguous` (which the
// rule layer answers with a prompt, never with an allow).

describe('wrappers', () => {
  it('parses the inner script of bash -c and tags the wrapper', () => {
    const inner = unwrapSegments(parseCommand('bash -c "pnpm publish"'))
    expect(inner[0]).toMatchObject({ verb: 'pnpm', subcommand: 'publish', wrappedBy: 'bash' })
  })
  it('sees through env and sudo prefixes', () => {
    expect(unwrapSegments(parseCommand('env FOO=1 sudo git push origin main'))[0].verb).toBe('git')
  })
  it('stops at the depth limit and marks ambiguity instead', () => {
    const deep = 'bash -c "' + 'bash -c "'.repeat(4) + 'pnpm publish' + '"'.repeat(4) + '"'
    expect(unwrapSegments(parseCommand(deep)).some((s) => s.ambiguous)).toBe(true)
  })
  it('treats a heredoc as a script for a shell but as data for cat', () => {
    const script = unwrapSegments(parseCommand('bash <<EOF\npnpm publish\nEOF'))
    expect(script.some((s) => s.verb === 'pnpm')).toBe(true)
    const data = unwrapSegments(parseCommand('cat >> /tmp/x.md <<EOF\npnpm publish\nEOF'))
    expect(data.every((s) => s.verb !== 'pnpm')).toBe(true)
  })
})

/** Wrap `script` in `levels` shells, quoting each level with JSON string rules. */
function nest(levels: number, script: string): string {
  let out = script
  for (let i = 0; i < levels; i++) out = 'bash -c ' + JSON.stringify(out)
  return out
}

describe('shell wrappers', () => {
  it('unwraps every shell the guard knows', () => {
    for (const shell of ['bash', 'sh', 'zsh', 'dash', 'ksh']) {
      const [s] = unwrapSegments(parseCommand(`${shell} -c "git push origin main"`))
      expect({ shell, verb: s.verb, subcommand: s.subcommand, wrappedBy: s.wrappedBy, refspecs: s.refspecs }).toEqual({
        shell,
        verb: 'git',
        subcommand: 'push',
        wrappedBy: shell,
        refspecs: ['origin', 'main'],
      })
    }
  })
  it('unwraps a combined short cluster that carries -c', () => {
    expect(unwrapSegments(parseCommand('bash -lc "git push origin main"'))[0]).toMatchObject({
      verb: 'git',
      subcommand: 'push',
      wrappedBy: 'bash',
    })
  })
  it('unwraps a script glued to the -c flag', () => {
    expect(unwrapSegments(parseCommand("bash -c'git push origin main'"))[0]).toMatchObject({
      verb: 'git',
      subcommand: 'push',
      wrappedBy: 'bash',
    })
  })
  it('unwraps a nest and re-tags the result with the outer wrapper', () => {
    const [s] = unwrapSegments(parseCommand('bash -c \'sh -c "git push origin main"\''))
    expect(s).toMatchObject({ verb: 'git', subcommand: 'push', wrappedBy: 'bash', ambiguous: false })
  })
  it('resolves a nest inside the depth budget', () => {
    const [s] = unwrapSegments(parseCommand(nest(MAX_WRAP_DEPTH - 1, 'git push origin main')))
    expect(s).toMatchObject({ verb: 'git', subcommand: 'push', ambiguous: false })
  })
  it('stops at MAX_WRAP_DEPTH, never guessing past it', () => {
    const deep = unwrapSegments(parseCommand(nest(MAX_WRAP_DEPTH + 1, 'git push origin main')))
    expect(deep.some((s) => s.ambiguous)).toBe(true)
    expect(deep.every((s) => s.verb !== 'git')).toBe(true)
  })
  it('marks an unresolvable -c argument ambiguous', () => {
    expect(unwrapSegments(parseCommand('bash -c'))[0]).toMatchObject({ verb: 'bash', ambiguous: true })
  })
  it('marks a shell whose script file the guard cannot read ambiguous', () => {
    expect(unwrapSegments(parseCommand('bash /tmp/deploy.sh'))[0]).toMatchObject({ verb: 'bash', ambiguous: true })
  })
  it('marks an interpreter whose inline program the guard cannot read ambiguous', () => {
    const commands = ['python -c "print(1)"', 'python3 -c "print(1)"', 'node -e "1"', 'perl -e "1"', 'ruby -e "1"', 'php -r "1"']
    for (const command of commands) {
      expect({ command, ambiguous: unwrapSegments(parseCommand(command))[0].ambiguous }).toEqual({ command, ambiguous: true })
    }
  })
  it('passes a plain command through unchanged', () => {
    const [seg] = parseCommand('git push origin main')
    expect(unwrapSegments([seg])[0]).toBe(seg)
  })
})

describe('prefix stripping', () => {
  it('sees through a chain of wrappers and env assignments', () => {
    const [s] = unwrapSegments(parseCommand('nohup time sudo env FOO=1 git push origin main'))
    expect(s).toMatchObject({ verb: 'git', subcommand: 'push', ambiguous: false })
    expect(s.refspecs).toEqual(['origin', 'main'])
  })
  it('strips sudo options and the values they consume', () => {
    expect(unwrapSegments(parseCommand('sudo -u root -n git push origin main'))[0]).toMatchObject({
      verb: 'git',
      subcommand: 'push',
      ambiguous: false,
    })
  })
  it('strips env options and assignments and keeps unwrapping the shell', () => {
    expect(unwrapSegments(parseCommand('env -i A=1 B=2 sh -c "git push origin main"'))[0]).toMatchObject({
      verb: 'git',
      subcommand: 'push',
      wrappedBy: 'sh',
    })
  })
  it('keeps an unknown prefix option fail-closed without losing the real verb', () => {
    expect(unwrapSegments(parseCommand('sudo --totally-unknown value git push origin main'))[0]).toMatchObject({
      verb: 'git',
      subcommand: 'push',
      ambiguous: true,
    })
  })
  it('strips the POSIX command builtin', () => {
    expect(unwrapSegments(parseCommand('command git push origin main'))[0]).toMatchObject({
      verb: 'git',
      subcommand: 'push',
      ambiguous: false,
    })
  })
  it('sees the shell behind the busybox dispatcher', () => {
    expect(unwrapSegments(parseCommand('busybox sh -c "git push origin main"'))[0]).toMatchObject({
      verb: 'git',
      subcommand: 'push',
      wrappedBy: 'sh',
    })
  })
})

describe('heredocs', () => {
  it('parses a shell heredoc body as a script', () => {
    const segs = unwrapSegments(parseCommand('bash <<EOF\ngit push origin main\nEOF'))
    expect(segs).toHaveLength(1)
    expect(segs[0]).toMatchObject({ verb: 'git', subcommand: 'push', wrappedBy: 'bash' })
  })
  it('parses the bash -s shape from its heredoc', () => {
    expect(unwrapSegments(parseCommand('bash -s <<EOF\ngit push origin main\nEOF'))[0]).toMatchObject({
      verb: 'git',
      subcommand: 'push',
      wrappedBy: 'bash',
    })
  })
  it('leaves a quoted-delimiter heredoc literal', () => {
    const segs = unwrapSegments(parseCommand("bash <<'EOF'\necho '$BRANCH'\ngit push origin main\nEOF"))
    expect(segs.map((s) => s.verb)).toEqual(['echo', 'git'])
    expect(segs.every((s) => s.ambiguous)).toBe(false)
  })
  it('marks an unquoted-delimiter heredoc expanded by the outer shell ambiguous', () => {
    const segs = unwrapSegments(parseCommand("bash <<EOF\necho '$BRANCH'\ngit push origin main\nEOF"))
    expect(segs.map((s) => s.verb)).toEqual(['echo', 'git'])
    expect(segs.every((s) => s.ambiguous)).toBe(true)
  })
  it('never turns a data heredoc into segments', () => {
    for (const verb of ['cat', 'tee', 'node', 'python']) {
      const segs = unwrapSegments(parseCommand(`${verb} <<EOF\ngit push origin main\nEOF`))
      expect({ verb, verbs: segs.map((s) => s.verb) }).toEqual({ verb, verbs: [verb] })
    }
  })
  it('keeps an interpreter heredoc data but marks it ambiguous', () => {
    const [s] = unwrapSegments(parseCommand('python <<EOF\nimport os\nEOF'))
    expect(s).toMatchObject({ verb: 'python', ambiguous: true })
    expect(s.heredoc).toBe('import os\n')
  })
  it('attaches the body to the segment so a rule can inspect it', () => {
    const [s] = parseCommand('cat >> /tmp/x.md <<EOF\ngit push origin main\nEOF')
    expect(s.verb).toBe('cat')
    expect(s.heredoc).toBe('git push origin main\n')
    expect(parseCommand('git push origin main')[0].heredoc).toBeUndefined()
  })
  it('keeps a heredoc body out of the segment list', () => {
    const segs = parseCommand('cat <<EOF\ngit push origin main\nEOF\nls')
    expect(segs.map((s) => s.verb)).toEqual(['cat', 'ls'])
  })
})

describe('here-strings', () => {
  // Fix round 1 (C1). `<<<` is a here-string, not a heredoc: its argument is a
  // single ordinary word. Queueing it as a heredoc delimiter made the body
  // reader eat every following line as a "body", so each command after it was
  // invisible to every downstream rule — a fail-open, not a false ask.
  it('keeps the command after a here-string in its own segment', () => {
    const segs = parseCommand('cat <<< x\nls /tmp')
    expect(segs.map((s) => s.verb)).toEqual(['cat', 'ls'])
    expect(segs[0].heredoc).toBeUndefined()
    // The here-string argument is an ordinary word, not a queued delimiter: the
    // segment keeps `cat <<< x` (plus the separator B1 always retains) and no
    // body is read past it.
    expect(segs[0].argv.slice(0, 3)).toEqual(['cat', '<<<', 'x'])
  })
  it('does not let a cascade of here-strings swallow the commands after them', () => {
    const segs = parseCommand('cat <<< a\ncat <<< b\nls /tmp')
    expect(segs.map((s) => s.verb)).toEqual(['cat', 'cat', 'ls'])
    expect(segs.map((s) => s.heredoc)).toEqual([undefined, undefined, undefined])
  })
  it('does not read the next command as a shell here-string script', () => {
    const segs = unwrapSegments(parseCommand('sh <<< x\ngit push origin main'))
    expect(segs.map((s) => s.verb)).toEqual(['sh', 'git'])
    expect(segs[0].ambiguous).toBe(true)
    expect(segs[1]).toMatchObject({ verb: 'git', subcommand: 'push', ambiguous: false })
  })
})

describe('exec-like wrappers', () => {
  // Fix round 1 (I1). These verbs run a trailing command of their own, so the
  // verb the guard reads is not the verb that executes. None of them is
  // unwrapped, which leaves the real command invisible — so each of them must
  // come back ambiguous (the rule layer asks) instead of looking resolved.
  it('marks an unresolved exec-like wrapper ambiguous', () => {
    const commands = [
      'timeout 5 bash -c "ls /tmp"',
      'nice -n 5 git push origin main',
      'setsid git push origin main',
      'stdbuf -o0 git push origin main',
      'watch git push origin main',
      'flock /tmp/lock git push origin main',
      'ionice -c2 git push origin main',
      'chrt 5 git push origin main',
      'taskset -c 0 git push origin main',
      'doas git push origin main',
    ]
    for (const command of commands) {
      const [s] = unwrapSegments(parseCommand(command))
      expect({ command, ambiguous: s.ambiguous }).toEqual({ command, ambiguous: true })
    }
  })
  it('does not newly mark a genuinely harmless command ambiguous', () => {
    for (const command of ['git push origin main', 'ls -la /tmp', 'pnpm publish']) {
      const [s] = unwrapSegments(parseCommand(command))
      expect({ command, ambiguous: s.ambiguous }).toEqual({ command, ambiguous: false })
    }
  })
  // Fix round 2 (Important). The exec-like class was NOT closed: these verbs run
  // a trailing command of their own exactly like `timeout`/`nice`, but were never
  // unwrapped and never marked, so the inner command was invisible to every rule.
  // One entry per verb, bare of long options so the assertion is about class
  // MEMBERSHIP — not about the unknown-long-option path that already happened to
  // flag some invocations of them.
  it('marks every newly closed exec-like verb ambiguous', () => {
    const commands = [
      'strace -f -e trace=execve git push origin main',
      'ltrace git push origin main',
      'script -qec "git push origin main" /dev/null',
      'chroot /mnt/root git push origin main',
      'setarch x86_64 git push origin main',
      'ssh build-host git push origin main',
      'fakeroot git push origin main',
      'caffeinate -d git push origin main',
      'unbuffer git push origin main',
      'parallel git push origin main',
      'bwrap git push origin main',
    ]
    const got = commands.map((command) => {
      const [s] = unwrapSegments(parseCommand(command))
      return { command, ambiguous: s.ambiguous }
    })
    // Compared as one array so a failure names every verb that is still hidden,
    // not just the first one.
    expect(got).toEqual(commands.map((command) => ({ command, ambiguous: true })))
  })
  // The remaining siblings the finding names were already in the exec-like class
  // after fix round 1; they must keep that behaviour.
  it('keeps the round-1 exec-like verbs ambiguous', () => {
    const commands = [
      'nsenter -t 1234 git push origin main',
      'systemd-run --user git push origin main',
      'runuser -u deploy git push origin main',
      'su deploy -c "git push origin main"',
    ]
    for (const command of commands) {
      const [s] = unwrapSegments(parseCommand(command))
      expect({ command, ambiguous: s.ambiguous }).toEqual({ command, ambiguous: true })
    }
  })
  // The non-regression guard for the widened class: ordinary commands carry no
  // exec-like verb, so they must stay resolved (`ambiguous: false`).
  it('keeps ordinary commands resolved after widening the exec-like class', () => {
    for (const command of ['ls -la /tmp', 'git status', 'pnpm --dir /tmp/proj test']) {
      const [s] = unwrapSegments(parseCommand(command))
      expect({ command, ambiguous: s.ambiguous }).toEqual({ command, ambiguous: false })
    }
  })
})

describe('query forms', () => {
  // Fix round 1 (accuracy). `command -v ls` / `command -V ls` only report where
  // `ls` resolves to; they execute nothing. The guard has no "word that is not a
  // command" shape, so the reading is marked ambiguous rather than reported as a
  // resolved `ls` execution that never happens.
  it('never reports command -v as a resolved execution of its argument', () => {
    for (const command of ['command -v ls', 'command -V ls', 'command -pv ls']) {
      const [s] = unwrapSegments(parseCommand(command))
      expect({ command, verb: s.verb, ambiguous: s.ambiguous }).toEqual({ command, verb: 'ls', ambiguous: true })
    }
  })
  it('still resolves command when it really runs its argument', () => {
    expect(unwrapSegments(parseCommand('command git push origin main'))[0]).toMatchObject({
      verb: 'git',
      subcommand: 'push',
      ambiguous: false,
    })
    expect(parseCommand('command -p ls')[0].ambiguous).toBe(false)
  })
})
