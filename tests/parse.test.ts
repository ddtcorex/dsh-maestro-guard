import { describe, it, expect } from 'vitest'
import {
  parseCommand,
  unwrapSegments,
  MAX_WRAP_DEPTH,
  extractCommandText,
  extractPathField,
  getCommandWorkingDir,
} from '../src/host/parse.js'

// Task B1: the guard stops matching regular expressions against the raw command
// string and starts reading a parsed command surface instead. The parser is
// deliberately shallow — segments, argv, and the few facts the rule layer needs
// — but it must not inherit the holes of the string matchers it replaces, the
// sharpest of which is a git global option hiding the subcommand:
// `git -C /repo push origin v1.2.3` never matched `\bgit\s+push\b`.

describe('parseCommand', () => {
  it('splits on operators outside quotes', () => {
    const segs = parseCommand('cd /repo && git push origin "feat/a && b"')
    expect(segs.map((s) => s.verb)).toEqual(['cd', 'git'])
    expect(segs[1].argv).toContain('feat/a && b')
  })
  it('classifies git push refspecs', () => {
    const [s] = parseCommand('git push --force origin master')
    expect(s).toMatchObject({ verb: 'git', subcommand: 'push', ambiguous: false })
    expect(s.flags).toContain('--force')
    expect(s.refspecs).toEqual(['origin', 'master'])
  })
  it('keeps every token (no segment loss)', () => {
    const cmd = "bash -c 'echo a; echo b' ; echo c"
    const tokenCount = (s: string) => s.split(/\s+/).filter(Boolean).length
    expect(parseCommand(cmd).reduce((n, s) => n + s.argv.length, 0)).toBeGreaterThanOrEqual(tokenCount('echo a echo b echo c'))
  })
  it('marks an unresolvable cd target ambiguous', () => {
    const segs = parseCommand('cd "$D" && git push origin HEAD')
    expect(segs[0].ambiguous).toBe(true)
  })
})

// The bypass the controller ruling closes: a value-taking git global option sits
// between `git` and its subcommand, so the subcommand must be the first non-flag
// token AFTER those options are consumed — never simply argv[1].
describe('git global options never hide the subcommand', () => {
  it('sees push past -C and keeps the refspec', () => {
    const [s] = parseCommand('git -C /repo push origin v1.2.3')
    expect(s.verb).toBe('git')
    expect(s.subcommand).toBe('push')
    expect(s.refspecs).toEqual(['origin', 'v1.2.3'])
    expect(s.ambiguous).toBe(false)
  })
  it('sees push past -C for a branch refspec', () => {
    const [s] = parseCommand('git -C /repo push origin master')
    expect(s.subcommand).toBe('push')
    expect(s.refspecs).toContain('master')
  })
  it('never leaks the option value into the refspecs', () => {
    expect(parseCommand('git -C /repo push origin v1.2.3')[0].refspecs).not.toContain('/repo')
  })
  it('consumes every value-taking global option the guard relies on', () => {
    const commands = [
      'git -c user.name=x push origin main',
      'git --git-dir /repo/.git push origin main',
      'git --git-dir=/repo/.git push origin main',
      'git --work-tree /repo push origin main',
      'git --work-tree=/repo push origin main',
      'git --namespace ns push origin main',
      'git --namespace=ns push origin main',
      'git --exec-path /usr/lib/git-core push origin main',
      'git --exec-path=/usr/lib/git-core push origin main',
      'git --config-env http.proxy=PROXY push origin main',
      'git --config-env=http.proxy=PROXY push origin main',
    ]
    for (const command of commands) {
      expect({ command, subcommand: parseCommand(command)[0].subcommand }).toEqual({ command, subcommand: 'push' })
    }
  })
  it('skips valueless global flags without eating the subcommand', () => {
    expect(parseCommand('git -p --paginate --no-pager push origin main')[0].subcommand).toBe('push')
  })
  it('keeps the options visible as flags', () => {
    expect(parseCommand('git -C /repo push origin v1.2.3')[0].flags).toContain('-C')
  })
  it('invents no subcommand for a flag-only invocation', () => {
    expect(parseCommand('git --version')[0].subcommand).toBeUndefined()
    expect(parseCommand('git -C /repo')[0].subcommand).toBeUndefined()
  })
  it('consumes several global options in one invocation', () => {
    const [s] = parseCommand('git --git-dir /repo/.git --work-tree /repo -c core.pager=cat push origin main')
    expect(s.subcommand).toBe('push')
    expect(s.refspecs).toEqual(['origin', 'main'])
  })
  it('sees a publish behind a package-manager global option', () => {
    const [s] = parseCommand('pnpm --dir /repo publish')
    expect(s.verb).toBe('pnpm')
    expect(s.subcommand).toBe('publish')
  })
})

// Fix round 1 — finding 1: the value-taking table is a denylist, so an option it
// does not list is assumed valueless and the token after it is read as the
// subcommand. `git --shallow-file /tmp/x push origin v1.2.3` therefore returned
// `subcommand: '/tmp/x'` with `ambiguous: false` — the very `git -C` bypass,
// reached with a different flag. Both halves are required: table the git globals
// that really consume a separate value (verified against real git), and fail
// CLOSED on any option that is in neither table, because the parser provably
// cannot tell `git --bare push` (valueless) from `git --shallow-file x push`.
describe('unknown pre-subcommand options are fail-closed', () => {
  it('consumes --shallow-file as a separate value (verified against git 2.53)', () => {
    const [s] = parseCommand('git --shallow-file /tmp/x push origin v1.2.3')
    expect(s.subcommand).toBe('push')
    expect(s.refspecs).toEqual(['origin', 'v1.2.3'])
    expect(s.ambiguous).toBe(false)
  })
  it('consumes --attr-source as a separate value (verified against git 2.53)', () => {
    const [s] = parseCommand('git --attr-source /tmp/x push origin v1.2.3')
    expect(s.subcommand).toBe('push')
    expect(s.refspecs).toEqual(['origin', 'v1.2.3'])
    expect(s.ambiguous).toBe(false)
  })
  it('keeps --list-cmds=<group> self-contained, as git requires', () => {
    // Audited: `git --list-cmds /tmp/x rev-parse …` dies with "unknown option:
    // --list-cmds"; only the `=` form exists, which the parser already reads as
    // self-contained. It must therefore NOT enter the value-taking table.
    const [s] = parseCommand('git --list-cmds=main push origin v1.2.3')
    expect(s.subcommand).toBe('push')
    expect(s.ambiguous).toBe(false)
  })
  it('marks an unknown long option followed by a word ambiguous', () => {
    const [s] = parseCommand('git --totally-unknown x push origin main')
    expect(s.ambiguous).toBe(true)
  })
  it('marks the segment ambiguous however the hidden word reads', () => {
    const commands = ['git --totally-unknown x push origin main', 'git --totally-unknown push x main']
    for (const command of commands) {
      expect({ command, ambiguous: parseCommand(command)[0].ambiguous }).toEqual({ command, ambiguous: true })
    }
  })
  it('fails closed for a non-git verb too (a hidden publish)', () => {
    expect(parseCommand('pnpm --totally-unknown x publish')[0].ambiguous).toBe(true)
  })
  it('treats a verified valueless long option as valueless', () => {
    // Audited with real git: `git --bare rev-parse …` runs rev-parse, so `--bare`
    // consumes nothing and the subcommand is still readable.
    const [s] = parseCommand('git --bare push origin main')
    expect(s.subcommand).toBe('push')
    expect(s.refspecs).toEqual(['origin', 'main'])
    expect(s.ambiguous).toBe(false)
  })
  it('does not mark a dangling unknown option ambiguous', () => {
    expect(parseCommand('git --totally-unknown')[0].ambiguous).toBe(false)
  })
  it('keeps a self-contained unknown --name=value readable', () => {
    expect(parseCommand('git --totally-unknown=1 push origin main')[0]).toMatchObject({
      subcommand: 'push',
      ambiguous: false,
    })
  })
  it('still resolves the legitimate forms', () => {
    expect(parseCommand('git -c core.pager=cat status')[0]).toMatchObject({
      verb: 'git',
      subcommand: 'status',
      ambiguous: false,
    })
    const [pushed] = parseCommand('git -C /repo push origin v1.2.3')
    expect(pushed).toMatchObject({ subcommand: 'push', ambiguous: false })
    expect(pushed.refspecs).toContain('v1.2.3')
  })
})

describe('tokenizer', () => {
  it('splits on every unquoted operator and on newlines', () => {
    const segs = parseCommand('a | b || c ; d && e\nf')
    expect(segs.map((s) => s.verb)).toEqual(['a', 'b', 'c', 'd', 'e', 'f'])
  })
  it('keeps a quoted operator inside a single token', () => {
    expect(parseCommand('echo "a | b"')[0].argv).toEqual(['echo', 'a | b'])
  })
  // Deleted `multiline-quoted` suite: the old string matcher split a quoted
  // block on the separators INSIDE it before stripping quotes, exposing the
  // phrasings as if they were argv. The tokenizer cannot fragment it — a quoted
  // newline, `&&` and `;` all stay inside one token of one segment.
  it('keeps a quoted multiline block in a single token and segment', () => {
    const data = 'pnpm dsh --profile x "TASK\n1) cd /tmp && git push -u origin feat/x\ndo not retry"'
    const segs = parseCommand(data)
    expect(segs).toHaveLength(1)
    expect(segs[0].argv).toContain('TASK\n1) cd /tmp && git push -u origin feat/x\ndo not retry')
  })
  it('keeps a quoted program body in a single segment', () => {
    const segs = parseCommand('node -e "runOne()\nrunTwo()\ngit push origin v1.0.0\nend()"')
    expect(segs).toHaveLength(1)
    expect(segs[0].verb).toBe('node')
  })
  it('strips quotes but keeps their content intact', () => {
    expect(parseCommand("git commit -m 'fix: a && b'")[0].argv).toContain('fix: a && b')
  })
  it('joins a backslash line continuation instead of splitting', () => {
    const segs = parseCommand('git push \\\n origin main')
    expect(segs).toHaveLength(1)
    expect(segs[0].argv).toEqual(['git', 'push', 'origin', 'main'])
  })
  it('treats a redirection as a flag and its target as a path, never a refspec', () => {
    const [s] = parseCommand('git push origin master > /tmp/out.log')
    expect(s.refspecs).toEqual(['origin', 'master'])
    expect(s.paths).toContain('/tmp/out.log')
    expect(s.flags).toContain('>')
  })
  it('does not mistake an fd duplication for a path', () => {
    const [s] = parseCommand('git push origin master 2>&1')
    expect(s.refspecs).toEqual(['origin', 'master'])
    expect(s.paths).toEqual([])
  })
  it('keeps the operator that ends a segment as a token', () => {
    const segs = parseCommand('cd /repo && git push origin master')
    expect(segs[0].argv).toEqual(['cd', '/repo', '&&'])
    expect(segs[1].argv).toEqual(['git', 'push', 'origin', 'master'])
  })
  it('keeps an input redirect target out of the refspecs', () => {
    const [s] = parseCommand('git push origin master < /tmp/in.txt')
    expect(s.refspecs).toEqual(['origin', 'master'])
    expect(s.paths).toContain('/tmp/in.txt')
  })
  it('does not treat a heredoc delimiter as a path', () => {
    const [s] = parseCommand('cat > /tmp/x.md <<EOF\nhello\nEOF')
    expect(s.paths).toContain('/tmp/x.md')
    expect(s.paths).not.toContain('EOF')
  })
  it('keeps the original text in raw', () => {
    const [s] = parseCommand('git push origin "feat/a"')
    expect(s.raw).toBe('git push origin "feat/a"')
  })
  it('returns no segments for an empty command', () => {
    expect(parseCommand('')).toEqual([])
    expect(parseCommand('   \n ')).toEqual([])
  })
})

describe('ambiguity is fail-closed', () => {
  it('marks an expanded dollar in a token ambiguous', () => {
    const segs = parseCommand('cd "$D" && git push origin HEAD')
    expect(segs[0].ambiguous).toBe(true)
  })
  it('does not mark a single-quoted dollar ambiguous (no expansion happens)', () => {
    expect(parseCommand("cd '$D'")[0].ambiguous).toBe(false)
  })
  it('does not mark an escaped dollar ambiguous', () => {
    expect(parseCommand('echo \\$HOME')[0].ambiguous).toBe(false)
  })
  it('marks an opaque verb ambiguous whatever its arguments say', () => {
    for (const verb of ['eval', 'exec', 'xargs']) {
      expect(parseCommand(`${verb} git push origin main`)[0].ambiguous).toBe(true)
    }
  })
  it('leaves a plain resolvable command unambiguous', () => {
    expect(parseCommand('git push origin master')[0].ambiguous).toBe(false)
  })
  it('marks every segment ambiguous once the wrapper depth budget is spent', () => {
    expect(parseCommand('git push origin master', MAX_WRAP_DEPTH)[0].ambiguous).toBe(true)
    expect(parseCommand('git push origin master', MAX_WRAP_DEPTH - 1)[0].ambiguous).toBe(false)
  })
  // Fix round 1 — finding 2: backtick substitution runs a command exactly like
  // `$(...)`, but only `$` set the expandable flag, so `` echo `git -C /repo push
  // origin v1.2.3` `` was `ambiguous: false` with the real push invisible, and
  // `` cd `pwd` `` looked like a resolved cd target.
  it('marks a backtick command substitution ambiguous like $(...)', () => {
    expect(parseCommand('cd `pwd`')[0].ambiguous).toBe(true)
  })
  it('marks a segment whose argument hides a command in backticks', () => {
    expect(parseCommand('echo `git -C /repo push origin v1.2.3`')[0].ambiguous).toBe(true)
  })
  it('marks a double-quoted backtick ambiguous (substitution still happens there)', () => {
    expect(parseCommand('echo "`pwd`"')[0].ambiguous).toBe(true)
  })
  it('does not mark a single-quoted backtick ambiguous (no expansion happens)', () => {
    expect(parseCommand("echo '`pwd`'")[0].ambiguous).toBe(false)
  })
  it('does not mark an escaped backtick ambiguous', () => {
    expect(parseCommand('echo \\`pwd\\`')[0].ambiguous).toBe(false)
  })
})

// Task B4: interpreting a command/args is the parser's job, not a path rule's.
// The tool-argument extractors moved here from the deleted `sandbox.ts`; the
// working-directory helper follows, because it reads `cd`/`git -C` out of the
// command text — the same surface `parseCommand` reads.
describe('tool-argument extractors', () => {
  it('extractCommandText returns the command field of shell-style args', () => {
    expect(extractCommandText({ command: 'git push origin feature', description: 'x' })).toBe('git push origin feature')
  })
  it('extractCommandText passes through bare string args', () => {
    expect(extractCommandText('git push origin feature')).toBe('git push origin feature')
  })
  it('extractCommandText returns undefined for non-shell tool args', () => {
    expect(extractCommandText({ file_path: '/a', content: 'mention git push' })).toBeUndefined()
    expect(extractCommandText({ command: 42 })).toBeUndefined()
    expect(extractCommandText(undefined)).toBeUndefined()
  })
  it('extractPathField reads every path key the file tools use', () => {
    expect(extractPathField({ path: '/a' })).toBe('/a')
    expect(extractPathField({ file: '/b' })).toBe('/b')
    expect(extractPathField({ file_path: '/c' })).toBe('/c')
    expect(extractPathField({ filePath: '/d' })).toBe('/d')
    expect(extractPathField('/e')).toBe('/e')
  })
  it('extractPathField returns undefined when no path is carried', () => {
    expect(extractPathField({ content: 'x' })).toBeUndefined()
    expect(extractPathField({ path: 42 })).toBeUndefined()
    expect(extractPathField(null)).toBeUndefined()
  })
})

describe('getCommandWorkingDir', () => {
  it('extracts an absolute cd target from a chained command', () => {
    expect(getCommandWorkingDir('cd /work/repo && git push -u origin feat/x 2>&1 | tail -5', '/work')).toBe('/work/repo')
  })
  it('resolves a relative cd against the session cwd', () => {
    expect(getCommandWorkingDir('cd packages/jobs && git push -u origin feat/x', '/work')).toBe('/work/packages/jobs')
  })
  it('handles the git -C form', () => {
    expect(getCommandWorkingDir('git -C /work/repo push origin feat/x', '/work')).toBe('/work/repo')
  })
  it('falls back to the session cwd only when no cd target is present', () => {
    expect(getCommandWorkingDir('git push origin feat/x', '/work')).toBe('/work')
    expect(getCommandWorkingDir(undefined, '/work')).toBe('/work')
    expect(getCommandWorkingDir('cd /x && git push', undefined)).toBeUndefined()
  })
  // Residual false-positive class from the audit: an unreadable cd target must
  // not inherit the session cwd, or a session whose cwd repo sits on a protected
  // branch keeps blocking feature pushes written as `cd "$REPO" && git push …`.
  it('returns undefined for a quoted cd target', () => {
    expect(getCommandWorkingDir('cd "$REPO" && git push -u origin feat/x', '/work')).toBeUndefined()
  })
  it('returns undefined for a $VAR cd target', () => {
    expect(getCommandWorkingDir('cd $REPO_DIR && git push -u origin feat/x', '/work')).toBeUndefined()
  })
})

/**
 * CRITICAL 2 — the shape test that stops `verb = argv[0]` from hiding a whole
 * command. A segment whose first token cannot be a command (a `VAR=value`
 * assignment, a `(`/`{` group opener, a shell keyword), or whose later tokens
 * name a verb the rules resolve while its first does not, is marked `ambiguous`
 * so the rule layer escalates it to `ask` instead of allowing it.
 *
 * The mechanism is pinned here (the flag) and its OUTCOME in
 * `tests/rules.test.ts` (the verdict), so a future change to either half fails
 * loudly.
 */
describe('parseCommand — a first token that cannot be a command is ambiguous', () => {
  const shapes = [
    'FOO=bar git push origin master',
    'GIT_DIR=/x git push origin master',
    '(git push origin master)',
    '{ git push origin master; }',
    'then git push origin master',
    'pkexec git push origin master',
    'my-custom-runner git push origin master',
    'find . -exec git push origin master +',
    'find . -execdir git push origin master +',
    'find . -ok git push origin master +',
  ]
  for (const command of shapes) {
    it(`flags ${command}`, () => {
      expect(parseCommand(command).some((s) => s.ambiguous)).toBe(true)
    })
  }

  it('does not flag a segment a known prefix verb still resolves', () => {
    for (const command of ['sudo git push origin master', 'command git push origin master', 'env A=1 git push origin master']) {
      expect(unwrapSegments(parseCommand(command))[0].ambiguous, command).toBe(false)
    }
  })

  it('does not flag ordinary commands', () => {
    // `ssh host ls` is deliberately absent: `ssh` is a known exec-like wrapper,
    // so the parser DOES mark it ambiguous on the verb alone (pre-existing). Its
    // outcome still stays allow — the escalation finds no rule shape in the raw
    // text — and `tests/rules.test.ts` pins that at the classify level.
    for (const command of ['ls -la', 'git status', 'pnpm test', 'echo hello']) {
      expect(parseCommand(command).every((s) => !s.ambiguous), command).toBe(true)
    }
  })

  it('does not flag a mention-led command whose later words name a rule verb', () => {
    // `echo`/`printf`/`grep`/`rg`/… only scan or print their arguments, so the
    // later-token rule must not apply to a segment they lead — that shape is a
    // documented mention, not a hidden command. `find` is the one mention verb
    // that CAN run a later command, and only through an action flag (pinned above).
    for (const command of ['rg git push docs/', 'grep -rn npm publish docs', 'echo pnpm publish', 'awk /publish/ docs/x']) {
      expect(parseCommand(command).every((s) => !s.ambiguous), command).toBe(true)
    }
  })
})
