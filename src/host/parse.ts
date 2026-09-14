/**
 * Shell-aware tokenizer and segmenter for the guard's command surface.
 *
 * The guard judges a command by what it actually executes, and a regex over the
 * raw string cannot do that. It splits on operators that sit inside quotes, and
 * — the live bypass this module exists to close — it cannot see the subcommand
 * of `git -C /repo push origin v1.2.3`, because a value-taking global option
 * sits between `git` and `push`.
 *
 * The parse is deliberately shallow: just enough structure (segments, argv, the
 * verb/subcommand, flags, refspecs, paths, ambiguity) for the rule layer, never
 * a POSIX implementation. Two invariants hold:
 *
 * - nothing is silently dropped — every word, operator, redirection operator and
 *   redirection target appears exactly once across the segments' `argv`, so a
 *   rule can always re-derive the text it needs (an operator keeps its own
 *   token kind and is never read as a word). The one deliberate exception is a
 *   heredoc BODY: it is not command surface, so it leaves the token stream and
 *   is attached to its owning segment as `Segment.heredoc` instead;
 * - anything unresolvable is marked `ambiguous` rather than guessed, and the
 *   rule layer treats ambiguity as "ask", never as "allow".
 *
 * Two consequences of that second invariant are worth naming, because both were
 * live bypasses before they were closed:
 *
 * - an option the tables do not know is NOT assumed valueless when a word
 *   follows it. `git --bare push` (valueless) and `git --shallow-file x push`
 *   (value-taking) differ only in git's own option table, so the parser cannot
 *   resolve the subcommand and marks the segment `ambiguous` instead of reading
 *   `x` as the subcommand and losing the push;
 * - a backtick substitutes a command exactly like `$(...)` does, so it sets the
 *   same expandable signal — otherwise `` echo `git -C /repo push origin v1.2.3`
 *   `` reads as a resolved `echo` and the push never reaches a rule.
 *
 * `unwrapSegments` is the layer above that parse. It removes the wrappers that
 * only change WHO runs a command (`env VAR=…`, `sudo`, `nohup`, `time`), replaces
 * a shell wrapper with the script it runs (`bash -c <script>`, `bash -s`, and a
 * `bash <<EOF` body), and tags every segment it derives with `wrappedBy`. A body
 * fed to a non-shell — `cat`, `tee`, an interpreter — stays data and is never
 * turned into segments; it is attached as `Segment.heredoc` so a rule can inspect
 * it without parsing it. A wrapper whose script cannot be read (a script file, a
 * `-c` with no argument, a nest deeper than `MAX_WRAP_DEPTH`, an interpreter's
 * inline program) marks its segments `ambiguous` instead of being treated as
 * resolved — and so does an exec-like wrapper the guard deliberately does not
 * unwrap (`timeout`, `nice`, `setsid`, `watch`, …), which runs a command of its
 * own that would otherwise never reach a rule.
 *
 * Pure with respect to the environment it inspects: string in, data out. It
 * writes no file, starts no child process, opens no socket and never expands
 * `$VAR`/backticks — an unexpanded token is exactly what `ambiguous` records.
 * Reading the ambient environment is allowed where the caller cannot supply it:
 * `node:os` `homedir()` and `node:path` resolve a `~`-relative `cd` target in
 * `getCommandWorkingDir`, which is the only reason either is imported.
 */

import { homedir } from 'node:os'
import { join, resolve } from 'node:path'

/** How many shell-wrapper levels `parseCommand` will descend before giving up. */
export const MAX_WRAP_DEPTH = 3

export interface Segment {
  /** The original source text of this segment, quoting preserved. */
  raw: string
  /** Every token of the segment: quotes stripped, operator and redirections kept. */
  argv: string[]
  verb?: string
  subcommand?: string
  flags: string[]
  refspecs: string[]
  paths: string[]
  ambiguous: boolean
  wrappedBy?: string
  /**
   * Every heredoc body this segment owns (`<<`/`<<-`), concatenated in feed
   * order with a `\n` between them: terminators are excluded and each body keeps
   * its own trailing newline. Present only when the segment owns at least one
   * heredoc redirection, so more than one cannot be told apart here. A rule that
   * judges content inspects it instead of forcing the body back through the
   * parser.
   */
  heredoc?: string
}

/** Verbs whose meaning is entirely "run whatever the arguments say". */
export const OPAQUE_VERBS = new Set(['eval', 'exec', 'xargs'])
/**
 * Verbs that run a trailing COMMAND of their own — after their own options and,
 * for most of them, a leading duration/priority/pid argument. The verb the guard
 * reads is therefore not the verb that executes: `timeout 5 bash -c '…'` runs
 * bash, never `timeout`, and the real command is invisible to a rule keyed on it.
 *
 * `unwrapSegments` does not unwrap these forms, because their argument grammar
 * is per-verb (`timeout 5 CMD`, `nice -n 5 CMD`, `stdbuf -o0 CMD`, `flock FILE
 * CMD`, …) and a wrong guess would hide the command rather than reveal it. Each
 * one is marked `ambiguous` instead, which the rule layer answers with a prompt,
 * never an allow. `xargs` is the same shape and is already in `OPAQUE_VERBS`.
 *
 * The class is closed over that SHAPE, not over a hand-picked sample: a verb that
 * runs a trailing command belongs here even when it is a tracer (`strace`,
 * `ltrace`), a sandbox/root switcher (`chroot`, `setarch`, `bwrap`, `fakeroot`),
 * a remote runner (`ssh`), or a scheduler/multiplexer (`parallel`, `unbuffer`,
 * `script`, `caffeinate`). Leaving one out does not fail safe: the segment reads
 * as a resolved verb and the command it really runs never reaches a rule.
 *
 * Exported (with `OPAQUE_VERBS`) so the rule layer can tell which segments hold a
 * COMMAND in their quoted spans rather than data — see `rawSurface` in `rules.ts`.
 */
export const EXEC_WRAPPERS = new Set([
  'bwrap',
  'caffeinate',
  'chpst',
  'chroot',
  'chrt',
  'cpulimit',
  'daemonize',
  'doas',
  'eatmydata',
  'fakeroot',
  'firejail',
  'flock',
  'gosu',
  'ionice',
  'ltrace',
  'nice',
  'nsenter',
  'parallel',
  'perf',
  'pkexec',
  'run0',
  'runuser',
  'script',
  'setarch',
  'setpriv',
  'setsid',
  'ssh',
  'sshpass',
  'stdbuf',
  'strace',
  'su',
  'systemd-run',
  'taskset',
  'timeout',
  'unbuffer',
  'unshare',
  'valgrind',
  'watch',
  'watchexec',
  'xvfb-run',
])

/**
 * Global options that consume the FOLLOWING token as their value, per verb.
 * `git` is the one that matters for safety: without this table `git -C <dir>
 * push` has subcommand `<dir>`, which is how the previous regex matcher let a
 * protected-branch push through. The package managers are listed for the same
 * reason — a publish hidden behind `--dir` must still be seen as a publish.
 *
 * Every entry here is verified against the real tool, separated form included.
 * `--shallow-file` and `--attr-source` are git's undocumented-but-real globals
 * (`git --shallow-file /tmp/x rev-parse --is-inside-work-tree` prints `true`,
 * i.e. git ate `/tmp/x`) and they hid the subcommand exactly like `-C` did.
 * `--list-cmds` is deliberately absent: git rejects the separated form
 * ("unknown option: --list-cmds"), so only `--list-cmds=<group>` exists and the
 * self-contained `--name=value` rule already covers it.
 */
const VALUE_FLAGS: Record<string, readonly string[]> = {
  git: [
    '-C',
    '-c',
    '--git-dir',
    '--work-tree',
    '--namespace',
    '--exec-path',
    '--config-env',
    '--shallow-file',
    '--attr-source',
  ],
  pnpm: ['--dir', '-C', '--prefix', '--cwd', '--config', '--filter', '-F', '--registry', '--reporter'],
  npm: ['--prefix', '-C', '--cwd', '--registry', '--userconfig', '--cache', '--loglevel'],
  yarn: ['--cwd', '--modules-folder', '--cache-folder'],
}

/**
 * Global options that take no value, so only the flag itself is consumed.
 * Verified against the real tool: `git <flag> rev-parse …` still runs the
 * subcommand, which is what makes it safe to keep resolving past these instead
 * of asking. Anything not listed here and not in `VALUE_FLAGS` is unreadable.
 */
const BARE_FLAGS: Record<string, readonly string[]> = {
  git: [
    '-p',
    '-P',
    '--paginate',
    '--no-pager',
    '--bare',
    '--no-replace-objects',
    '--literal-pathspecs',
    '--glob-pathspecs',
    '--noglob-pathspecs',
    '--icase-pathspecs',
    '--no-optional-locks',
  ],
}

type TokKind = 'word' | 'sep' | 'redir' | 'target'

interface Tok {
  text: string
  kind: TokKind
  start: number
  end: number
  /** True when the token still holds a `$` the shell would expand. */
  expandable: boolean
  /** The body of a heredoc whose delimiter this token is. */
  heredoc?: string
  /** True when that delimiter was quoted, which disables expansion of the body. */
  heredocQuoted?: boolean
}

/** Read one redirection at `i`: `>`, `>>`, `<`, `<<`, `<<<`, `N>&M`, `&>`. */
function scanRedirect(input: string, i: number): { op: string; dup: boolean; next: number } {
  const c = input[i]
  let j = i + 1
  let op = c
  if (input[j] === c && c !== '&') {
    op += c
    j++
  }
  if (c === '<' && input[j] === '<') {
    op += '<'
    j++
  }
  if (input[j] === '&') {
    op += '&'
    j++
    while (j < input.length && /[0-9-]/.test(input[j])) {
      op += input[j]
      j++
    }
    return { op, dup: true, next: j }
  }
  return { op, dup: false, next: j }
}

/**
 * Read the body of one heredoc: every line after `pos` up to the line that holds
 * only the delimiter. Returns the body (terminator excluded, each line keeping
 * its newline) and where tokenizing resumes. An unterminated heredoc consumes
 * the rest of the input — a body must never leak back out as argv.
 */
function readHeredocBody(
  input: string,
  pos: number,
  delim: string,
  stripTabs: boolean,
): { body: string; next: number } {
  if (pos >= input.length) return { body: '', next: input.length }
  let body = ''
  let p = pos
  for (;;) {
    const nl = input.indexOf('\n', p)
    const end = nl === -1 ? input.length : nl
    const line = input.slice(p, end)
    const compared = stripTabs ? line.replace(/^\t+/, '') : line
    if (compared === delim) return { body, next: nl === -1 ? input.length : nl + 1 }
    body += compared + '\n'
    if (nl === -1) return { body, next: input.length }
    p = nl + 1
  }
}

/** Split the command into tokens, keeping separators as their own tokens. */
function tokenize(input: string): Tok[] {
  const toks: Tok[] = []
  let buf = ''
  let bufStart = 0
  let expandable = false
  let quote: '"' | "'" | null = null
  // 'file' → the next word is a redirection target; 'heredoc' → it is a heredoc
  // delimiter (a word, never a path); null → nothing pending.
  let pending: 'file' | 'heredoc' | null = null
  // Delimiters seen but not yet fed. Their bodies start after the next newline,
  // so the queue is drained at the newline that ends the current line.
  let heredocs: { index: number; delim: string; stripTabs: boolean }[] = []
  let heredocTabs = false
  let i = 0

  const emit = (text: string, kind: TokKind, start: number, end: number): void => {
    const k = kind === 'word' && pending === 'file' ? 'target' : kind
    const delimiter = kind === 'word' && pending === 'heredoc'
    if (delimiter) {
      heredocs.push({ index: toks.length, delim: text, stripTabs: heredocTabs })
      pending = null
      heredocTabs = false
    } else if (kind === 'word' && pending !== null) {
      pending = null
      heredocTabs = false
    }
    toks.push({
      text,
      kind: k,
      start,
      end,
      expandable,
      // For a delimiter the source slice still holds the quotes, so it says
      // whether the shell expands the body (`<<EOF`) or reads it literally
      // (`<<'EOF'`).
      ...(delimiter ? { heredocQuoted: /['"]/.test(input.slice(start, end)) } : {}),
    })
    expandable = false
  }
  const flush = (end: number): void => {
    if (buf === '') return
    const text = buf
    buf = ''
    emit(text, 'word', bufStart, end)
  }
  const sep = (text: string, end: number): void => {
    flush(i)
    pending = null
    toks.push({ text, kind: 'sep', start: i, end, expandable: false })
  }

  while (i < input.length) {
    const ch = input[i]

    if (quote === "'") {
      if (ch === "'") quote = null
      else buf += ch
      i++
      continue
    }
    if (quote === '"') {
      if (ch === '\\') {
        const nx = input[i + 1]
        if (nx === '"' || nx === '\\' || nx === '$' || nx === '`') {
          buf += nx
          i += 2
          continue
        }
      } else if (ch === '"') {
        quote = null
        i++
        continue
      } else if (ch === '$' || ch === '`') {
        // Double quotes still substitute: both `$VAR` and `` `cmd` `` execute.
        expandable = true
      }
      buf += ch
      i++
      continue
    }

    if (ch === '\\') {
      const nx = input[i + 1]
      if (nx === '\n') {
        i += 2
        continue
      }
      if (buf === '') bufStart = i
      buf += nx === undefined ? ch : nx
      i += nx === undefined ? 1 : 2
      continue
    }
    if (ch === "'" || ch === '"') {
      if (buf === '') bufStart = i
      quote = ch
      i++
      continue
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      flush(i)
      i++
      continue
    }
    if (ch === '\n' || ch === ';') {
      sep(ch, i + 1)
      i++
      // Heredoc bodies begin on the line after the delimiter; consume them here
      // so no body word is ever read as argv of the segment that owns them.
      if (ch === '\n' && heredocs.length > 0) {
        const queue = heredocs
        heredocs = []
        for (const h of queue) {
          const read = readHeredocBody(input, i, h.delim, h.stripTabs)
          toks[h.index].heredoc = read.body
          i = read.next
        }
      }
      continue
    }
    if (ch === '#' && buf === '') {
      while (i < input.length && input[i] !== '\n') i++
      continue
    }
    if (ch === '&' || ch === '|') {
      if (input[i + 1] === ch) {
        sep(ch + ch, i + 2)
        i += 2
        continue
      }
      if (ch === '&' && input[i + 1] === '>') {
        flush(i)
        const r = scanRedirect(input, i + 1)
        toks.push({ text: '&' + r.op, kind: 'redir', start: i, end: r.next, expandable: false })
        pending = 'file'
        i = r.next
        continue
      }
      sep(ch, i + 1)
      i++
      continue
    }
    if (ch === '>' || ch === '<') {
      const fold = buf !== '' && /^[0-9]+$/.test(buf)
      const start = fold ? bufStart : i
      if (fold) {
        buf = ''
        expandable = false
      } else flush(i)
      const r = scanRedirect(input, i)
      // `<<-` is a heredoc too; its body is indented with tabs, which both the
      // body lines and the terminator may carry.
      const tabs = r.op === '<<' && input[r.next] === '-'
      const op = tabs ? '<<-' : r.op
      const next = tabs ? r.next + 1 : r.next
      // Only `<<` and `<<-` introduce a body. `<<<` is a here-string: its
      // argument is one ordinary word, so queueing it as a delimiter would let
      // the body reader eat every following line as a "body" and hide the
      // commands after it from every downstream rule.
      const heredoc = op === '<<' || op === '<<-'
      toks.push({ text: input.slice(start, i) + op, kind: 'redir', start, end: next, expandable: false })
      pending = r.dup ? null : heredoc ? 'heredoc' : 'file'
      heredocTabs = pending === 'heredoc' && tabs
      i = next
      continue
    }
    if (buf === '') bufStart = i
    // A backtick runs a command exactly like `$(...)`, so it is expandable too;
    // single-quoted and escaped backticks never reach here.
    if (ch === '$' || ch === '`') expandable = true
    buf += ch
    i++
  }
  flush(i)
  // A delimiter at the end of the input still owns a (possibly empty) body.
  for (const h of heredocs) {
    toks[h.index].heredoc = readHeredocBody(input, input.length, h.delim, h.stripTabs).body
  }
  return toks
}

/** A word that names a path: absolute, explicitly relative, or containing `/`. */
function looksLikePath(text: string): boolean {
  return text.startsWith('/') || text.startsWith('./') || text.startsWith('../') || text.startsWith('~/') || text.includes('/')
}

/** Where a segment's subcommand sits, and whether that reading is trustworthy. */
interface Subcommand {
  /** Index of the subcommand token, or -1 when the segment has none. */
  index: number
  /** True when an option in neither table made the reading unprovable. */
  unknownOption: boolean
}

/**
 * Resolve the subcommand: the first non-flag token once the verb's value-taking
 * global options (and its known valueless ones) are consumed.
 *
 * Fail-closed on an unknown long option. When `git --totally-unknown x …` is
 * seen, `--totally-unknown` may be valueless (`x` is the subcommand) or
 * value-taking (`x` is its value and the real subcommand follows); nothing short
 * of git's own option table can decide. The parser keeps resolving with the
 * valueless reading — the optimistic one, which still surfaces a later `push`
 * via `refspecs` — but reports `unknownOption`, so `buildSegment` marks the
 * segment ambiguous and the rule layer asks instead of allowing.
 */
function subcommandIndex(toks: Tok[], verb: string | undefined): Subcommand {
  if (verb === undefined) return { index: -1, unknownOption: false }
  const values = VALUE_FLAGS[verb] ?? []
  const bares = BARE_FLAGS[verb] ?? []
  let i = 1
  let unknownOption = false
  while (i < toks.length) {
    const t = toks[i]
    if (t.kind !== 'word' || !t.text.startsWith('-')) break
    const next = toks[i + 1]
    if (bares.includes(t.text)) {
      i++ // -p / --paginate / --no-pager / --bare: the flag is the whole option
    } else if (t.text.startsWith('--') && t.text.indexOf('=') > 0) {
      i++ // --name=value is self-contained
    } else if (values.includes(t.text) && next !== undefined && next.kind === 'word') {
      i += 2 // the option and the value it consumes
    } else {
      // Unknown option. A following word is exactly the token that would be
      // misread as the subcommand, so record that the reading is unprovable.
      if (t.text.startsWith('--') && next !== undefined && next.kind === 'word' && !next.text.startsWith('-')) {
        unknownOption = true
      }
      i++ // assume it takes no value; the ambiguity above carries the doubt
    }
  }
  return { index: i < toks.length && toks[i].kind === 'word' ? i : -1, unknownOption }
}

/**
 * Shell reserved words that can lead a segment without being the command it
 * runs. The token after one of them is never that segment's command either, so
 * a segment led by one cannot be resolved from its first word.
 */
const SHELL_KEYWORDS = new Set([
  'if', 'then', 'else', 'elif', 'fi', 'while', 'until', 'do', 'done', 'for',
  'case', 'esac', 'select', 'function', 'in', '!', '[[', ']]',
])

/** `VAR=value` — an assignment the shell evaluates before any command runs. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/

/**
 * Verbs the rule layer resolves as a command's own first word. A segment whose
 * first token cannot be a command (a `VAR=value` assignment, a `(`/`{` group
 * opener, a shell keyword), or whose LATER tokens name one of these while its
 * first does not, is a command the parser failed to resolve — not a mention.
 *
 * This is a SHAPE test on purpose. `verb = argv[0]` plus exact-verb rule matches
 * meant `FOO=bar git push origin master`, `(git push origin master)`,
 * `if true; then git push origin master; fi` and every exec-like wrapper outside
 * the table (`pkexec git push origin master`) were silently ALLOWED, and a longer
 * denylist of wrapper names cannot close that class — `my-custom-runner git push`
 * has the same shape. Marking the segment `ambiguous` hands it to the rule
 * layer's escalation, which asks, never allows.
 */
const RULE_VERBS = new Set(['git', 'gh', 'pnpm', 'npm', 'yarn', 'curl', 'wget', 'source', '.'])

/**
 * Verbs that only SCAN or PRINT their arguments, never execute them: the
 * protected phrase in `grep -rn npm publish docs` is the pattern being searched
 * for, not a command. They lead a segment whose later words name a rule verb
 * without running it, so the later-token shape test must not apply to them.
 *
 * `find` is the one verb here that CAN run a command — but only through
 * `-exec`, which {@link unresolvedCommand} treats separately. The set is
 * exported so the rule layer applies the same reading to a protected path.
 */
export const MENTION_VERBS = new Set([
  'grep',
  'egrep',
  'fgrep',
  'rg',
  'sed',
  'awk',
  'echo',
  'printf',
  'find',
  'ls',
  'test',
  'wc',
  'sort',
  'uniq',
  'jq',
])

/** The verb without its directory (`/bin/git` → `git`). */
function commandBase(text: string): string {
  const cut = text.lastIndexOf('/')
  return cut === -1 ? text : text.slice(cut + 1)
}

/**
 * True when this segment's first token cannot be the command it claims to be, or
 * when a later token names a verb the rules resolve while the first does not.
 * See {@link RULE_VERBS} for why this is a shape test.
 *
 * A MENTION verb as the first token opts out of the later-token rule: `echo`,
 * `printf`, `grep`, `rg`, `awk`, `ls` and friends only scan or print their
 * arguments, so a rule phrase in them is a documented mention (`rg git push
 * docs/`), not a hidden command — treating it as one was the over-block this
 * exemption closes. `find` is the exception, and only through `-exec`, because
 * that form really does run the command it names.
 */
function unresolvedCommand(toks: Tok[]): boolean {
  const first = toks[0]
  const firstWord = first !== undefined && first.kind === 'word' ? first.text : undefined
  if (firstWord !== undefined) {
    if (ASSIGNMENT.test(firstWord) || SHELL_KEYWORDS.has(firstWord)) return true
    if (firstWord.startsWith('(') || firstWord.startsWith('{')) return true
    // A known prefix verb (`env`, `sudo`, `nohup`, `time`, `command`, `busybox`)
    // is stripped by `unwrapSegments`, which re-derives the segment afterwards.
    // It must not make the raw reading look unresolved, or every `sudo git push`
    // would be flagged ambiguous on the strength of the prefix alone.
    const base = commandBase(firstWord)
    if (RULE_VERBS.has(base) || PREFIX_VERBS.has(base)) return false
    if (MENTION_VERBS.has(base)) {
      return base === 'find' && toks.some((t) => t.kind === 'word' && t.text === '-exec')
    }
  }
  return toks.some((t, i) => i > 0 && t.kind === 'word' && RULE_VERBS.has(t.text))
}

function buildSegment(source: string, toks: Tok[], exhausted: boolean): Segment {
  const argv = toks.map((t) => t.text)
  const verb = argv[0]
  const flags: string[] = []
  const paths: string[] = []
  for (const t of toks) {
    if (t.kind === 'sep') continue
    if (t.kind === 'redir' || t.text.startsWith('-')) flags.push(t.text)
    else if (t.kind === 'target' || looksLikePath(t.text)) paths.push(t.text)
  }
  const sub = subcommandIndex(toks, verb)
  const refspecs =
    sub.index < 0
      ? []
      : toks
          .slice(sub.index + 1)
          .filter((t) => t.kind === 'word' && !t.text.startsWith('-'))
          .map((t) => t.text)
  const ambiguous =
    exhausted ||
    sub.unknownOption ||
    unresolvedCommand(toks) ||
    toks.some((t) => t.expandable) ||
    (verb !== undefined && (OPAQUE_VERBS.has(verb) || EXEC_WRAPPERS.has(verb)))
  const words = toks.filter((t) => t.kind !== 'sep')
  const segment: Segment = {
    raw: source.slice(words[0].start, words[words.length - 1].end).trim(),
    argv,
    verb,
    subcommand: sub.index < 0 ? undefined : toks[sub.index].text,
    flags,
    refspecs,
    paths: [...new Set(paths)],
    ambiguous,
  }
  // Bodies stay in order for the (exotic) segment that owns more than one.
  const bodies = toks.filter((t) => t.heredoc !== undefined).map((t) => t.heredoc as string)
  if (bodies.length > 0) segment.heredoc = bodies.join('\n')
  return segment
}

/**
 * Parse a shell command into its segments. `depth` is the shell-wrapper nesting
 * level: once it reaches `MAX_WRAP_DEPTH` the segments are marked ambiguous
 * instead of parsed, so an unreadable wrapper can never be treated as harmless.
 *
 * The operator that ends a segment stays in that segment's `argv` (its kind is
 * `sep`, so no rule reads it as a word): splitting must not drop tokens, and the
 * concatenated `argv` still holds every word, operator and redirection target of
 * the command. A heredoc BODY is the one deliberate exception — it is not argv —
 * so the round trip covers the command surface only: every body is removed from
 * the token stream and attached to its owning segment as `Segment.heredoc`.
 */
export function parseCommand(command: string, depth = 0): Segment[] {
  const exhausted = depth >= MAX_WRAP_DEPTH
  const segments: Segment[] = []
  let group: Tok[] = []
  const flushGroup = (): void => {
    if (group.length > 0) segments.push(buildSegment(command, group, exhausted))
    group = []
  }
  for (const t of tokenize(command)) {
    if (t.kind === 'sep') {
      if (group.length > 0) {
        group.push(t)
        flushGroup()
      }
      continue
    }
    group.push(t)
  }
  flushGroup()
  return segments
}

/* ------------------------------------------------------------------ *
 * Wrapper unwrapping and heredoc classification
 * ------------------------------------------------------------------ */

/**
 * Shells whose `-c <script>` argument the guard can parse as a script itself,
 * plus the same shape under other POSIX-ish names. A verb outside this set is
 * judged as itself: the guard never guesses that some other program runs its
 * argument as a shell script — only the interpreters below are known to run an
 * argument as a program, and those stay ambiguous instead.
 */
const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'ash', 'fish', 'csh', 'tcsh'])

/**
 * Verbs that run an inline program in another language. `python -c`, `node -e`
 * and friends are wrapper forms the guard cannot read: the segment stays
 * ambiguous, because "the program is opaque" must never read as "nothing runs".
 */
const INTERPRETER_SCRIPT_FLAGS: Record<string, readonly string[]> = {
  python: ['-c'],
  python3: ['-c'],
  node: ['-e', '-p'],
  perl: ['-e', '-E'],
  ruby: ['-e'],
  php: ['-r'],
}

/**
 * Prefixes that change WHO runs a command, never what it is. Stripping them is
 * what keeps `sudo git push` and the bare `git push` judged by the same rule.
 * `command` is the POSIX builtin prefix; `busybox` is a multi-call dispatcher
 * whose first word is the applet that really runs (`busybox sh -c …`).
 */
const PREFIX_VERBS = new Set(['env', 'sudo', 'nohup', 'time', 'command', 'busybox'])

/** Valueless short options, per prefix verb. */
const PREFIX_BARE_SHORT: Record<string, string> = {
  env: 'i0v',
  sudo: 'EHinSbkKAelsV',
  time: 'pvaq',
  nohup: '',
  command: 'pVv',
  busybox: '',
}

/** Short options that consume a value (glued or separated), per prefix verb. */
const PREFIX_VALUE_SHORT: Record<string, string> = {
  env: 'uCS',
  sudo: 'ughpCTrRtUDZ',
  time: 'o',
  nohup: '',
  command: '',
  busybox: '',
}

const PREFIX_BARE_LONG: Record<string, readonly string[]> = {
  env: ['--ignore-environment', '--null', '--debug'],
  sudo: [
    '--preserve-env',
    '--login',
    '--shell',
    '--stdin',
    '--non-interactive',
    '--set-home',
    '--reset-timestamp',
    '--validate',
    '--list',
    '--edit',
    '--askpass',
    '--background',
    '--version',
    '--help',
  ],
  time: ['--portability', '--verbose', '--append', '--quiet'],
  nohup: ['--help', '--version'],
  command: [],
  busybox: ['--help', '--version'],
}

const PREFIX_VALUE_LONG: Record<string, readonly string[]> = {
  env: ['--unset', '--chdir', '--split-string'],
  sudo: [
    '--user',
    '--group',
    '--host',
    '--prompt',
    '--close-from',
    '--command-timeout',
    '--role',
    '--type',
    '--other-user',
    '--chdir',
    '--chroot',
  ],
  time: ['--output'],
  nohup: [],
  command: [],
  busybox: ['--install'],
}

/** `env FOO=1 …` — an assignment the prefix exports, never the command's verb. */
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/

interface Stripped {
  /** The tokens from the real verb on. */
  toks: Tok[]
  /** How many leading tokens were removed. */
  dropped: number
  /** True when an unknown prefix option made the reading unprovable. */
  ambiguous: boolean
}

/**
 * Consume a prefix verb's own options and assignments.
 *
 * Fail-closed like `subcommandIndex`: an option that is in neither table may or
 * may not consume the next word. The optimistic reading skips the pair (which
 * keeps the real verb visible) and records `ambiguous`, so the rule layer asks
 * rather than allows.
 */
function skipPrefixOptions(verb: string, toks: Tok[], start: number): { index: number; ambiguous: boolean } {
  const bareShort = PREFIX_BARE_SHORT[verb] ?? ''
  const valueShort = PREFIX_VALUE_SHORT[verb] ?? ''
  const bareLong = PREFIX_BARE_LONG[verb] ?? []
  const valueLong = PREFIX_VALUE_LONG[verb] ?? []
  let i = start
  let ambiguous = false
  while (i < toks.length) {
    const t = toks[i]
    if (t.kind !== 'word') break
    if (verb === 'env' && ENV_ASSIGNMENT.test(t.text)) {
      i++
      continue
    }
    if (t.text === '--') {
      i++
      break
    }
    if (!t.text.startsWith('-') || t.text === '-') break
    const next = toks[i + 1]
    const consumeValue = (): void => {
      if (next !== undefined && next.kind === 'word') i += 2
      else {
        ambiguous = true
        i++
      }
    }
    if (t.text.startsWith('--')) {
      if (t.text.indexOf('=') > 0) i++ // --name=value is self-contained
      else if (bareLong.includes(t.text)) i++
      else if (valueLong.includes(t.text)) consumeValue()
      else if (next !== undefined && next.kind === 'word' && !next.text.startsWith('-')) {
        ambiguous = true
        i += 2
      } else i++
      continue
    }
    // A single-dash cluster: every character before a value-taking one is a flag.
    const chars = t.text.slice(1)
    let done = false
    for (let k = 0; k < chars.length && !done; k++) {
      const c = chars[k]
      if (verb === 'command' && (c === 'v' || c === 'V')) {
        // `command -v ls` / `command -V ls` only report where `ls` resolves to
        // (or describe it); they execute nothing. The guard has no "word that is
        // not a command" shape, so the reading is recorded as unprovable rather
        // than derived as a resolved `ls` execution that never happens.
        // `command -p ls` DOES run `ls`, so it stays resolvable.
        ambiguous = true
        continue
      }
      if (bareShort.includes(c)) continue
      if (valueShort.includes(c)) {
        if (k + 1 < chars.length) i++ // -uroot: the rest of the cluster is the value
        else consumeValue() // -u root: the value is the next word
        done = true
        break
      }
      ambiguous = true
      i++
      done = true
      break
    }
    if (!done) i++
  }
  return { index: i, ambiguous }
}

/** Drop the leading `env …` / `sudo …` / `nohup …` / `time …` prefixes. */
function stripPrefixes(toks: Tok[]): Stripped {
  let i = 0
  let ambiguous = false
  for (;;) {
    const t = toks[i]
    if (t === undefined || t.kind !== 'word' || !PREFIX_VERBS.has(t.text)) break
    i++
    const skipped = skipPrefixOptions(t.text, toks, i)
    i = skipped.index
    ambiguous = ambiguous || skipped.ambiguous
  }
  return { toks: toks.slice(i), dropped: i, ambiguous }
}

/**
 * The script a shell was told to run with `-c`: `-c cmd`, `-c'cmd'`, `-lc cmd`.
 * `found: false` means no `-c` appears at all (a script file, `-s`, a bare
 * shell), and `script: undefined` means `-c` had no argument — both unreadable.
 */
function shellCommandArg(toks: Tok[]): { found: boolean; script?: string } {
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i]
    if (t.kind !== 'word') break
    if (t.text === '--') break
    if (!t.text.startsWith('-') || t.text === '-') break
    if (t.text.startsWith('--')) {
      if (t.text === '--rcfile' || t.text === '--init-file') i++ // takes a value
      continue
    }
    const chars = t.text.slice(1)
    for (let k = 0; k < chars.length; k++) {
      const c = chars[k]
      if (c === 'c') {
        const inline = chars.slice(k + 1)
        if (inline !== '') return { found: true, script: inline }
        const next = toks[i + 1]
        return { found: true, script: next !== undefined && next.kind === 'word' ? next.text : undefined }
      }
      if (c === 'o' || c === 'O') {
        if (k + 1 === chars.length) i++ // -o pipefail: the value is the next word
        break
      }
    }
  }
  return { found: false }
}

/** True when an interpreter carries an inline program (`python -c`, `node -e`). */
function hasInterpreterScript(toks: Tok[]): boolean {
  const verb = toks[0]?.text
  if (verb === undefined) return false
  const flags = INTERPRETER_SCRIPT_FLAGS[verb]
  if (flags === undefined) return false
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i]
    if (t.kind !== 'word') break
    if (t.text === '--') break
    if (!t.text.startsWith('-') || t.text === '-') break
    if (flags.includes(t.text)) return true
    if (!t.text.startsWith('--')) {
      for (const c of t.text.slice(1)) if (flags.includes('-' + c)) return true
    }
  }
  return false
}

/** The tokens of one segment again, so its fields can be re-derived. */
function segmentTokens(seg: Segment): Tok[] {
  return tokenize(seg.raw).filter((t) => t.kind !== 'sep')
}

/** Re-derive a segment from a token subset of its own source text. */
function rebuild(seg: Segment, toks: Tok[], forced: boolean): Segment {
  const words = toks.filter((t) => t.kind !== 'sep')
  if (words.length === 0) {
    return { raw: seg.raw, argv: [], flags: [], refspecs: [], paths: [], ambiguous: true }
  }
  const built = buildSegment(seg.raw, words, forced)
  if (seg.heredoc !== undefined) built.heredoc = seg.heredoc
  return built
}

/**
 * Remove every wrapper around a parsed command and return the segments that
 * actually run.
 *
 * A segment that is not a wrapper is returned unchanged — same object, no
 * re-derivation — so the common path costs nothing and cannot drift. A shell
 * wrapper (`bash -c …`, `bash -s`, a `bash <<EOF` body) is REPLACED by the
 * segments of its script, each tagged `wrappedBy`. A wrapper that cannot be read
 * — unknown nesting past `MAX_WRAP_DEPTH`, a `-c` with no argument, a script file
 * the guard cannot open, an interpreter's inline program — stays in the result
 * marked `ambiguous`, which the rule layer answers with a prompt, never an allow.
 * An exec-like wrapper (`timeout`, `nice`, `setsid`, `watch`, …) is not unwrapped
 * at all and is `ambiguous` for the same reason: the command it runs is not the
 * command the guard read.
 */
export function unwrapSegments(segs: Segment[], depth = 0): Segment[] {
  const out: Segment[] = []
  for (const seg of segs) out.push(...unwrapSegment(seg, depth))
  return out
}

function unwrapSegment(seg: Segment, depth: number): Segment[] {
  const toks = segmentTokens(seg)
  const stripped = stripPrefixes(toks)
  const rest = stripped.toks
  const verb = rest[0] !== undefined && rest[0].kind === 'word' ? rest[0].text : undefined

  if (verb !== undefined && SHELLS.has(verb)) {
    const command = shellCommandArg(rest)
    const script = command.found ? command.script : seg.heredoc
    if (script === undefined || depth >= MAX_WRAP_DEPTH) return [rebuild(seg, rest, true)]
    // Two readings stay approximations even with a script in hand: a `-c` script
    // that is also fed a heredoc may run whatever that body holds, and an
    // UNQUOTED heredoc delimiter lets the outer shell expand the body first. Mark
    // the derived segments ambiguous rather than present the text as exact.
    const delimiters = toks.filter((t) => t.heredoc !== undefined)
    const expanded =
      delimiters.length > 0 && !delimiters.every((t) => t.heredocQuoted === true) && /[$`]/.test(script)
    const approximate = (command.found && seg.heredoc !== undefined) || (!command.found && expanded)
    const inner = unwrapSegments(parseCommand(script, depth + 1), depth + 1)
    if (inner.length === 0) return [rebuild(seg, rest, true)]
    const ambiguous = seg.ambiguous || stripped.ambiguous || approximate
    return inner.map((s) => ({ ...s, wrappedBy: verb, ambiguous: s.ambiguous || ambiguous }))
  }

  const opaque =
    stripped.ambiguous ||
    (verb !== undefined &&
      INTERPRETER_SCRIPT_FLAGS[verb] !== undefined &&
      (hasInterpreterScript(rest) || seg.heredoc !== undefined))
  if (stripped.dropped === 0 && !opaque) return [seg]
  return [rebuild(seg, rest, seg.ambiguous || opaque)]
}

/* ------------------------------------------------------------------ *
 * Command and tool-argument interpretation
 * ------------------------------------------------------------------ */

/**
 * Collapse quoted spans — text inside quotes is data (echo/printf/script
 * bodies), not argv.
 */
export function stripQuoted(cmd: string): string {
  return cmd.replace(/"[^"]*"/g, ' ').replace(/'[^']*'/g, ' ')
}

/**
 * Collapse heredoc bodies — the lines fed to a command's stdin are data, not
 * argv. A heredoc body routinely contains protected path literals (setup
 * scripts, config generators) which must not be mistaken for an access.
 * Run this AFTER `stripQuoted` so a quoted delimiter (`<<'EOF'`) is already
 * reduced to its bare form.
 */
export function stripHeredocs(cmd: string): string {
  return cmd.replace(/<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?[^\r\n]*\r?\n[\s\S]*?^\1\s*$/gm, ' ')
}

/**
 * The executed command surface of a tool call. Shell-style tools carry their
 * script in `args.command` (bash/exec/shell/govard_shell); bare string args are
 * the command itself. Tools with no command field (read/write/memory/...) have
 * no execution surface, so protected-op detection must not apply to their
 * content — that was the source of the analysis-tool false positives.
 */
export function extractCommandText(args: unknown): string | undefined {
  if (args == null) return undefined
  if (typeof args === 'string') return args
  if (typeof args === 'object' && typeof (args as Record<string, unknown>).command === 'string') {
    return (args as Record<string, unknown>).command as string
  }
  return undefined
}

/**
 * The path a file-oriented tool call targets, from the args shapes the DSH and
 * Maestro file tools use (`path` / `file` / `file_path` / `filePath`, or a bare
 * string arg). Returns undefined when the call carries no path.
 */
export function extractPathField(args: unknown): string | undefined {
  if (args == null) return undefined
  if (typeof args === 'string') return args
  if (typeof args !== 'object') return undefined
  const a = args as Record<string, unknown>
  const v = a.path ?? a.file ?? a.file_path ?? a.filePath
  return typeof v === 'string' ? v : undefined
}

/**
 * Resolve the working directory a command actually executes in, when it names
 * one explicitly (cd <dir> / git -C <dir>). Falls back to the passed cwd when
 * the command has no explicit target — preserving the historical session-cwd
 * semantics for commands that run in place.
 */
export function getCommandWorkingDir(command: string | undefined, cwd: string | undefined): string | undefined {
  if (!command || !cwd) return cwd ?? undefined
  const hasCdVerb = /\bcd\b/.test(command) || /\bgit\s+-C\b/.test(command)
  const cd = /\bcd\s+([^\s;&|"'`${}]+)(?:\s*(?:[;&|]|$))/.exec(command)
  const c = /\bgit\s+-C\s+([^\s;&|"'`${}]+)/.exec(command)
  const dir = cd?.[1] ?? c?.[1]
  if (!dir) {
    // A cd/-C verb is present but its target cannot be parsed (quoted, $VAR,
    // wildcard, bare `cd`): do NOT assume the session cwd — that reintroduces
    // the false positive when the session cwd repo sits on a protected branch.
    // Unknown target means no protected-branch assumption (segment word checks
    // still apply); commands with no cd verb keep the session-cwd semantics.
    if (hasCdVerb) return undefined
    return cwd
  }
  if (dir === '~') return homedir()
  if (dir.startsWith('~/')) return join(homedir(), dir.slice(2))
  return resolve(cwd, dir)
}
