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
 *   token kind and is never read as a word);
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
 * Pure module: string in, data out. No filesystem, no child processes, no
 * network, and no expansion of `$VAR`/backticks — an unexpanded token is exactly
 * what `ambiguous` records.
 */

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
}

/** Verbs whose meaning is entirely "run whatever the arguments say". */
const OPAQUE_VERBS = new Set(['eval', 'exec', 'xargs'])

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
  let i = 0

  const emit = (text: string, kind: TokKind, start: number, end: number): void => {
    const k = kind === 'word' && pending === 'file' ? 'target' : kind
    if (kind === 'word' && pending !== null) pending = null
    toks.push({ text, kind: k, start, end, expandable })
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
      toks.push({ text: input.slice(start, i) + r.op, kind: 'redir', start, end: r.next, expandable: false })
      pending = r.dup ? null : r.op.startsWith('<<') ? 'heredoc' : 'file'
      i = r.next
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
    exhausted || sub.unknownOption || toks.some((t) => t.expandable) || (verb !== undefined && OPAQUE_VERBS.has(verb))
  const words = toks.filter((t) => t.kind !== 'sep')
  return {
    raw: source.slice(words[0].start, words[words.length - 1].end).trim(),
    argv,
    verb,
    subcommand: sub.index < 0 ? undefined : toks[sub.index].text,
    flags,
    refspecs,
    paths: [...new Set(paths)],
    ambiguous,
  }
}

/**
 * Parse a shell command into its segments. `depth` is the shell-wrapper nesting
 * level: once it reaches `MAX_WRAP_DEPTH` the segments are marked ambiguous
 * instead of parsed, so an unreadable wrapper can never be treated as harmless.
 *
 * The operator that ends a segment stays in that segment's `argv` (its kind is
 * `sep`, so no rule reads it as a word): splitting must not drop tokens, and the
 * round-trip invariant is asserted on the concatenated `argv`.
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
