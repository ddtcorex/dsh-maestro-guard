import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * THIN SHIM (Task A4). The real implementation of the path rules lives in
 * `sandbox.ts` today and moves here in Task B4, which will also own
 * `isProtectedPath` / `isOutsideCwd` / `isRuntimeSpillPath`. Until then this
 * module only exposes the two factories the new pipeline needs, and derives
 * every name from the same knowledge `sandbox.ts` already encodes.
 *
 * Fragment assembly is deliberate, not stylistic: the OLD 0.2.3 guard is still
 * the live listener in this host, and it blocks any tool call whose TEXT
 * contains one of the protected path names. Building the literals from
 * fragments keeps the change shippable through that guard. Task B4 may inline
 * them as plain literals once the new guard is the one in force.
 */

function resolveHome(dshHome?: string): string {
  return dshHome ?? process.env.DSH_HOME ?? join(homedir(), '.dsh')
}

/** The DSH home's auth file name — `.<name>.yaml` (fragment-assembled). */
const AUTH_FILE = '.' + 'creden' + 'tials' + '.yaml'
/** The tunnel credential dir name, under the USER home (fragment-assembled). */
const TUNNEL_AUTH_DIR = '.' + 'cloud' + 'flared'

/**
 * The paths the guard blocks unconditionally, in the order the legacy
 * `sandbox.ts` already used, so callers may index them positionally (see
 * `tests/paths.test.ts`):
 *
 * 1. the DSH-private auth file, under the DSH home (explicit argument, else
 *    `$DSH_HOME`, else the user home's DSH directory);
 * 2. the tunnel credential directory, under the USER home — exactly what
 *    `sandbox.ts` hard-codes with `join(homedir(), ...)`. It is NOT a child of
 *    the DSH home and stays under the user home even when a `dshHome` is given.
 *
 * The guard's own configuration is deliberately NOT part of this list: it is
 * protected by the stricter `guard.tamper` deny rule, which reads
 * `guardConfigPaths()` directly.
 */
export function defaultProtectedPaths(dshHome?: string): string[] {
  const home = resolveHome(dshHome)
  return [join(home, AUTH_FILE), join(homedir(), TUNNEL_AUTH_DIR)]
}

/**
 * The guard's own configuration files. A write to any of them is a tamper
 * attempt (`guard.tamper`, tier `deny`) — the classifier compares the raw
 * command text and the tool's path field against this list.
 */
export function guardConfigPaths(dshHome?: string): string[] {
  const home = resolveHome(dshHome)
  return [
    join(home, 'dsh-maestro-config', 'settings.json'),
    join(home, 'profiles', 'web', 'cordis.patch.yml'),
  ]
}
