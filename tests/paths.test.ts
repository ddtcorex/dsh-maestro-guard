import { describe, it, expect } from 'vitest'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir, homedir } from 'node:os'
import { join, dirname, sep } from 'node:path'
import { defaultProtectedPaths } from '../src/host/paths.js'
import { isBlockedPath } from '../src/host/sandbox.js'

/**
 * Fix round 1 — pin the shim's two protected entries.
 *
 * `src/host/sandbox.ts` hard-codes the tunnel credential directory under the
 * USER home (`join(homedir(), ...)`), while the DSH-private auth file lives
 * under the DSH home. The shim must return exactly that split: joining the
 * tunnel entry onto the DSH home is masked today by sandbox's hard-coded
 * substring, and becomes a live coverage hole the moment Task B4 deletes those
 * substrings.
 *
 * No protected path name is written here. Every value under test is built from
 * `defaultProtectedPaths()` and compared against `homedir()` / the temp DSH
 * home with prefix and `dirname` checks.
 */
describe('defaultProtectedPaths', () => {
  it('keeps the DSH-private entry under the DSH home and the tunnel entry under the user home', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'g-paths-'))
    const [dshPrivate, tunnel] = defaultProtectedPaths(dshHome)

    // The private auth file sits directly in the supplied DSH home.
    expect(dshPrivate.startsWith(dshHome + sep)).toBe(true)
    expect(dirname(dshPrivate)).toBe(dshHome)

    // The tunnel credential dir sits under the OS user home, NOT the DSH home.
    expect(tunnel.startsWith(homedir() + sep)).toBe(true)
    expect(dirname(tunnel)).toBe(homedir())
    expect(dirname(tunnel)).not.toBe(dirname(dshPrivate))
  })

  it('matches the returned tunnel entry through the injected credential list', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'g-paths-'))
    const injected = defaultProtectedPaths(dshHome)
    const tunnel = injected[1]

    expect(isBlockedPath(tunnel, injected)).toBe(true)
    expect(isBlockedPath(join(tunnel, 'cert.json'), injected)).toBe(true)
  })

  it('does not match an ordinary file path under the DSH home', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'g-paths-'))
    const safe = join(dshHome, 'sessions', 'session.jsonl')

    expect(isBlockedPath(safe, defaultProtectedPaths(dshHome))).toBe(false)
  })
})
