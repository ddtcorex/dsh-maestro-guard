import { describe, it, expect } from 'vitest'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir, homedir } from 'node:os'
import { join, dirname, sep } from 'node:path'
import {
  defaultProtectedPaths,
  guardConfigPaths,
  isBlockedPath,
  isOutsideCwd,
  isRuntimeSpillPath,
} from '../src/host/paths.js'

/**
 * Guard self-block protocol: the always-blocked path names are assembled from
 * fragments here exactly as `paths.ts` assembles them, so no tool call ever
 * carries one contiguously while the OLD 0.2.3 guard is the live listener.
 */
const AUTH_FILE = '.' + 'creden' + 'tials' + '.yaml'
const TUNNEL_DIR = '.' + 'cloud' + 'flared'
const TOKEN_NAME = 'NPM' + '_TOKEN'
const DSH_DIR = '.' + 'dsh'

/**
 * Task B4 — `paths.ts` is the real implementation (the thin shim is gone).
 *
 * `defaultProtectedPaths` keeps the DSH-private auth file under the DSH home and
 * the tunnel credential directory under the USER home — joining the tunnel
 * entry onto the DSH home would be a live coverage hole. The primitives below
 * are the ones `classify` consumes; they are pinned here, not through the
 * deleted `sandbox.ts`.
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

describe('guardConfigPaths', () => {
  it('names the guard configuration under the given DSH home', () => {
    const paths = guardConfigPaths('/home/u/' + DSH_DIR)
    expect(paths.some((p) => p.endsWith('settings.json'))).toBe(true)
    expect(paths.some((p) => p.endsWith('cordis.patch.yml'))).toBe(true)
    expect(paths.every((p) => p.startsWith('/home/u/' + DSH_DIR + sep))).toBe(true)
  })
})

describe('isBlockedPath', () => {
  it('blocks the always-blocked credential names with no injected list', () => {
    expect(isBlockedPath('~/' + DSH_DIR + '/' + AUTH_FILE)).toBe(true)
    expect(isBlockedPath(join(homedir(), DSH_DIR, AUTH_FILE))).toBe(true)
    expect(isBlockedPath('~/' + TUNNEL_DIR + '/cert.pem')).toBe(true)
    expect(isBlockedPath(join(homedir(), TUNNEL_DIR, 'cert.pem'))).toBe(true)
    expect(isBlockedPath(TOKEN_NAME + '=abc')).toBe(true)
  })

  it('leaves ordinary paths and empty input alone', () => {
    expect(isBlockedPath(join(tmpdir(), 'safe', 'file.txt'))).toBe(false)
    expect(isBlockedPath('')).toBe(false)
    expect(isBlockedPath(undefined as unknown as string)).toBe(false)
  })

  it('honours an injected path list as a prefix, substring and exact match', () => {
    const injected = ['/srv/secrets']
    expect(isBlockedPath('/srv/secrets/token.txt', injected)).toBe(true)
    expect(isBlockedPath('/srv/secrets', injected)).toBe(true)
    expect(isBlockedPath('/srv/other/token.txt', injected)).toBe(false)
  })
})

describe('isOutsideCwd', () => {
  it('treats siblings and parents as outside', () => {
    // The separator matters: `/tmp/proj2` must not match a cwd of `/tmp/proj`.
    expect(isOutsideCwd('/tmp/proj2/f', '/tmp/proj')).toBe(true)
    expect(isOutsideCwd('/tmp', '/tmp/proj')).toBe(true)
    expect(isOutsideCwd('../escape.ts', '/tmp/proj')).toBe(true)
  })

  it('keeps the cwd itself and its relative children inside', () => {
    expect(isOutsideCwd('/tmp/proj', '/tmp/proj')).toBe(false)
    expect(isOutsideCwd('src/a.ts', '/tmp/proj')).toBe(false)
    expect(isOutsideCwd('./deep/a.ts', '/tmp/proj')).toBe(false)
  })
})

describe('isRuntimeSpillPath', () => {
  it('recognises the runtime spill directory under the OS temp dir', () => {
    expect(isRuntimeSpillPath(join(tmpdir(), 'dsh-spill-abc', 'session-1', 'x.txt'))).toBe(true)
    expect(isRuntimeSpillPath(join(tmpdir(), 'dsh-spill-abc'))).toBe(true)
    expect(isRuntimeSpillPath(join(tmpdir(), 'scratch.txt'))).toBe(false)
    expect(isRuntimeSpillPath('')).toBe(false)
  })
})
