import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DEFAULT_CONFIG,
  loadGuardConfig,
  loadGuardConfigWithMigration,
  mapLegacyConfig,
} from '../src/host/config.js'
import { Journal, journalPath } from '../src/host/journal.js'
import { journalLegacyConfigMigration } from '../src/host/index.js'

/**
 * The store lib's on-disk layout is its own private detail — it moved between
 * config-lib 0.1.x and 0.2.0, and `set()` refuses a legacy v1 `guard` document
 * because the v2 validator rejects it. Neither belongs in the guard's suite, so
 * the loader is driven through a mocked store: the contract under test is that
 * `domains.guard` is read, migrated and reported.
 */
const store = vi.hoisted(() => ({ doc: undefined as unknown, calls: [] as unknown[] }))

vi.mock('@ddtcorex/dsh-maestro-config-lib', () => ({
  load: async (opts?: unknown) => {
    store.calls.push(opts)
    return store.doc
  },
  get: async (_domain: string, opts?: unknown) => {
    store.calls.push(opts)
    return (store.doc as { domains?: Record<string, unknown> } | undefined)?.domains?.guard
  },
}))

/** Point the mocked store at a persisted `domains.guard` document. */
function withGuardDoc(guard: Record<string, unknown> | undefined): void {
  store.doc = guard === undefined ? { version: 1, domains: {} } : { version: 1, domains: { guard } }
}

async function tempHome(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'guard-config-'))
}

beforeEach(() => {
  store.calls = []
  store.doc = { version: 1, domains: {} }
})

/**
 * Schema v2 replaced the legacy `domains.guard` booleans with a per-rule tier
 * table. `mapLegacyConfig` is the one-way translation: it reads the old keys
 * and returns the v2 config plus the names of the legacy keys it actually
 * translated, so `apply()` can journal a single `config-legacy` note per boot
 * instead of silently changing what the guard gates.
 */
describe('mapLegacyConfig', () => {
  it('maps the legacy keys onto the rule table', () => {
    const { config, migratedKeys } = mapLegacyConfig({
      gitProtection: { enabled: false, branches: ['trunk'] },
      publishBlocked: false,
      cwdContainment: true,
      credentialPaths: ['/x'],
    })
    expect(config.rules['git.push.protected']).toBe('journal') // git protection disabled
    expect(config.rules['pkg.publish']).toBe('journal') // publish not blocked
    expect(config.protectedBranches).toEqual(['trunk'])
    expect(config.protectedPaths).toContain('/x')
    expect(migratedKeys).toContain('gitProtection')
  })

  it('disables every git gate when git protection was off', () => {
    const { config } = mapLegacyConfig({ gitProtection: { enabled: false } })
    expect(config.rules['git.push.protected']).toBe('journal')
    expect(config.rules['git.tag.release']).toBe('journal')
    expect(config.rules['git.push.force']).toBe('journal')
  })

  it('journals the outside-cwd write when containment was off', () => {
    const { config, migratedKeys } = mapLegacyConfig({ cwdContainment: false })
    expect(config.rules['fs.write.outside']).toBe('journal')
    expect(migratedKeys).toContain('cwdContainment')
  })

  it('replaces, never extends, the protected branch list', () => {
    const { config } = mapLegacyConfig({ gitProtection: { branches: ['trunk', 'release'] } })
    expect(config.protectedBranches).toEqual(['trunk', 'release'])
  })

  it('appends the legacy credential paths to the built-in protected paths', () => {
    const { config, migratedKeys } = mapLegacyConfig({ credentialPaths: ['/legacy/creds', '/legacy/token'] })
    expect(config.protectedPaths).toEqual([...DEFAULT_CONFIG.protectedPaths, '/legacy/creds', '/legacy/token'])
    expect(migratedKeys).toContain('credentialPaths')
  })

  it('does not repeat a credential path that is already protected', () => {
    const { config } = mapLegacyConfig({ credentialPaths: ['/legacy/creds', '/legacy/creds'] })
    expect(config.protectedPaths.filter((p) => p === '/legacy/creds')).toHaveLength(1)
  })

  it('reports only the keys that actually changed something', () => {
    const { config, migratedKeys } = mapLegacyConfig({
      gitProtection: { enabled: true },
      publishBlocked: true,
      cwdContainment: true,
      credentialPaths: [],
    })
    // `gitProtection` is reported because its branch list is still consumed and
    // the key is superseded; the no-op booleans changed nothing and stay out.
    expect(migratedKeys).toEqual(['gitProtection'])
    expect(config.rules).toEqual(DEFAULT_CONFIG.rules)
  })

  it('returns the defaults, untouched, when no legacy key is present', () => {
    const { config, migratedKeys } = mapLegacyConfig({})
    expect(migratedKeys).toEqual([])
    expect(config).toEqual(DEFAULT_CONFIG)
    expect(config).not.toBe(DEFAULT_CONFIG)
    expect(config.rules).not.toBe(DEFAULT_CONFIG.rules)
  })

  it('never mutates the exported defaults', () => {
    const before = JSON.parse(JSON.stringify(DEFAULT_CONFIG))
    mapLegacyConfig({
      gitProtection: { enabled: false, branches: ['trunk'] },
      publishBlocked: false,
      cwdContainment: false,
      credentialPaths: ['/legacy'],
    })
    expect(DEFAULT_CONFIG).toEqual(before)
  })

  it('keeps the new v2 keys of a half-migrated config', () => {
    const { config } = mapLegacyConfig({
      publishBlocked: false,
      rules: { 'secret.access': 'journal' },
      protectedPaths: ['/v2/only'],
      journal: { retainDays: 7, retainFiles: 3, enabled: false, allowCounters: false },
    })
    expect(config.rules['secret.access']).toBe('journal')
    expect(config.rules['pkg.publish']).toBe('journal')
    expect(config.protectedPaths).toContain('/v2/only')
    expect(config.journal.retainDays).toBe(7)
  })

  it('leaves a partial or unreadable legacy object on the defaults', () => {
    const { config, migratedKeys } = mapLegacyConfig({ gitProtection: 'on', publishBlocked: 'no' })
    expect(migratedKeys).toEqual([])
    expect(config).toEqual(DEFAULT_CONFIG)
  })

  it('lets an explicit v2 rule win over the legacy boolean that maps to it', () => {
    // The legacy translation is the OLDER reading of the document, so it is
    // applied first and the v2 `rules` map is merged on top of it.
    const { config } = mapLegacyConfig({
      gitProtection: { enabled: false },
      publishBlocked: false,
      rules: { 'pkg.publish': 'deny' },
    })
    expect(config.rules['pkg.publish']).toBe('deny')
    expect(config.rules['git.push.protected']).toBe('journal') // untouched by v2
  })

  it('does not report an empty legacy gitProtection object', () => {
    const { config, migratedKeys } = mapLegacyConfig({
      gitProtection: {},
      protectedBranches: ['release'],
    })
    expect(migratedKeys).toEqual([])
    expect(config.protectedBranches).toEqual(['release'])
  })
})

/**
 * The loader half of the finding: a persisted v1 `domains.guard` must actually
 * be migrated at runtime, not only by a `mapLegacyConfig` nobody calls.
 * `loadGuardConfigWithMigration` reports the keys so `apply()` can journal one
 * note per boot; `loadGuardConfig` stays the cheap per-call read.
 */
describe('loadGuardConfigWithMigration', () => {
  it('migrates a persisted legacy document and reports the keys', async () => {
    withGuardDoc({
      gitProtection: { enabled: false, branches: ['trunk'] },
      publishBlocked: false,
      credentialPaths: ['/legacy/creds'],
    })
    const { config, migratedKeys } = await loadGuardConfigWithMigration()
    // Coverage must not narrow: the legacy branch list and credential paths survive.
    expect(config.protectedBranches).toEqual(['trunk'])
    expect(config.protectedPaths).toContain('/legacy/creds')
    expect(config.rules['git.push.protected']).toBe('journal')
    expect(config.rules['pkg.publish']).toBe('journal')
    expect(migratedKeys.sort()).toEqual(['credentialPaths', 'gitProtection', 'publishBlocked'])
  })

  it('reports nothing for a document that is already schema v2', async () => {
    withGuardDoc({
      rules: { 'secret.access': 'journal' },
      protectedBranches: ['release'],
    })
    const { config, migratedKeys } = await loadGuardConfigWithMigration()
    expect(migratedKeys).toEqual([])
    expect(config.rules['secret.access']).toBe('journal')
    expect(config.protectedBranches).toEqual(['release'])
  })

  it('keeps loadGuardConfig a thin wrapper that returns the plain config', async () => {
    withGuardDoc({ credentialPaths: ['/legacy/wrapper'] })
    const config = await loadGuardConfig()
    expect(config.protectedPaths).toContain('/legacy/wrapper')
    expect(config.rules).toEqual(DEFAULT_CONFIG.rules)
  })

  it('falls back to the defaults when the store is missing', async () => {
    withGuardDoc(undefined)
    const { config, migratedKeys } = await loadGuardConfigWithMigration()
    expect(migratedKeys).toEqual([])
    expect(config).toEqual(DEFAULT_CONFIG)
  })

  it('passes the DSH home through to the store read', async () => {
    withGuardDoc(undefined)
    await loadGuardConfigWithMigration('/home/x/.dsh-test')
    expect(store.calls).toEqual([{ dshHome: '/home/x/.dsh-test' }])
  })
})

/**
 * The boot-time half: exactly one `config-legacy` journal entry, and only when
 * something was migrated.
 */
describe('journalLegacyConfigMigration', () => {
  it('journals one config-legacy note naming the migrated keys', async () => {
    const home = await tempHome()
    withGuardDoc({ gitProtection: { branches: ['trunk'] } })
    const journal = new Journal(home)
    const migrated = await journalLegacyConfigMigration(journal, home)
    expect(migrated).toEqual(['gitProtection'])
    const text = await readFile(journalPath(home), 'utf8')
    const lines = text.trim().split('\n')
    expect(lines).toHaveLength(1)
    const entry = JSON.parse(lines[0])
    expect(entry.rule).toBe('config-legacy')
    expect(entry.tier).toBe('journal')
    expect(entry.target).toBe('gitProtection')
    expect(entry.note).toContain('gitProtection')
  })

  it('journals nothing when the document is already v2', async () => {
    const home = await tempHome()
    withGuardDoc({ protectedBranches: ['release'] })
    const journal = new Journal(home)
    expect(await journalLegacyConfigMigration(journal, home)).toEqual([])
    expect(store.calls).toHaveLength(1) // the read happened, the journal entry did not
    await expect(readFile(journalPath(home), 'utf8')).rejects.toThrow()
  })
})
