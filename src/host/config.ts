import { DEFAULT_TIERS } from './rules.js'
import { defaultProtectedPaths, guardConfigPaths } from './paths.js'
import type { Tier } from './tiers.js'

/**
 * Schema v2 of `domains.guard`. Every decision the pipeline makes is a lookup
 * on this object: `classify` produces a rule id, `decide` maps it through
 * `rules`, and the settings lists feed the classifier's path/branch checks.
 *
 * {@link mapLegacyConfig} carries a document written for schema v1 (the
 * `gitProtection` / `publishBlocked` / `cwdContainment` / `credentialPaths`
 * booleans) forward; {@link mergeGuardConfig} reads a v2 document.
 */
export interface GuardConfigV2 {
  rules: Record<string, Tier>
  protectedBranches: string[]
  protectedPaths: string[]
  guardPaths: string[]
  journal: { enabled: boolean; retainDays: number; retainFiles: number; allowCounters: boolean }
  workingDirContainment: { enabled: boolean; spillReads: boolean }
}

/**
 * Built-in defaults. Protection is ON for everything that can be on: a missing,
 * unreadable or half-written config must never turn a gate off, so every
 * fallback path lands here rather than on an empty object.
 */
export const DEFAULT_CONFIG: GuardConfigV2 = {
  rules: { ...DEFAULT_TIERS },
  protectedBranches: ['master', 'main'],
  protectedPaths: defaultProtectedPaths(),
  guardPaths: guardConfigPaths(),
  journal: { enabled: true, retainDays: 30, retainFiles: 14, allowCounters: true },
  workingDirContainment: { enabled: true, spillReads: true },
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function stringArray(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined
  const out = v.filter((x): x is string => typeof x === 'string')
  return out.length > 0 ? out : undefined
}

/**
 * A retention window must be a positive finite number. The journal block used to
 * be spread into the defaults unvalidated, and `rotate()` multiplies/compares
 * with both windows: `retainDays: "30"` makes the day cutoff `NaN` and
 * `retainFiles: "14"` makes the file window compare false, so BETWEEN them a
 * non-numeric value prunes EVERY archive. An invalid value falls back to the
 * built-in default — the fail-safe direction for a retention window.
 */
function positiveInt(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.floor(v) : undefined
}

/** A boolean config switch, or the built-in default when it is not a boolean. */
function booleanOr(v: unknown, fallback: boolean): boolean {
  return typeof v === 'boolean' ? v : fallback
}

/**
 * Merge the persisted `domains.guard` object onto the defaults. Only keys that
 * are actually present are overlaid, and `rules` merges per rule id, so a
 * partial config can neither drop the default tiers nor unset the protected
 * path lists.
 */
export function mergeGuardConfig(raw: unknown): GuardConfigV2 {
  const base: GuardConfigV2 = {
    ...DEFAULT_CONFIG,
    rules: { ...DEFAULT_CONFIG.rules },
    protectedBranches: [...DEFAULT_CONFIG.protectedBranches],
    protectedPaths: [...DEFAULT_CONFIG.protectedPaths],
    guardPaths: [...DEFAULT_CONFIG.guardPaths],
    journal: { ...DEFAULT_CONFIG.journal },
    workingDirContainment: { ...DEFAULT_CONFIG.workingDirContainment },
  }
  if (!isPlainObject(raw)) return base

  if (isPlainObject(raw.rules)) {
    for (const [rule, tier] of Object.entries(raw.rules)) {
      if (typeof tier === 'string') base.rules[rule] = tier as Tier
    }
  }
  base.protectedBranches = stringArray(raw.protectedBranches) ?? base.protectedBranches
  base.protectedPaths = stringArray(raw.protectedPaths) ?? base.protectedPaths
  base.guardPaths = stringArray(raw.guardPaths) ?? base.guardPaths
  if (isPlainObject(raw.journal)) {
    const j = raw.journal as Record<string, unknown>
    base.journal = {
      enabled: booleanOr(j.enabled, base.journal.enabled),
      allowCounters: booleanOr(j.allowCounters, base.journal.allowCounters),
      retainDays: positiveInt(j.retainDays) ?? base.journal.retainDays,
      retainFiles: positiveInt(j.retainFiles) ?? base.journal.retainFiles,
    }
  }
  if (isPlainObject(raw.workingDirContainment)) {
    const c = raw.workingDirContainment as Record<string, unknown>
    base.workingDirContainment = {
      enabled: booleanOr(c.enabled, base.workingDirContainment.enabled),
      spillReads: booleanOr(c.spillReads, base.workingDirContainment.spillReads),
    }
  }
  return base
}

/**
 * The legacy keys schema v2 replaced, and the rules each one used to gate.
 * `gitProtection.enabled: false` switched the whole git family off, so all
 * three git rules become `journal` (still recorded, never prompted).
 */
const LEGACY_GIT_RULES = ['git.push.protected', 'git.tag.release', 'git.push.force'] as const

/** The four keys schema v2 replaced. They are stripped before the v2 merge. */
const LEGACY_KEYS = new Set(['gitProtection', 'publishBlocked', 'cwdContainment', 'credentialPaths'])

/**
 * Translate a persisted `domains.guard` object that still carries the legacy
 * `gitProtection` / `publishBlocked` / `cwdContainment` / `credentialPaths`
 * keys onto schema v2.
 *
 * The legacy translation is applied FIRST and the remaining v2 document is
 * merged on top of it: the legacy booleans are the older reading of the
 * document, so an explicit v2 `rules` entry must win over the boolean that
 * translated onto the same rule id. Nothing is mutated: the arrays, the rule
 * table and the nested objects are fresh copies, which matters because
 * `DEFAULT_CONFIG` is a module-level object shared by every caller.
 *
 * `migratedKeys` names the legacy keys that were actually read (a key that is
 * absent, or a `gitProtection` that carries no setting at all, is not
 * reported; `publishBlocked: true` / `cwdContainment: true` / an empty
 * `credentialPaths` changed nothing and stay out). `apply()` journals one
 * `config-legacy` note per boot from this list, so an operator can see why the
 * gate changed instead of discovering it from a silent behaviour shift.
 */
export function mapLegacyConfig(raw: unknown): { config: GuardConfigV2; migratedKeys: string[] } {
  if (!isPlainObject(raw)) return { config: mergeGuardConfig(undefined), migratedKeys: [] }
  const migratedKeys: string[] = []

  // Stage 1 — translate the legacy keys onto the v2 shape.
  const legacyRules: Record<string, Tier> = {}
  let legacyBranches: string[] | undefined
  let legacyCredentialPaths: string[] | undefined

  const gitProtection = raw.gitProtection
  if (isPlainObject(gitProtection) && Object.keys(gitProtection).length > 0) {
    migratedKeys.push('gitProtection')
    if (gitProtection.enabled === false) {
      for (const rule of LEGACY_GIT_RULES) legacyRules[rule] = 'journal'
    }
    legacyBranches = stringArray(gitProtection.branches)
  }

  if (raw.publishBlocked === false) {
    migratedKeys.push('publishBlocked')
    legacyRules['pkg.publish'] = 'journal'
  }

  if (raw.cwdContainment === false) {
    migratedKeys.push('cwdContainment')
    legacyRules['fs.write.outside'] = 'journal'
  }

  const credentialPaths = stringArray(raw.credentialPaths)
  if (credentialPaths) {
    migratedKeys.push('credentialPaths')
    legacyCredentialPaths = credentialPaths
  }

  // Stage 2 — the v2 document wins key by key; `rules` merges per rule id so an
  // explicit v2 tier beats the legacy boolean that produced the same id.
  const v2: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(raw)) {
    if (!LEGACY_KEYS.has(key)) v2[key] = value
  }
  const v2Rules = isPlainObject(v2.rules) ? v2.rules : {}
  const config = mergeGuardConfig({
    ...v2,
    rules: { ...legacyRules, ...v2Rules },
    protectedBranches: stringArray(v2.protectedBranches) ?? legacyBranches,
  })

  // The legacy credential paths are an ADDITION to whatever protected the
  // document, never a replacement: narrowing coverage is exactly the failure
  // this migration exists to prevent.
  if (legacyCredentialPaths) {
    config.protectedPaths = [...new Set([...config.protectedPaths, ...legacyCredentialPaths])]
  }

  return { config, migratedKeys }
}

/**
 * Read the raw `domains.guard` value from the shared Maestro settings store. A
 * missing store, an absent domain or an unreadable file all yield `undefined`:
 * the caller falls back to the built-in defaults, so the guard's own
 * protection may degrade in precision, never in coverage.
 */
async function readGuardDomain(dshHome?: string): Promise<unknown> {
  try {
    const mod: any = await import('@ddtcorex/dsh-maestro-config-lib')
    const opts = dshHome === undefined ? undefined : { dshHome }
    if (typeof mod.load === 'function') {
      const doc = await mod.load(opts)
      return doc?.domains?.guard
    }
    if (typeof mod.get === 'function') {
      return await mod.get('guard', opts)
    }
  } catch (e) {
    console.error('[dsh-maestro-guard] guard config read failed, using defaults:', (e as Error)?.message)
  }
  return undefined
}

/**
 * The migrating read: run the persisted `domains.guard` through
 * {@link mapLegacyConfig} and report which legacy keys were translated, so
 * `apply()` can journal one `config-legacy` note per boot.
 *
 * `mapLegacyConfig` is pure and this is the only place a v1 document is
 * translated at runtime — before this existed, `loadGuardConfig` called
 * `mergeGuardConfig` directly and a persisted v1 document silently lost its
 * `credentialPaths` and custom branch list.
 */
export async function loadGuardConfigWithMigration(dshHome?: string): Promise<{ config: GuardConfigV2; migratedKeys: string[] }> {
  return mapLegacyConfig(await readGuardDomain(dshHome))
}

/**
 * The per-call read the guard handler performs on every tool call: a thin
 * wrapper over {@link loadGuardConfigWithMigration} that returns only the
 * config. No journaling happens here — that is a once-per-boot concern.
 */
export async function loadGuardConfig(dshHome?: string): Promise<GuardConfigV2> {
  return (await loadGuardConfigWithMigration(dshHome)).config
}
