import { DEFAULT_TIERS } from './rules.js'
import { defaultProtectedPaths, guardConfigPaths } from './paths.js'
import type { Tier } from './tiers.js'

/**
 * Schema v2 of `domains.guard`. Every decision the pipeline makes is a lookup
 * on this object: `classify` produces a rule id, `decide` maps it through
 * `rules`, and the settings lists feed the classifier's path/branch checks.
 *
 * Task B5 adds `mapLegacyConfig()` (the legacy `gitProtection` / `publishBlocked`
 * / `cwdContainment` / `credentialPaths` keys) and its tests; Task A4 only
 * needs the defaults plus a live read of the new keys.
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
  if (isPlainObject(raw.journal)) base.journal = { ...base.journal, ...(raw.journal as GuardConfigV2['journal']) }
  if (isPlainObject(raw.workingDirContainment)) {
    base.workingDirContainment = { ...base.workingDirContainment, ...(raw.workingDirContainment as GuardConfigV2['workingDirContainment']) }
  }
  return base
}

/**
 * Read `domains.guard` from the shared Maestro settings store. A missing store,
 * an absent domain or an unreadable file all yield {@link DEFAULT_CONFIG}: the
 * guard's own protection may degrade in precision, never in coverage.
 */
export async function loadGuardConfig(): Promise<GuardConfigV2> {
  try {
    const mod: any = await import('@ddtcorex/dsh-maestro-config-lib')
    if (typeof mod.load === 'function') {
      const doc = await mod.load()
      return mergeGuardConfig(doc?.domains?.guard)
    }
    if (typeof mod.get === 'function') {
      return mergeGuardConfig(await mod.get('guard'))
    }
  } catch (e) {
    console.error('[dsh-maestro-guard] guard config read failed, using defaults:', (e as Error)?.message)
  }
  return mergeGuardConfig(undefined)
}
