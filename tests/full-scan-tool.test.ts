import { describe, it, expect } from 'vitest'
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// `maestro_full_scan` runs `scripts/enforce-rules.mjs` against a workspace root.
// The tool used to fall back to `process.cwd()` whenever no script sat under the
// requested root, so a call aimed at an unrelated directory silently scanned the
// guard's OWN checkout and reported that repo's blacklist hits instead. The old
// test could not see it: it passed `/tmp`, which never holds the script, and then
// asserted only `ok === true`. Here the fixture IS the requested root, and the
// scan must speak about that fixture — never about the checkout running it.

const REGISTER = (mod: any, config: any = {}) => {
  const regs: any[] = []
  const ctx: any = { tools: { register: (d: any) => regs.push(d) }, effect: (fn: () => void) => fn() }
  mod.apply(ctx, config)
  return regs[0]
}

const MINIMAL_SCRIPT = `#!/usr/bin/env node
console.log('SCAN-ROOT=' + process.cwd())
console.log('argv=' + process.argv.slice(2).join(','))
process.exit(0)
`

describe('maestro_full_scan tool', () => {
  it('registers tool', async () => {
    const mod = await import('../src/host/full-scan-tool.js')
    expect(REGISTER(mod).name).toBe('maestro_full_scan')
  })

  it('scans the requested root, not the process cwd', async () => {
    // A workspace fixture that is NOT this repo: it owns the script, the checkout does not.
    const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'))
    await mkdir(join(root, 'scripts'), { recursive: true })
    await writeFile(join(root, 'scripts/enforce-rules.mjs'), MINIMAL_SCRIPT)

    const mod = await import('../src/host/full-scan-tool.js')
    const tool = REGISTER(mod)
    const res: any = await tool.execute({ rootPath: root }, { agent: { session: { header: { cwd: root } } } })

    expect(res.ok).toBe(true)
    expect(res.report).toContain('enforce-rules')
    // The script reports its own cwd; that must be the fixture we asked for.
    expect(res.report).toContain(`SCAN-ROOT=${root}`)
    expect(res.report).not.toContain(join(process.cwd(), ''))
  })

  it('reports a skip instead of scanning elsewhere when the root has no script', async () => {
    // No scripts/enforce-rules.mjs anywhere under this root, and no ancestor of it has one.
    const bare = await mkdtemp(join(tmpdir(), 'scan-bare-'))

    const mod = await import('../src/host/full-scan-tool.js')
    const tool = REGISTER(mod)
    const res: any = await tool.execute({ rootPath: bare }, { agent: { session: { header: { cwd: bare } } } })

    // Skipping is fine and must stay `ok`; what is NOT fine is reporting another
    // tree's findings as if they belonged to the requested root.
    expect(res.ok).toBe(true)
    expect(res.report).toContain('skipping')
    expect(res.report).not.toContain('blacklist')
  })

  it('honours the configured rootPath over the session cwd', async () => {
    const root = await mkdtemp(join(tmpdir(), 'scan-cfg-'))
    await mkdir(join(root, 'scripts'), { recursive: true })
    await writeFile(join(root, 'scripts/enforce-rules.mjs'), MINIMAL_SCRIPT)
    const elsewhere = await mkdtemp(join(tmpdir(), 'scan-elsewhere-'))

    const mod = await import('../src/host/full-scan-tool.js')
    const tool = REGISTER(mod, { rootPath: root })
    const res: any = await tool.execute({}, { agent: { session: { header: { cwd: elsewhere } } } })

    expect(res.report).toContain(`SCAN-ROOT=${root}`)
  })
})
