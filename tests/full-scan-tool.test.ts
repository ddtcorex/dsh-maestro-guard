import { describe, it, expect } from 'vitest'
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
describe('maestro_full_scan tool', () => {
  it('registers tool', async () => {
    const mod = await import('../src/host/full-scan-tool.js')
    const regs:any[] = []
    const ctx:any = { tools:{register:(d:any)=>regs.push(d)}, effect:(fn:()=>void)=>fn() }
    mod.apply(ctx, {})
    expect(regs[0].name).toBe('maestro_full_scan')
  })
  it('execute runs enforce-rules and returns ok', async () => {
    const mod = await import('../src/host/full-scan-tool.js')
    const regs:any[] = []
    const ctx:any = { tools:{register:(d:any)=>regs.push(d)}, effect:(fn:()=>void)=>fn() }
    mod.apply(ctx, {})
    const res:any = await regs[0].execute({}, {agent:{session:{header:{cwd:'/tmp'}}}})
    expect(res.ok).toBe(true)
    expect(res.report).toContain('enforce-rules')
  })
})
