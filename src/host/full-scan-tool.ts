import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
export const name = 'maestro-full-scan-tool'
export const inject = ['tools'] as const
function workspaceRootFor(c:string|undefined, e:unknown): string {
  if (c) return c
  const cwd=(e as any)?.agent?.session?.header?.cwd
  return typeof cwd==='string'&&cwd?cwd:process.cwd()
}
function resolveScript(root:string): string {
  // ONLY the requested root and its ancestors. The old version also walked up
  // from process.cwd() as a last resort, so a call aimed at a directory without
  // the script silently scanned the guard's OWN checkout and returned that
  // repo's blacklist hits as if they were the caller's. Scanning a tree nobody
  // asked about is worse than reporting nothing: the report looks authoritative.
  let cur = resolve(root)
  for (let i=0;i<8;i++) {
    const cand = join(cur, 'scripts/enforce-rules.mjs')
    if (existsSync(cand)) return cand
    const parent = resolve(cur, '..')
    if (parent===cur) break
    cur = parent
  }
  return join(resolve(root), 'scripts/enforce-rules.mjs')
}
export function apply(ctx: Context, config:{rootPath?:string}={}) {
  ctx.effect(()=> ctx.tools.register(defineTool({
    name:'maestro_full_scan',
    description:'Run full enforce-rules scan (blacklist + protection + publish gate) and return report. No approval needed; read-only.',
    parameters:{ rootPath:{type:'string', description:'workspace root override'} },
    output:{ schema:{type:'object', additionalProperties:true, properties:{ok:{type:'boolean', required:true}, report:{type:'string', required:true}, code:{type:'number', required:true}}}, render:(_a:any,v:any)=>[{type:'text', text: v.report.slice(0,4000)}] },
    async execute(args:any, exec:unknown) {
      const root = workspaceRootFor((args as any)?.rootPath ?? config.rootPath, exec)
      const script = resolveScript(root)
      if (!existsSync(script)) {
        return {ok: true, report: `enforce-rules: no script found at ${script} (standalone repo, skipping)`, code: 0}
      }
      const run = (extra:string[])=>{
        // cwd = the scanned root: the script resolves its own targets relative to
        // it, so inheriting the host's cwd made the report describe the wrong tree.
        const r=spawnSync('node', [script, ...extra], {encoding:'utf-8', timeout: 30000, cwd: resolve(root)})
        return {code: r.status??0, out: (r.stdout??'')+(r.stderr??'')}
      }
      let combined=''
      let ok=true
      const a=run([])
      combined+=`$ node scripts/enforce-rules.mjs\n${a.out}\n`
      if (a.code!==0) ok=false
      const b=run(['--check-protection'])
      combined+=`$ node scripts/enforce-rules.mjs --check-protection\n${b.out}\n`
      if (b.code!==0) combined+=`[warn] --check-protection non-zero (may need gh auth)\n`
      const c=run(['--check-publish'])
      combined+=`$ node scripts/enforce-rules.mjs --check-publish\n${c.out}\n`
      // do not fail on --check-publish when no tag
      return {ok, report: combined.slice(0,12000), code: ok?0:1}
    }
  })))
}
