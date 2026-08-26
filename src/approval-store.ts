import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

function resolveHome(dshHome?: string) { return dshHome ?? process.env.DSH_HOME ?? join(homedir(), '.dsh') }
export function approvalsPath(dshHome?: string) { return join(resolveHome(dshHome), 'dsh-maestro-guard', 'approvals.json') }
export const pathFor = approvalsPath

let _queue: Promise<unknown> = Promise.resolve()
function enqueue<T>(fn: () => Promise<T>): Promise<T> {
  const p = _queue.then(fn, fn) as Promise<T>
  _queue = p.catch(() => {})
  return p
}

export class ApprovalStore {
  constructor(private dshHome?: string) {}
  async load(): Promise<Record<string, boolean>> {
    try { return JSON.parse(await readFile(approvalsPath(this.dshHome), 'utf-8')) } catch { return {} }
  }
  async isApproved(tool: string): Promise<boolean> { const m = await this.load(); return !!m[tool] }
  async approve(tool: string): Promise<void> {
    return enqueue(async () => {
      const m = await this.load()
      m[tool] = true
      const p = approvalsPath(this.dshHome)
      await mkdir(dirname(p), { recursive: true, mode: 0o700 })
      await writeFile(p, JSON.stringify(m, null, 2), { encoding: 'utf-8', mode: 0o600 })
      await chmod(p, 0o600)
    })
  }
  async revoke(tool: string): Promise<void> {
    return enqueue(async () => {
      const m = await this.load(); delete m[tool]
      const p = approvalsPath(this.dshHome)
      await mkdir(dirname(p), { recursive: true, mode: 0o700 })
      await writeFile(p, JSON.stringify(m, null, 2), { encoding: 'utf-8', mode: 0o600 })
      await chmod(p, 0o600)
    })
  }
}
