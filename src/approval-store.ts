import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

function resolveHome(dshHome?: string) { return dshHome ?? process.env.DSH_HOME ?? join(homedir(), '.dsh') }
export function approvalsPath(dshHome?: string) { return join(resolveHome(dshHome), 'dsh-maestro-guard', 'approvals.json') }
function legacyPath(dshHome?: string) { return join(resolveHome(dshHome), 'dsh-maestro-harness', 'approvals.json') }

export class ApprovalStore {
  constructor(private dshHome?: string) {}
  private async maybeMigrate() {
    try { await readFile(approvalsPath(this.dshHome), 'utf-8'); return } catch {}
    try {
      const data = await readFile(legacyPath(this.dshHome), 'utf-8')
      await mkdir(dirname(approvalsPath(this.dshHome)), { recursive: true, mode: 0o700 })
      await writeFile(approvalsPath(this.dshHome), data, { encoding: 'utf-8', mode: 0o600 })
      await chmod(approvalsPath(this.dshHome), 0o600)
    } catch {}
  }
  async load(): Promise<Record<string, boolean>> {
    await this.maybeMigrate()
    try { return JSON.parse(await readFile(approvalsPath(this.dshHome), 'utf-8')) } catch { return {} }
  }
  async isApproved(tool: string): Promise<boolean> { const m = await this.load(); return !!m[tool] }
  async approve(tool: string): Promise<void> {
    const m = await this.load()
    m[tool] = true
    const p = approvalsPath(this.dshHome)
    await mkdir(dirname(p), { recursive: true, mode: 0o700 })
    await writeFile(p, JSON.stringify(m, null, 2), { encoding: 'utf-8', mode: 0o600 })
    await chmod(p, 0o600)
  }
  async revoke(tool: string): Promise<void> {
    const m = await this.load(); delete m[tool]
    const p = approvalsPath(this.dshHome)
    await writeFile(p, JSON.stringify(m, null, 2), { encoding: 'utf-8', mode: 0o600 })
    await chmod(p, 0o600)
  }
}
