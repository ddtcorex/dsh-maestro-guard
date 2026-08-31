import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { randomUUID, createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

function resolveHome(dshHome?: string) { return dshHome ?? process.env.DSH_HOME ?? join(homedir(), '.dsh') }
export function pendingPath(dshHome?: string) { return join(resolveHome(dshHome), 'dsh-maestro-guard', 'pending.json') }

export const MAX_PENDING = 20

export interface PendingRequest {
  id: string
  scope: 'git-protection' | 'publish'
  tool: string
  command: string
  reason: string
  sessionId?: string
  cwd?: string
  requestedAt: string
  status: 'pending' | 'approved' | 'dismissed'
}

let _queue: Promise<unknown> = Promise.resolve()
function enqueue<T>(fn: () => Promise<T>): Promise<T> {
  const p = _queue.then(fn, fn) as Promise<T>
  _queue = p.catch(() => {})
  return p
}

function hashKey(scope: string, command: string): string {
  return createHash('sha1').update(scope + '\u0000' + command).digest('hex').slice(0, 8)
}

export class PendingStore {
  constructor(private dshHome?: string) {}
  private async load(): Promise<{ requests: PendingRequest[] }> {
    try { return JSON.parse(await readFile(pendingPath(this.dshHome), 'utf-8')) } catch { return { requests: [] } }
  }
  private async save(doc: { requests: PendingRequest[] }): Promise<void> {
    const p = pendingPath(this.dshHome)
    await mkdir(dirname(p), { recursive: true, mode: 0o700 })
    await writeFile(p, JSON.stringify(doc, null, 2), { encoding: 'utf-8', mode: 0o600 })
    await chmod(p, 0o600)
  }
  async record(opts: { scope: 'git-protection' | 'publish'; tool: string; command: string; reason: string; sessionId?: string; cwd?: string }): Promise<PendingRequest> {
    return enqueue(async () => {
      const doc = await this.load()
      const key = hashKey(opts.scope, opts.command)
      const dup = doc.requests.find((r) => r.status === 'pending' && hashKey(r.scope, r.command) === key)
      if (dup) return dup
      const req: PendingRequest = {
        id: `g-${randomUUID().slice(0, 8)}`,
        scope: opts.scope,
        tool: opts.tool,
        command: opts.command,
        reason: opts.reason,
        sessionId: opts.sessionId,
        cwd: opts.cwd,
        requestedAt: new Date().toISOString(),
        status: 'pending',
      }
      doc.requests.push(req)
      const pending = doc.requests.filter((r) => r.status === 'pending')
      const resolved = doc.requests.filter((r) => r.status !== 'pending')
      const drop = Math.max(0, resolved.length - (MAX_PENDING - pending.length))
      await this.save({ requests: [...pending, ...resolved.slice(drop)] })
      return req
    })
  }
  async list(): Promise<PendingRequest[]> {
    const doc = await this.load()
    return [...doc.requests].sort((a, b) => (a.requestedAt < b.requestedAt ? 1 : -1))
  }
  async approve(id: string): Promise<PendingRequest | undefined> {
    return enqueue(async () => {
      const doc = await this.load()
      const req = doc.requests.find((r) => r.id === id)
      if (!req || req.status !== 'pending') return undefined
      req.status = 'approved'
      await this.save(doc)
      return req
    })
  }
  async dismiss(id: string): Promise<PendingRequest | undefined> {
    return enqueue(async () => {
      const doc = await this.load()
      const req = doc.requests.find((r) => r.id === id)
      if (!req || req.status !== 'pending') return undefined
      req.status = 'dismissed'
      await this.save(doc)
      return req
    })
  }
}