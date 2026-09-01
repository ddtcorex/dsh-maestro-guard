import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { randomUUID, createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

function resolveHome(dshHome?: string) { return dshHome ?? process.env.DSH_HOME ?? join(homedir(), '.dsh') }
export function pendingPath(dshHome?: string) { return join(resolveHome(dshHome), 'dsh-maestro-guard', 'pending.json') }

export const MAX_PENDING = 20

/**
 * How long an approval (and a pending ticket) stays actionable. Approved grants
 * must not linger indefinitely as standing one-shot passes for any later session,
 * and superseded pending tickets should not clutter the store forever.
 */
export const APPROVAL_TTL_MS = 30 * 60 * 1000

export interface PendingRequest {
  id: string
  scope: 'git-protection' | 'publish'
  tool: string
  hash: string
  command: string
  reason: string
  sessionId?: string
  cwd?: string
  requestedAt: string
  expiresAt?: string
  status: 'pending' | 'approved' | 'consumed' | 'expired'
}

let _queue: Promise<unknown> = Promise.resolve()
function enqueue<T>(fn: () => Promise<T>): Promise<T> {
  const p = _queue.then(fn, fn) as Promise<T>
  _queue = p.catch(() => {})
  return p
}

export function ticketHash(scope: string, command: string): string {
  return createHash('sha1').update(scope + '\u0000' + command).digest('hex').slice(0, 12)
}

function isExpired(req: PendingRequest, nowMs: number): boolean {
  // Legacy tickets recorded before the TTL existed carry no expiresAt; treat
  // them as expiring at requestedAt + APPROVAL_TTL_MS so pre-TTL pending/
  // approved tickets are pruned too instead of lingering forever.
  if (req.expiresAt) return nowMs > Date.parse(req.expiresAt)
  try { return nowMs > Date.parse(req.requestedAt) + APPROVAL_TTL_MS } catch { return false }
}

export class PendingStore {
  constructor(private dshHome?: string, private now: () => number = Date.now) {}
  private async load(): Promise<{ requests: PendingRequest[] }> {
    try { return JSON.parse(await readFile(pendingPath(this.dshHome), 'utf-8')) } catch { return { requests: [] } }
  }
  private async save(doc: { requests: PendingRequest[] }): Promise<void> {
    const p = pendingPath(this.dshHome)
    await mkdir(dirname(p), { recursive: true, mode: 0o700 })
    await writeFile(p, JSON.stringify(doc, null, 2), { encoding: 'utf-8', mode: 0o600 })
    await chmod(p, 0o600)
  }
  /** Mark expired pending/approved tickets as 'expired' (mutates, persists). */
  private async prune(doc: { requests: PendingRequest[] }): Promise<void> {
    const t = this.now()
    let changed = false
    for (const r of doc.requests) {
      if ((r.status === 'pending' || r.status === 'approved') && isExpired(r, t)) {
        r.status = 'expired'
        changed = true
      }
    }
    if (changed) await this.save(doc)
  }
  async record(opts: { scope: 'git-protection' | 'publish'; tool: string; command: string; reason: string; sessionId?: string; cwd?: string }): Promise<PendingRequest> {
    return enqueue(async () => {
      const doc = await this.load()
      await this.prune(doc)
      const hash = ticketHash(opts.scope, opts.command)
      const existing = doc.requests.find(
        (r) => r.scope === opts.scope && r.hash === hash && (r.status === 'pending' || r.status === 'approved'),
      )
      if (existing) return existing
      const req: PendingRequest = {
        id: `g-${randomUUID().slice(0, 8)}`,
        scope: opts.scope,
        tool: opts.tool,
        hash,
        command: opts.command,
        reason: opts.reason,
        sessionId: opts.sessionId,
        cwd: opts.cwd,
        requestedAt: new Date(this.now()).toISOString(),
        expiresAt: new Date(this.now() + APPROVAL_TTL_MS).toISOString(),
        status: 'pending',
      }
      doc.requests.push(req)
      const pending = doc.requests.filter((r) => r.status === 'pending' || r.status === 'approved')
      const resolved = doc.requests.filter((r) => r.status === 'consumed' || r.status === 'expired')
      const drop = Math.max(0, resolved.length - (MAX_PENDING - pending.length))
      await this.save({ requests: [...pending, ...resolved.slice(drop)] })
      return req
    })
  }
  async list(): Promise<PendingRequest[]> {
    return enqueue(async () => {
      const doc = await this.load()
      await this.prune(doc)
      return [...doc.requests].sort((a, b) => (a.requestedAt < b.requestedAt ? 1 : -1))
    })
  }
  async approve(id: string): Promise<PendingRequest | undefined> {
    return enqueue(async () => {
      const doc = await this.load()
      await this.prune(doc)
      const req = doc.requests.find((r) => r.id === id)
      if (!req || req.status !== 'pending') return undefined
      req.status = 'approved'
      req.expiresAt = new Date(this.now() + APPROVAL_TTL_MS).toISOString()
      await this.save(doc)
      return req
    })
  }
  async consume(id: string): Promise<boolean> {
    return enqueue(async () => {
      const doc = await this.load()
      const req = doc.requests.find((r) => r.id === id)
      if (!req || req.status !== 'approved') return false
      req.status = 'consumed'
      await this.save(doc)
      return true
    })
  }
  async findApprovedByHash(scope: string, hash: string, sessionId?: string): Promise<PendingRequest | undefined> {
    return enqueue(async () => {
      const doc = await this.load()
      await this.prune(doc)
      const t = this.now()
      return doc.requests.find(
        (r) =>
          r.scope === scope &&
          r.hash === hash &&
          r.status === 'approved' &&
          !isExpired(r, t) &&
          (r.sessionId ? r.sessionId === sessionId : true), // legacy tickets without a sessionId stay usable
      )
    })
  }
}