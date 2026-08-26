# @ddtcorex/dsh-maestro-guard

Host-only safety gate for the DeepSeek Harness: gates tool execution before dispatch via a
waterfall pre-execute hook — persistent approval grants, secret redaction before
logging/persistence, and a pure allow/deny permission policy.

Part of the Maestro Harness suite (`dsh-maestro-*`). Cordis patch row id: `dsh-maestro-guard`.

> Opt-in and intentionally **not** part of the meta-bundle one-liner until published:
> add it explicitly with `dsh plugin add @ddtcorex/dsh-maestro-guard`.

## What it provides

- **Waterfall pre-execute integration** — one Cordis row (`dsh-maestro-guard`) wiring the
  guard handler into the tool-execution waterfall.
- **ApprovalStore** — persistent approval grants with legacy migration, revoke, and
  read-modify-write safety under a mutex.
- **SecretRedactor** — redacts known secret families (`ghp_`, `xox`, private keys, …) before
  calls are logged or persisted.
- **PermissionPolicy** — pure, unit-testable allow/deny checks for tool calls.

Host-only: no client bundle; DSH types come from local structural declarations
(`src/augment.d.ts`).

## Development

```sh
pnpm install
pnpm verify   # tsc --noEmit
pnpm test     # vitest run
pnpm build    # tsc -> lib/
```

## License

MIT
