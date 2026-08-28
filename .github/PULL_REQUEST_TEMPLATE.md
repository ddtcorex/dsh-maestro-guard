## Summary

Describe the change in 2–3 bullets.

## Why

Explain the problem this PR solves and why this approach was chosen.

## Changes

- [ ] Code updated (`src/host/` — approval-store / secret-redactor / permission-policy / Cordis row)
- [ ] Tests added or updated (`tests/` — vitest, 27 tests)
- [ ] Documentation updated (`README.md` / `CONTRIBUTING.md` / `CHANGELOG.md` if needed)
- [ ] `lib/index.js` rebuilt and verified flat (`test -f lib/index.js`)
- [ ] Version bumped in `package.json` and `CHANGELOG.md` (if release-relevant)

## Validation

Paste exact commands and outcomes (do not claim verified without evidence):

```bash
pnpm verify
pnpm test
pnpm build
test -f lib/index.js && echo "flat OK" || echo "FAIL"
```

## Linked Issues

Fixes #

## Checklist

- [ ] Branch is `feat/...`, `fix/...`, or `docs/...` off `master` (no direct commits to `master`)
- [ ] Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`) in imperative mood
- [ ] Followed the Superpowers 3-phase workflow (brainstorming → writing-plans → executing-plans with TDD) where applicable
- [ ] `pnpm verify` / `pnpm test` / `pnpm build` are green
