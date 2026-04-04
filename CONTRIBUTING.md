# Contributing

Thanks for your interest in contributing to `depaudit-license`.

## Before you start

- Use a GitHub issue or pull request discussion for large changes, behavior changes, output contract changes, input model changes, new external sources, or release-process changes.
- Small editorial fixes can be proposed directly in a pull request.
- Keep changes focused and small when practical.
- Add or update tests when behavior changes.
- Update documentation in the same change when CLI behavior, output contracts, or support scope changes.
- If a change affects release validation expectations, update [RELEASE.md](D:/Source/Self/license/RELEASE.md).
- If a change affects catalog structure or localized license descriptions, update [configs/README.md](D:/Source/Self/license/configs/README.md).
- Public OSS releases start at `1.0.0`; changes that affect documented CLI behavior or output contracts must be reviewed as public contract changes.
- If a dependency is added, removed, or version-updated in `go.mod`, update [THIRD-PARTY-NOTICES.md](D:/Source/Self/license/THIRD-PARTY-NOTICES.md) in the same change.

## Development workflow

1. Create a topic branch from `main`.
2. Use an issue or pull request discussion when the work changes product behavior or repository policy.
3. Implement the change with matching tests or documentation updates.
4. Run validation from the repository root:

```powershell
go test ./...
```

5. If the change affects CLI output contracts, run or update the relevant integration tests in `main_integration_test.go`.
6. Submit a pull request with:
   - what changed
   - why it changed
   - validation results

## Project expectations

- Preserve the normalized inventory model as the boundary between input loading, enrichment, reporting, and vulnerability assessment.
- Prefer explicit, testable changes over hidden behavior drift.
- For `1.x` work, architecture consistency still matters, but changes to documented public behavior must be treated as compatibility-sensitive.
- Avoid adding comments unless they clarify orchestration or non-obvious invariants.

## Additional docs

- [README.md](D:/Source/Self/license/README.md)
- [docs/ARCHITECTURE.md](/D:/Source/Self/license/docs/ARCHITECTURE.md)
- [CHANGELOG.md](/D:/Source/Self/license/CHANGELOG.md)
- [RELEASE.md](D:/Source/Self/license/RELEASE.md)
- [SECURITY.md](D:/Source/Self/license/SECURITY.md)
- [.github/SUPPORT.md](D:/Source/Self/license/.github/SUPPORT.md)
- [CODE_OF_CONDUCT.md](D:/Source/Self/license/CODE_OF_CONDUCT.md)
