# Release Validation

このリポジトリでは、release readiness を次の 2 軸で判断します。

- テストが主要な利用経路をカバーしていること
- 最終出力物の契約が integration test で固定されていること

## Release baseline

- OSS 公開バージョンは `1.0.0`
- 以後の公開リリースは semantic versioning を前提に扱う
- `1.x` では、明示的に breaking とした変更を除いて CLI / JSON / HTML の公開契約を維持対象とする

## Required checks

release 前に少なくとも次を実行します。

```powershell
go test ./...
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

release workflow は GitHub Actions の [`.github/workflows/release.yml`](.github/workflows/release.yml) に従い、次の条件を満たした tag push を前提とします。

- tag は `vX.Y.Z` 形式の exact semantic version であること
- tag は lightweight tag ではなく annotated tag であること
- tag が指す commit は `main` に含まれていること

例:

```powershell
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0
```

## Representative smoke matrix

`main_integration_test.go` の `TestRunReleaseSmokeMatrix` を release gate として扱います。確認対象は次の代表ケースです。

- `repository-scan` から report / legal notice を生成できること
- `cyclonedx-json` から report / legal notice を生成できること
- `spdx-json` から report / legal notice を生成できること
- `repository-scan + cyclonedx-json` の multi-source から report / legal notice / vulnerability JSON を生成できること

## Output-facing contract tests

smoke matrix に加えて、次の最終出力契約は個別の integration test で固定されています。

- report HTML
- legal notice HTML
- vulnerability HTML
- report JSON provenance
- vulnerability JSON provenance
- CycloneDX / SPDX / multi-source input の最終 JSON 出力
- remote catalog override / pinned remote catalog の反映
- embedded license text の raw text copy と `copiedFilePath` 出力
- package-level license override の適用、validation 失敗、custom catalog key、provenance / diagnostics 出力

## 1.2.0 release checklist

`v1.2.0` では、少なくとも次の文書状態を確認してから tag を作成します。

- [CHANGELOG.md](CHANGELOG.md) に `1.2.0` の section があり、embedded license text と package-level license override が記載されている
- [README.md](README.md) と [README.ja.md](README.ja.md) に `-license-override-file` の使い分け、`ifMissing` / `force` の挙動、実行例が記載されている
- [configs/README.md](configs/README.md) に license override schema / sample と selector の用途が記載されている
- release archive に含まれる `configs/` から `license-overrides.schema.json` と `license-overrides.sample.json` を参照できる

## Release decision

現時点で `release ready` と判断するには、次を満たしている必要があります。

- `go test ./...` が全通している
- representative smoke matrix が全通している
- coverage が主要 package で `90%` を大きく下回っていない
- open issue が release blocker ではなく、残件が低価値の coverage 追い込みか将来改善である
- release notes と主要文書が対象バージョンの公開前提と矛盾していない

## Notes

- `1.0.0` 以後は互換性より設計を優先する変更でも、公開契約への影響を文書化してから release 判断を行います。
- コメントは必要箇所だけに限定し、仕様や運用判断はコード外の文書に寄せます。
