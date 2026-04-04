# depaudit-license

<p align="center">
  <img src="docs/assets/readme-icon.png" alt="depaudit-license icon" width="320">
</p>

日本語版 README です。English README is available at [README.md](/D:/Source/Self/license/README.md).

`depaudit-license` は、リポジトリの直接スキャンまたは既存 SBOM を入力として、OSS ライセンス棚卸しと配布用 notice 出力を生成する Go 製 CLI です。

このツールでできること:

- リポジトリを直接スキャンする
- `CycloneDX JSON` / `SPDX JSON` を取り込む
- 複数入力を 1 つの正規化 inventory にマージする
- パッケージエコシステムからメタデータを補完する
- report HTML / legal notice HTML / JSON を出力する
- 同じ正規化 inventory から vulnerability checklist 出力を任意で生成する

## 対応入力

- `repository-scan=<path>`
- `cyclonedx-json=<path>`
- `spdx-json=<path>`

`-input` は複数回指定でき、複数 source を 1 つの正規化 inventory にまとめられます。

## 対応エコシステム

repository scan が直接認識する package ecosystem は現在次のとおりです。

- `Node.js / npm`
- `.NET / NuGet`

SBOM input からは、次の normalized ecosystem も取り込めます。

- `generic`

意味合いとしては次のとおりです。

- repository scan は Node.js / npm と .NET / NuGet の manifest / metadata を中心に設計されています
- CycloneDX / SPDX input では他 ecosystem の package も取り込めますが、generic な SBOM data としてしか表現できない場合は metadata enrichment や ecosystem 固有挙動が限定されます
- report / legal notice 出力は正規化 inventory 全体に対して動作しますが、enrichment や vulnerability matching の精度は ecosystem と利用できる identifier に依存します

## 生成物

既定では次を出力します。

- `dist/depaudit-license.html`
- `dist/depaudit-license.json`
- `dist/depaudit-license-legal-notice.html`

脆弱性出力は必要に応じて追加できます。

- `-output-vuln-html`
- `-output-vuln-json`

## クイックスタート

GitHub Releases から利用する platform 向けの release archive を取得し、ローカルに展開してください。

release archive には次が含まれます。

- platform ごとのバイナリ
- 既定の HTML/CSS asset を含む `templates/`
- 既定の license catalog と locale bundle を含む `configs/`
- 配布パッケージ自体を走査した Syft 生成の SPDX JSON SBOM
- `README.md`, `README.ja.md`, `LICENSE`, `THIRD-PARTY-NOTICES.md`

展開したフォルダでバイナリを実行します。

Windows:

```powershell
.\depaudit-license-windows-amd64.exe
```

Linux:

```bash
./depaudit-license-linux-amd64
```

macOS:

```bash
./depaudit-license-darwin-arm64
```

例: 手元のリポジトリを直接スキャンする:

```powershell
.\depaudit-license-windows-amd64.exe `
  -input repository-scan=.\my-repository `
  -output-html dist\report.html `
  -output-json dist\report.json `
  -output-legal-html dist\legal-notice.html
```

例: CycloneDX SBOM から生成する:

```powershell
.\depaudit-license-windows-amd64.exe `
  -input cyclonedx-json=.\sbom\app.cyclonedx.json `
  -output-html dist\cyclonedx-report.html `
  -output-json dist\cyclonedx-report.json `
  -output-legal-html dist\cyclonedx-legal-notice.html
```

例: 脆弱性出力も合わせて生成する:

```powershell
.\depaudit-license-windows-amd64.exe `
  -input repository-scan=.\my-repository `
  -output-html dist\report.html `
  -output-json dist\report.json `
  -output-legal-html dist\legal-notice.html `
  -output-vuln-html dist\vulnerability.html `
  -output-vuln-json dist\vulnerability.json `
  -vuln-mode full
```

## カスタマイズ

ライセンス定義と説明文:

- `-license-catalog` はローカルファイルパスと `https://` URL を受け付けます
- `-license-catalog` は後ろに指定した source が前の source を上書きします
- `-locale` は `configs/license-texts.<locale>.json` を選びます
- `-license-text-bundle` を指定すると locale ベース解決よりそのパスを優先します

見た目:

- `-template`, `-theme-css`
- `-legal-template`, `-legal-theme-css`
- `-vuln-template`, `-vuln-theme-css`

report / legal notice の custom template で使える helper:

- `slug`
- `ecosystemLabel`
- `dependencyTypeLabel`
- `prettyJSON`

`slug`, `ecosystemLabel`, `dependencyTypeLabel` は表示向け helper です。

`prettyJSON` は debug / convenience 用 helper です。構造化データをインデント付き JSON 文字列として出せるため、nested data の確認や `<pre>` での生データ表示に使えます。report / legal notice renderer は `html/template` を使うため、出力は HTML escape されます。

remote catalog の挙動:

- `-remote-catalog-mode fail-fast`
- `-remote-catalog-mode stale-fallback`
- `-remote-catalog-cache-dir <path>`

## バージョニングと互換性

公開 OSS リリースは `1.0.0` から開始します。

- `1.x` では、明示的に breaking change として告知しない限り、文書化された CLI / JSON / HTML 契約を維持対象とします
- breaking change は release note と関連文書で明示します
- 実験的または暫定的な挙動は、公開前に該当文書でその旨を示します

## 利用者向けドキュメント

- [README.md](README.md) English README
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [CHANGELOG.md](CHANGELOG.md)
- [RELEASE.md](RELEASE.md)
- [configs/README.md](configs/README.md)
- [SECURITY.ja.md](SECURITY.ja.md)
- [.github/SUPPORT.ja.md](.github/SUPPORT.ja.md)
- [LICENSE](LICENSE)
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)

## 免責

- このツールは、ライセンス inventory、notice 生成、補助的な vulnerability reporting のための独立した OSS です
- OSV、GitHub Advisory Database、NVD、SPDX、CycloneDX project とは提携していません
