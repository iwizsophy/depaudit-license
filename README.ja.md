# depaudit-license

<p align="center">
  <img src="docs/assets/readme-icon.png" alt="depaudit-license icon" width="320">
</p>

日本語版 README です。English README is available at [README.md](README.md).

`depaudit-license` は、リポジトリの直接スキャンまたは既存 SBOM を入力として、OSS ライセンス棚卸しと配布用 notice 出力を生成する Go 製 CLI です。

## 背景

OSS を利用したアプリケーション開発において、依存パッケージのライセンス情報を整理し、適切に提示することが求められます。

SBOM は有効な手段ですが、それだけでは利用者に提示する成果物としては十分でない場合があります。

一方で、アプリケーションの公開にあたっては、各 OSS ライセンスの要件に対応したライセンスページ（notice）の用意が必要となり、「理解可能な形で提示すること」が重要になります。

しかし、既存ツールはライセンス情報の抽出や SBOM の生成には対応しているものの、「配布可能な形に整形された成果物」を一貫して生成することには十分対応しておらず、最終的には手作業による加工が必要になるケースが多い状況でした。

また、ライセンスページは重要であるにもかかわらず、開発プロセスの中で後回しになりやすく、対応漏れが発生しやすいという問題もあります。

この課題を解決するために、「ライセンス対応を成果物生成まで含めて自動化する」ことを目的として `depaudit-license` を開発しました。

`depaudit-license` は、リポジトリスキャンや SBOM を入力として取り込み、正規化された inventory に統合した上で、配布可能なライセンスページ（legal notice）を生成します。

これにより、ライセンス対応を CI に組み込める形で実現し、作業の属人化を防ぎながら、確実かつ継続的な対応を可能にします。

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

- `Node.js / npm / pnpm / Yarn`
- `.NET / NuGet`

SBOM input からは、次の normalized ecosystem も取り込めます。

- `generic`

意味合いとしては次のとおりです。

- repository scan は Node.js の manifest / lockfile（`package.json`, `pnpm-lock.yaml`, `yarn.lock`）と .NET / NuGet の manifest / metadata を中心に設計されています
- NuGet enrichment は、registration metadata だけでは判定できない場合でも、local global-packages cache や remote package archive から同梱 file license を解決できます
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
- `-license-override-file` は `Unknown` など未解決の license を package 単位で手動解決する override JSON を読み込みます
- `-exclude-policy` は versioned な shallow/subgraph exclude policy JSON を読み込みます
- `-exclude-patterns` は引き続き利用でき、内部的には legacy shallow rule として扱われます

既定 catalog には、common な source-available / proprietary-adjacent license を review-only key として識別する定義も含まれます。これらに一致した package は `Unknown` からは抜けますが、`requires_manual_review: true` のままであり、事前承認済み OSS と同じ扱いにはしません。

package 単位の license override:

```json
{
  "version": "v1alpha1",
  "licenseOverrides": [
    {
      "id": "left-pad-1.3.0-mit",
      "reason": "Upstream metadata is missing and the package LICENSE file was manually reviewed.",
      "match": {
        "ecosystems": ["node"],
        "names": ["left-pad"],
        "versions": ["1.3.0"],
        "purls": ["pkg:npm/left-pad@1.3.0"]
      },
      "licenseKey": "MIT",
      "mode": "ifMissing",
      "evidence": {
        "url": "https://github.com/example/left-pad/blob/v1.3.0/LICENSE",
        "reviewedBy": "manual",
        "reviewedAt": "2026-04-10",
        "note": "LICENSE text matches MIT."
      }
    }
  ]
}
```

```powershell
.\depaudit-license-windows-amd64.exe `
  -input repository-scan=.\my-repository `
  -license-override-file .\configs\license-overrides.json `
  -output-html dist\report.html `
  -output-json dist\report.json `
  -output-legal-html dist\legal-notice.html
```

`-license-catalog` は raw license 文字列や URL の正規化に使い、同じ raw license に一致する package 全体へ効きます。特定 package だけを手動解決したい場合は `-license-override-file` を使います。既定の `mode` は `ifMissing` で、`licenseKey` が空または fallback (`Unknown`) の場合だけ適用します。既存の非 fallback license を上書きする場合は `mode: "force"` を明示します。

既定の review-only key の例として、`Microsoft-Software-License-Terms`, `BUSL-1.1`, `Elastic-2.0`, `SSPL-1.0`, `Commons-Clause`, `PolyForm-Noncommercial-1.0.0`, `FSL-1.1-MIT`, `Confluent-Community-License`, `Timescale-License`, `CockroachDB-Community-License` などがあります。

見た目:

- `-template`, `-theme-css`
- `-legal-template`, `-legal-theme-css`
- `-vuln-template`, `-vuln-theme-css`

package 内の同梱ライセンス本文を検出した場合、CLI は legal notice 出力の隣に `license-texts/...` として原文をコピーし、legal notice HTML / JSON から `copiedFilePath` で参照できるようにします。

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

外部 metadata / vulnerability API の挙動:

- `-http-cache-mode off|use|refresh|cache-only`
- `-http-cache-dir <path>`
- `-http-cache-ttl 24h`
- `-npm-registry-base-url <url>`
- `-nuget-registration-base-url <url>`
- `-osv-base-url <url>`
- `-github-advisory-base-url <url>`
- `-github-advisory-token <token>`
- `-nvd-base-url <url>`
- `-nvd-api-key <key>`

`-http-cache-*` は package metadata enrichment と vulnerability API に適用されます。remote license catalog URL については、引き続き `-remote-catalog-mode` / `-remote-catalog-cache-dir` を使い、stale-fallback は catalog 専用挙動として扱います。

選択された external metadata / vulnerability endpoint は、report JSON と vulnerability JSON の `provenance.externalSources` にも記録されます。remote license catalog URL は引き続き `provenance.catalogSources` に出力されます。

推奨パターン:

- 通常の CI / local run では `-http-cache-mode use -http-cache-ttl 24h`
- 表示調整などで繰り返し実行し、新しい外部リクエストを避けたい場合は `-http-cache-mode cache-only -http-cache-ttl 0`
- upstream API から強制的に再取得して cache を更新したい場合は `-http-cache-mode refresh`
- cache を完全に使わない場合は `-http-cache-mode off`

## 外部ネットワークアクセス

metadata enrichment、remote catalog、vulnerability reporting を使う場合、この CLI は外部 service へアクセスすることがあります。

- npm metadata enrichment:
  既定 `https://registry.npmjs.org`
  上書き `-npm-registry-base-url`
- NuGet metadata enrichment:
  既定 `https://api.nuget.org/v3/registration5-gz-semver2`
  package archive fallback は、選択された registration service が返す `packageContent` URL を使います
  上書き `-nuget-registration-base-url`
- remote license catalog:
  `-license-catalog` に渡した任意の `http://` / `https://` URL
  cache 制御は `-remote-catalog-mode`, `-remote-catalog-cache-dir`
- OSV vulnerability query:
  既定 `https://api.osv.dev`
  上書き `-osv-base-url`
- GitHub Advisory query:
  既定 `https://api.github.com`
  上書き `-github-advisory-base-url`
  認証: `-github-advisory-token` または `DEPAUDIT_LICENSE_GITHUB_ADVISORY_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`
- NVD vulnerability enrichment:
  既定 `https://services.nvd.nist.gov`
  上書き `-nvd-base-url`
  認証: `-nvd-api-key` または `DEPAUDIT_LICENSE_NVD_API_KEY`, `NVD_API_KEY`

rate limit に関する補足:

- GitHub は認証付きで REST API の上限が緩和されます
- NVD は API key ありで利用上限が引き上がります
- OSV は現時点で認証を要求しません
- npm registry と NuGet の public-read metadata は、個別 credential より cache や社内 mirror / proxy で吸収する前提が現実的です

endpoint override を使う場合、選択した mirror / proxy 自体が evidence path の一部になるため、運用上の依存先として管理してください。

## 除外ポリシー

`depaudit-license` には、役割の異なる 2 層の除外があります。

- `shallow exclude`: merge 後の最終出力調整です。`repository-scan` / CycloneDX / SPDX のどの入力由来 package に対しても適用されます。
- `subgraph exclude`: source-local な dependency graph 調整です。現時点では、`repository-scan` で収集した `.NET / NuGet` package のうち、`obj/project.assets.json` から graph を取得できる場合にだけ適用されます。

`shallow exclude` は、rendered な report / legal notice から package を外したいが、JSON 上の監査痕跡は残したい場合に使います。除外 package は visible package list、license group、production inventory、legal notice evidence からは外れますが、JSON 出力では `excludedPackages` に rule metadata 付きで残ります。

`subgraph exclude` は、matched root package と、その root からしか到達できない依存枝を merge 前に落としたい場合に使います。別の非除外 root から到達可能な shared dependency は残ります。graph が利用できない場合は `onUnsupported` で `warn` / `error` / `ignore` を選べます。

`-exclude-patterns` は、package 名断片ベースの簡易 shallow exclude として引き続き使えます。ただし内部的には合成 shallow rule に変換されるため、project path、dependency type、runtime asset、graph ベース条件は表現できません。

最小例:

```json
{
  "version": "v1alpha1",
  "shallowExcludes": [
    {
      "id": "omit-test-tooling",
      "reason": "hide development-only tooling from rendered outputs",
      "match": {
        "ecosystems": ["npm", "nuget"],
        "dependencyTypes": ["devDependency", "devTransitiveDependency"],
        "nameGlobs": ["eslint*", "xunit*"]
      }
    }
  ],
  "subgraphExcludes": [
    {
      "id": "omit-analyzer-subgraph",
      "reason": "drop analyzer-only dependency branches from repository scan",
      "onUnsupported": "warn",
      "match": {
        "ecosystems": ["nuget"],
        "projects": ["src/server/App.csproj"],
        "hasRuntimeAssets": false
      }
    }
  ]
}
```

実行例:

```powershell
.\depaudit-license-windows-amd64.exe `
  -input repository-scan=.\my-repository `
  -exclude-policy .\configs\exclude-policy.json `
  -output-html dist\report.html `
  -output-json dist\report.json `
  -output-legal-html dist\legal-notice.html
```

関連ファイル:

- [configs/exclude-policy.sample.json](configs/exclude-policy.sample.json)
- [configs/exclude-policy.schema.json](configs/exclude-policy.schema.json)
- [configs/license-overrides.sample.json](configs/license-overrides.sample.json)
- [configs/license-overrides.schema.json](configs/license-overrides.schema.json)

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
- 入力と flag に応じて、外部の package metadata、license catalog、vulnerability API にアクセスすることがあります
- ライセンス inventory、notice 生成、review workflow の容易化を目的とした支援ツールであり、ライセンス上の問題を最終的に解決または確定するものではありません
- 法的助言、法的見解、またはライセンス適合性の保証を提供するものではありません
- license classification、metadata enrichment、生成される notice 出力は、upstream package metadata や取得できる evidence に依存しており、不完全、古い、または誤っている可能性があります
- ライセンス義務の最終解釈、社内ポリシー判断、公開可否の承認は利用者側の責任で行い、必要に応じて法務または compliance review を実施してください
