# Config Files

- `licenses.json`: `depaudit-license` が読み込むライセンス定義です。
- `licenses.schema.json`: `licenses.json` の正式な構造定義です。設定変更時のテストとレビューはこの schema を基準にします。
- `license-texts.ja.json`: 日本語の説明文 bundle です。`description` / `obligations` / `permissions` / `limitations` を持ちます。
- `license-texts.schema.json`: 説明文 bundle の正式な構造定義です。
- `exclude-policy.schema.json`: `-exclude-policy` で読み込む exclude policy JSON の schema です。
- `exclude-policy.sample.json`: shallow exclude / subgraph exclude を同じ policy file で表現するサンプルです。
- `license-overrides.schema.json`: `-license-override-file` で読み込む package-level license override JSON の schema です。
- `license-overrides.sample.json`: `Unknown` など未解決 license を package 単位で手動解決するサンプルです。
- `depaudit-license -locale ja` のように locale を指定すると、既定では `configs/license-texts.<locale>.json` を解決します。
- `-license-text-bundle` を指定した場合は locale 規約よりそのパスを優先します。

`licenses.json` の `text_matchers` / `text_match_threshold` / `required_phrases` は、同梱ライセンスファイル本文から license key を推定するための任意フィールドです。`required_phrases` は全件一致、`text_matchers` は `text_match_threshold` 件以上の一致で採用されます。`text_match_threshold` を省略した場合、または `0` 以下を指定した場合は、既定で `text_matchers` の件数が使われるため、実質的に `text_matchers` は全件一致が必要です。

## Catalog Sources

- `depaudit-license` の `-license-catalog` にはローカルファイルパスだけでなく `https://` URL も指定できます。
- 複数指定した場合は先に読み込んだ catalog を後続の source が上書きします。
- 例:
  - `-license-catalog configs/licenses.json`
  - `-license-catalog https://example.test/licenses.json -license-catalog configs/override.json`

## Package License Overrides

- `-license-catalog` は raw license 文字列や URL を catalog 定義に正規化するための設定です。同じ raw license に一致する package 全体へ効きます。
- `-license-override-file` は特定 package にだけ license key を紐づけるための設定です。`ecosystems` / `names` / `versions` / `purls` などの selector で対象を絞ります。
- 既定の `mode` は `ifMissing` で、`licenseKey` が空または fallback (`Unknown`) の場合だけ適用します。
- 既存の非 fallback license を上書きする場合は `mode: "force"` を明示します。
