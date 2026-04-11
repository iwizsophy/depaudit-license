# depaudit-license

<p align="center">
  <img src="docs/assets/readme-icon.png" alt="depaudit-license icon" width="320">
</p>

Japanese README is available at [README.ja.md](README.ja.md).

`depaudit-license` is a Go CLI that builds OSS license inventory and distribution notice outputs from either a repository scan or an existing SBOM.

## Background

When building applications that rely on OSS, teams need to organize dependency license information and present it appropriately.

SBOM is an effective mechanism, but in many cases it is not sufficient on its own as the final artifact presented to end users.

At the same time, publishing an application often requires preparing a license page (notice) that satisfies the obligations of each OSS license, and it is important to present that information in a form people can actually understand.

Existing tools can extract license information and generate SBOMs, but they do not consistently produce artifacts that are already formatted for distribution. In many cases, the final output still needs manual processing before it can be published.

There is also a process problem: even though the license page is important, it is easy for this work to be postponed until late in development, which increases the risk of omissions.

`depaudit-license` was built to address this by automating license compliance all the way through artifact generation.

It accepts repository scans and SBOMs as inputs, merges them into a normalized inventory, and generates a distributable license page (legal notice).

This makes it practical to incorporate license compliance into CI, reduce dependence on manual work, and handle it reliably and continuously over time.

It can:

- scan a repository directly
- import `CycloneDX JSON` or `SPDX JSON`
- merge multiple inputs into one inventory
- enrich package metadata from package ecosystems
- render report HTML, legal notice HTML, and JSON outputs
- optionally build vulnerability checklist outputs from the same normalized inventory

## Supported inputs

- `repository-scan=<path>`
- `cyclonedx-json=<path>`
- `spdx-json=<path>`

You can specify `-input` multiple times to merge sources into one normalized inventory.

## Supported ecosystems

Repository scan currently recognizes these package ecosystems directly:

- `Node.js / npm / pnpm / Yarn`
- `.NET / NuGet`

SBOM inputs can also carry packages that are normalized as:

- `generic`

In practice this means:

- repository scan is designed around Node.js manifests and lockfiles (`package.json`, `pnpm-lock.yaml`, `yarn.lock`) and .NET / NuGet manifests and metadata
- NuGet enrichment can resolve embedded file-based licenses from either the local global-packages cache or the remote package archive when registration metadata alone is insufficient
- CycloneDX / SPDX inputs can bring in packages from other ecosystems, but metadata enrichment and ecosystem-specific behavior may be more limited when the package is only represented as generic SBOM data
- report and legal notice outputs work across the normalized inventory, while enrichment and vulnerability matching quality can vary by ecosystem and available identifiers

## Generated outputs

By default the CLI writes:

- `dist/depaudit-license.html`
- `dist/depaudit-license.json`
- `dist/depaudit-license-legal-notice.html`

Optional vulnerability outputs:

- `-output-vuln-html`
- `-output-vuln-json`

## Quick start

Download the release archive for your platform from GitHub Releases, then extract it to a local folder.

The release archive includes:

- the platform-specific binary
- `templates/` for the default HTML/CSS assets
- `configs/` for the default license catalog and locale bundle
- a Syft-generated SPDX JSON SBOM for the packaged distribution
- `README.md`, `README.ja.md`, `LICENSE`, and `THIRD-PARTY-NOTICES.md`

Run the binary from the extracted folder.

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

Example: scan a local repository:

```powershell
.\depaudit-license-windows-amd64.exe `
  -input repository-scan=.\my-repository `
  -output-html dist\report.html `
  -output-json dist\report.json `
  -output-legal-html dist\legal-notice.html
```

Example: run from a CycloneDX SBOM:

```powershell
.\depaudit-license-windows-amd64.exe `
  -input cyclonedx-json=.\sbom\app.cyclonedx.json `
  -output-html dist\cyclonedx-report.html `
  -output-json dist\cyclonedx-report.json `
  -output-legal-html dist\cyclonedx-legal-notice.html
```

Example: run with vulnerability outputs:

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

Example: load runtime defaults from a config file and override only the repository path:

```powershell
.\depaudit-license-windows-amd64.exe `
  -config .\configs\depaudit-license.config.json `
  -input repository-scan=.\my-repository
```

## Customization

License definitions and descriptions:

- `-license-catalog` accepts local file paths and `https://` URLs
- later `-license-catalog` values override earlier sources
- `-locale` selects `configs/license-texts.<locale>.json`
- `-license-text-bundle` overrides locale-based bundle resolution
- `-license-override-file` loads a package-level override JSON for manually resolving licenses such as `Unknown`
- `-exclude-policy` loads versioned shallow/subgraph exclude policy JSON
- `-exclude-patterns` remains supported and is internally synthesized as a legacy shallow rule

The built-in catalog now also includes review-only definitions for common source-available and proprietary-adjacent licenses. When a package matches one of these definitions, it can resolve out of `Unknown`, but the matched license still carries `requires_manual_review: true` and should not be treated as pre-approved OSS without policy review.

Package-level license override:

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

Use `-license-catalog` when a raw license string or URL should normalize to a catalog definition across matching packages. Use `-license-override-file` when only a selected package should be manually resolved. The default `mode` is `ifMissing`, which applies only when `licenseKey` is blank or the fallback (`Unknown`). Use `mode: "force"` to intentionally replace an existing non-fallback license.

Examples of built-in review-only keys include `Microsoft-Software-License-Terms`, `BUSL-1.1`, `Elastic-2.0`, `SSPL-1.0`, `Commons-Clause`, `PolyForm-Noncommercial-1.0.0`, `FSL-1.1-MIT`, `Confluent-Community-License`, `Timescale-License`, and `CockroachDB-Community-License`.

Presentation:

- `-template`, `-theme-css`
- `-legal-template`, `-legal-theme-css`
- `-vuln-template`, `-vuln-theme-css`
- `-config` loads a versioned runtime config JSON for CLI defaults

Runtime config:

- `-config <path>` loads runtime defaults from JSON
- precedence is `CLI > env > runtime config > built-in default`
- local paths inside the runtime config are resolved relative to the config file itself
- `inputs` and `licenseCatalogs` are list settings, so any CLI `-input` or `-license-catalog` replaces the runtime-config list instead of appending to it
- runtime config schema and sample are available at:
  - [configs/runtime-config.schema.json](configs/runtime-config.schema.json)
  - [configs/runtime-config.sample.json](configs/runtime-config.sample.json)

When package-local embedded license text is discovered, the CLI copies that raw text next to the legal notice output under `license-texts/...` and links it from the legal notice HTML / JSON via `copiedFilePath`.

Report / legal notice custom templates can use these helpers:

- `slug`
- `ecosystemLabel`
- `dependencyTypeLabel`
- `prettyJSON`

`slug`, `ecosystemLabel`, and `dependencyTypeLabel` are presentation helpers for report / legal notice templates.

`prettyJSON` is a debug/convenience helper for custom templates. It renders structured values as indented JSON text so template authors can inspect nested data or expose raw view data in a `<pre>` block. Because the report and legal notice renderers use `html/template`, the output is HTML-escaped unless the template explicitly wraps it in a safe HTML construct such as `<pre>`.

Remote catalog behavior:

- `-remote-catalog-mode fail-fast`
- `-remote-catalog-mode stale-fallback`
- `-remote-catalog-cache-dir <path>`

External metadata / vulnerability API behavior:

- `-http-cache-mode off|use|refresh|cache-only`
- `-http-cache-dir <path>`
- `-http-cache-ttl 24h`
- `-max-package-artifact-bytes 268435456`
- `-max-package-metadata-bytes 1048576`
- `-max-embedded-license-bytes 4194304`
- `-max-package-archive-entries 10000`
- `-npm-registry-base-url <url>`
- `-nuget-registration-base-url <url>`
- `-osv-base-url <url>`
- `-github-advisory-base-url <url>`
- `-github-advisory-token <token>`
- `-nvd-base-url <url>`
- `-nvd-api-key <key>`

For secret-like settings, the effective precedence is:

- CLI flag
- environment variable
- runtime config
- built-in default

`-http-cache-*` applies to package metadata enrichment and vulnerability APIs. Remote license catalog URLs continue to use `-remote-catalog-mode` / `-remote-catalog-cache-dir` so stale-fallback behavior remains catalog-specific.

Artifact-backed license resolution also enforces explicit safety limits for package artifacts, package metadata files, embedded license files, and package archive entry counts. The same limits apply to local package-manager artifacts and remote package-content fallback. When one of these limits is exceeded, the run fails with an error instead of falling back to review-only output.

The external metadata and vulnerability endpoints actually used during the run are recorded in report JSON and vulnerability JSON as `provenance.externalSources`. Remote license catalog URLs continue to appear in `provenance.catalogSources`.

Package-level provenance can also record `provenance.artifactResolution`. Local package-manager artifacts such as `node_modules` or NuGet `global-packages` are preferred and can be recorded even when enrichment does not need to overwrite any package fields. When no local package-manager artifact is available and the resolver has to rely on a remote source, the package is marked with `reviewRequired: true`, a warning is emitted to stderr, and report JSON includes a `remote_resolution_fallback_used` diagnostic so the result can be reviewed separately from local-artifact-backed evidence.

Recommended patterns:

- use `-http-cache-mode use -http-cache-ttl 24h` for normal CI or local runs
- use `-http-cache-mode cache-only -http-cache-ttl 0` when repeatedly adjusting output presentation and you want to avoid new external requests
- use `-http-cache-mode refresh` when you need to repopulate cache from upstream APIs
- use `-http-cache-mode off` when cache must be bypassed completely

## External network access

This CLI can access external services when metadata enrichment, remote catalogs, or vulnerability reporting are enabled.

- npm metadata enrichment:
  default `https://registry.npmjs.org`
  override `-npm-registry-base-url`
- NuGet metadata enrichment:
  default `https://api.nuget.org/v3/registration5-gz-semver2`
  package archive fallback uses the `packageContent` URL returned by the selected registration service
  override `-nuget-registration-base-url`
- Remote license catalogs:
  any `http://` or `https://` URL passed to `-license-catalog`
  cache controls: `-remote-catalog-mode`, `-remote-catalog-cache-dir`
- OSV vulnerability queries:
  default `https://api.osv.dev`
  override `-osv-base-url`
- GitHub Advisory queries:
  default `https://api.github.com`
  override `-github-advisory-base-url`
  auth: `-github-advisory-token` or `DEPAUDIT_LICENSE_GITHUB_ADVISORY_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`
- NVD vulnerability enrichment:
  default `https://services.nvd.nist.gov`
  override `-nvd-base-url`
  auth: `-nvd-api-key` or `DEPAUDIT_LICENSE_NVD_API_KEY`, `NVD_API_KEY`

Rate-limit notes:

- GitHub raises REST API limits when authenticated
- NVD raises API limits when an API key is provided
- OSV does not currently require authentication
- npm registry and NuGet public-read metadata requests are better handled through cache or an internal mirror/proxy than through per-request credentials

When endpoint overrides are used, the selected mirror or proxy becomes part of the tool's evidence path and should be managed as an operational dependency.

## Exclude policies

`depaudit-license` supports two different exclusion layers.

- `shallow exclude`: post-merge output filtering. This applies to the final normalized inventory regardless of whether packages came from `repository-scan`, CycloneDX, or SPDX input.
- `subgraph exclude`: source-local dependency graph filtering. This currently applies only to `.NET / NuGet` packages collected from `repository-scan` when a package graph is available from `obj/project.assets.json`.

Use `shallow exclude` when you want to hide packages from the rendered report / legal notice output but still keep an audit trail in JSON output. Excluded packages are removed from visible package lists, license groups, production inventory, and legal notice evidence, but remain visible in `excludedPackages` with rule metadata.

Use `subgraph exclude` when you want to remove a matched root package and dependencies that are reachable only from that root before merge. Shared dependencies are preserved if another non-excluded root still reaches them. If graph support is unavailable, `onUnsupported` controls whether the policy should `warn`, `error`, or `ignore`.

`-exclude-patterns` remains a legacy shorthand for simple shallow exclusion by package-name fragment. It is internally converted into a synthesized shallow rule, so it cannot express project path, dependency type, runtime-asset, or graph-based behavior.

Minimal example:

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

Example invocation:

```powershell
.\depaudit-license-windows-amd64.exe `
  -input repository-scan=.\my-repository `
  -exclude-policy .\configs\exclude-policy.json `
  -output-html dist\report.html `
  -output-json dist\report.json `
  -output-legal-html dist\legal-notice.html
```

See also:

- [configs/exclude-policy.sample.json](configs/exclude-policy.sample.json)
- [configs/exclude-policy.schema.json](configs/exclude-policy.schema.json)
- [configs/license-overrides.sample.json](configs/license-overrides.sample.json)
- [configs/license-overrides.schema.json](configs/license-overrides.schema.json)

## Versioning and compatibility

Public OSS releases start at `1.0.0`.

- `1.x` releases should preserve documented CLI and output contracts unless a change is intentionally released as breaking
- breaking changes should be called out explicitly in release notes and repository documentation
- experimental or provisional behavior should be labeled as such in the relevant document before release

## Repository docs

- [README.ja.md](README.ja.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [CHANGELOG.md](CHANGELOG.md)
- [RELEASE.md](RELEASE.md)
- [configs/README.md](configs/README.md)
- [LICENSE](LICENSE)
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [SECURITY.ja.md](SECURITY.ja.md)
- [.github/SUPPORT.md](.github/SUPPORT.md)
- [.github/SUPPORT.ja.md](.github/SUPPORT.ja.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Disclaimer

- This is an independent OSS tool for license inventory, notice generation, and supplemental vulnerability reporting.
- It is not affiliated with OSV, GitHub Advisory Database, NVD, SPDX, or the CycloneDX project.
- It can access external package metadata, license catalog, and vulnerability APIs depending on the selected inputs and flags.
- It is intended to assist and streamline license inventory, notice generation, and review workflows, not to conclusively resolve licensing issues.
- It does not provide legal advice, legal opinions, or a guarantee of license compliance.
- License classification, metadata enrichment, and generated notice outputs can be incomplete, outdated, or incorrect depending on upstream package metadata and available evidence.
- Final interpretation of license obligations, policy decisions, and release approval remains the responsibility of the user and, where appropriate, legal counsel or internal compliance review.
