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

- `Node.js / npm`
- `.NET / NuGet`

SBOM inputs can also carry packages that are normalized as:

- `generic`

In practice this means:

- repository scan is designed around Node.js / npm and .NET / NuGet manifests and metadata
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

## Customization

License definitions and descriptions:

- `-license-catalog` accepts local file paths and `https://` URLs
- later `-license-catalog` values override earlier sources
- `-locale` selects `configs/license-texts.<locale>.json`
- `-license-text-bundle` overrides locale-based bundle resolution

Presentation:

- `-template`, `-theme-css`
- `-legal-template`, `-legal-theme-css`
- `-vuln-template`, `-vuln-theme-css`

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
