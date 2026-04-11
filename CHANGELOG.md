# Changelog

All notable public-release changes to this project will be documented in this file.

The format is intentionally simple and release-oriented.

## [Unreleased]

No notable changes yet.

## [1.3.0] - 2026-04-11

### Added

- Built-in review-only catalog definitions for common source-available and proprietary-adjacent licenses, including Microsoft Software License Terms, BUSL, Elastic License 2.0, SSPL, Commons Clause, PolyForm, Functional Source License, Confluent Community License, Timescale License, and CockroachDB Community License.
- Japanese localized explanations for the new review-only catalog entries so reports can carry short operator-facing guidance without treating those licenses as pre-approved OSS.
- Configurable HTTP response caching for external metadata and vulnerability APIs, including `off`, `use`, `refresh`, and `cache-only` modes with TTL control.
- Configurable endpoint overrides for npm registry and NuGet registration metadata, alongside the existing OSV / GitHub Advisory / NVD base URL settings.
- Optional GitHub Advisory token and NVD API key settings for environments that need higher external API limits.
- Report JSON and vulnerability JSON provenance now record the selected external metadata and vulnerability endpoints in `externalSources`.

### Changed

- NuGet registration fallback now reads embedded `<license type="file">` evidence from package archives even when registration metadata also exposes `licenseUrl`, allowing review-only or file-based licenses to resolve out of `Unknown` when the package archive contains a recognizable license text.
- README and release-facing documentation now explicitly describe external network access, cache behavior, endpoint overrides, and authentication knobs for rate-limited APIs.
- Shared HTTP cache keys are now partitioned by auth-sensitive request headers, and cache files are written with restricted permissions so mirrored or authenticated upstreams do not bleed into each other through a shared cache entry.

## [1.2.0] - 2026-04-10

### Added

- Package-level license override files via `-license-override-file`, for manually binding selected packages such as unresolved `Unknown` licenses to catalog license keys.
- JSON schema and sample config for package-level license overrides in `configs/license-overrides.schema.json` and `configs/license-overrides.sample.json`.
- Legal notice handling for embedded package-local license text, including copied raw text files under `license-texts/...` and `copiedFilePath` output links.

## [1.1.0] - 2026-04-10

### Added

- Yarn lockfile support for repository scan, alongside the existing Node.js `package.json` fallback and pnpm lockfile support
- Versioned exclude policy files via `-exclude-policy`, including shallow output filtering and source-local NuGet subgraph exclusion.
- NuGet dependency graph extraction from `obj/project.assets.json` for graph-aware repository scan filtering.

## [1.0.0] - 2026-04-04

First public release of `depaudit-license`.

### Added

- repository scan input for Node.js / npm and .NET / NuGet projects
- CycloneDX JSON and SPDX JSON import
- normalized inventory merge across multiple inputs
- metadata enrichment pipeline for supported ecosystems
- report HTML, legal notice HTML, and report JSON outputs
- optional vulnerability checklist HTML and JSON outputs
- layered license catalog and localized license text bundle support
- binary release archives for Windows, Linux, and macOS
- Syft-generated SPDX JSON SBOM included in release packages
- Japanese user-facing documentation

### Notes

- `1.x` treats documented CLI, JSON, and HTML output behavior as public contract
- release archives are the primary distribution model
