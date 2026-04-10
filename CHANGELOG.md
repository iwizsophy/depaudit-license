# Changelog

All notable public-release changes to this project will be documented in this file.

The format is intentionally simple and release-oriented.

## [Unreleased]

No notable changes yet.

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
