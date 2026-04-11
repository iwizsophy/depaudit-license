# Architecture Overview

This document preserves the core design decisions behind `depaudit-license` now that the in-repository issue backlog has been retired.

## Purpose

`depaudit-license` normalizes license and package evidence from either a repository scan or existing SBOM inputs, then renders user-facing outputs from that normalized inventory.

The main product boundary is:

1. load inputs
2. normalize into inventory
3. enrich metadata
4. apply package-level license overrides
5. render report / legal notice / vulnerability outputs

## Input model

Supported CLI input kinds:

- `repository-scan=<path>`
- `cyclonedx-json=<path>`
- `spdx-json=<path>`

Multiple `-input` flags are merged into one normalized inventory.

## Supported ecosystems

Repository scan directly supports:

- `node` (`Node.js / npm / pnpm / Yarn`)
- `dotnet` (`.NET / NuGet`)

SBOM imports can also normalize packages as:

- `generic`

`generic` packages remain valid for reporting, but metadata enrichment and vulnerability matching can be more limited when ecosystem-specific identifiers are unavailable.

## Normalized inventory boundary

The normalized inventory model is the contract between:

- input loading
- metadata enrichment
- report rendering
- vulnerability assessment

This boundary is intentionally kept explicit so input parsing and output rendering do not become tightly coupled.

## Catalog and localization

License metadata comes from:

- `configs/licenses.json`
- optional override sources from `-license-catalog`
- locale bundles such as `configs/license-texts.ja.json`

Catalog sources can be layered, and remote catalogs are supported with:

- `fail-fast`
- `stale-fallback`

Locale bundles enrich descriptions and obligations without changing the normalized license key structure.

The built-in catalog may intentionally include review-only definitions for common source-available or proprietary-adjacent licenses. These definitions help move packages out of the fallback `Unknown` bucket while preserving `requires_manual_review: true` as an explicit contract for downstream policy and report handling.

Package-level license overrides are intentionally separate from catalog sources. Catalog overrides normalize raw license evidence globally, while license override files match selected inventory packages and update their `licenseKey` with explicit provenance.

## Metadata enrichment and provenance

After input loading, ecosystem-aware enrichment can add metadata such as:

- repository / homepage
- copyright holder / year
- embedded license text

Merge and enrich stages preserve provenance so downstream outputs can explain where fields came from and how layered sources were applied.

For NuGet specifically, enrichment first checks the local global-packages cache and then the remote registration/package endpoints. When registration metadata does not expose a usable SPDX expression, the resolver can read embedded `<license type="file">` content from the package archive so text-based catalog normalization still has a chance to classify the license.

External HTTP calls used by metadata enrichment and vulnerability assessment are intentionally configurable. npm registry, NuGet registration, OSV, GitHub Advisory, and NVD endpoints can be redirected to mirrors or proxies, and metadata/vulnerability API requests can be cached with explicit `off`, `use`, `refresh`, and `cache-only` modes plus TTL control. The selected endpoint set is emitted in JSON outputs as `provenance.externalSources`, while remote license catalogs keep their own `provenance.catalogSources` and stale-fallback cache because catalog layering and pinning semantics are treated as a distinct contract from generic HTTP response reuse.

## Output model

Primary outputs:

- report HTML
- report JSON
- legal notice HTML

When legal notice evidence includes embedded license text from a package-local file, the CLI also writes a raw-text copy next to the legal notice output under `license-texts/...` and exposes the relative path as `copiedFilePath`.

Optional outputs:

- vulnerability HTML
- vulnerability JSON

These outputs are public contracts and should be treated as compatibility-sensitive for `1.x`.

## Template model

The built-in report and legal notice renderers use assets from `templates/`.

Custom templates can use these helpers:

- `slug`
- `ecosystemLabel`
- `dependencyTypeLabel`
- `prettyJSON`

Helper categories:

- `slug`, `ecosystemLabel`, `dependencyTypeLabel`: presentation helpers
- `prettyJSON`: debug/convenience helper for inspecting structured view data in custom templates

`prettyJSON` is intentionally not a core presentation primitive. It exists to help template authors inspect nested data or emit raw view content in a controlled way.

## Vulnerability pipeline

The vulnerability pipeline runs from the same normalized inventory as the license outputs.

Supported modes:

- `disabled`
- `osv-only`
- `osv+github`
- `full`

Coverage and fidelity vary by ecosystem and identifier quality.

When vulnerability modes are enabled, GitHub Advisory and NVD can also receive optional credentials so operators can work within higher upstream API limits without changing the normalized inventory model itself.

## Release packaging

Release archives are the primary distribution model.

Each package includes:

- platform-specific binary
- `templates/`
- `configs/`
- `README.md`
- `README.ja.md`
- `LICENSE`
- `THIRD-PARTY-NOTICES.md`
- a Syft-generated SPDX JSON SBOM for the packaged distribution

## Quality policy

The project uses representative contract coverage rather than chasing 100% coverage unconditionally.

The rule is:

- preserve high-value user-facing contracts with tests
- avoid architecture changes whose main purpose is only to satisfy incidental coverage branches

This keeps the system testable without distorting product structure around test-only seams.
