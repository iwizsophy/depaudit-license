# Third-Party Notices

This document lists third-party Go modules currently included in the repository dependency graph through `go.mod`.

## Scope

- Listed items cover modules explicitly present in `go.mod`, including indirect entries.
- The Go standard library is not listed here.
- Additional transitive dependencies that are not represented in `go.mod` are reviewed during dependency updates and release validation, but are not listed separately by default.

## Current modules

### github.com/santhosh-tekuri/jsonschema/v6 v6.0.2

- License: Apache License 2.0
- Source: `github.com/santhosh-tekuri/jsonschema/v6`

### gopkg.in/yaml.v3 v3.0.1

- License: Apache License 2.0
- Additional notice: parts of the module include code ported from libyaml under the MIT License
- Source: `gopkg.in/yaml.v3`

### golang.org/x/text v0.14.0

- License: BSD 3-Clause
- Source: `golang.org/x/text`

## Update policy

- Update this file when a dependency is added, removed, or its version changes in `go.mod`.
- Re-check license terms when dependency versions change.
- If a module ships multiple notices or mixed-license files, summarize that fact here and retain the upstream notice requirements in distributed materials when applicable.

## Trademarks

GitHub is a trademark of GitHub, Inc.

Node.js is a trademark of the OpenJS Foundation.

.NET and NuGet are trademarks of Microsoft.

SPDX is a trademark of The Linux Foundation.

CycloneDX is a trademark of the OWASP Foundation.

Syft is a trademark of Anchore, Inc.

This project is independent and is not affiliated with, endorsed by, or sponsored by those trademark owners.
