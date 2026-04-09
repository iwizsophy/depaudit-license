package scan

import "depaudit-license/internal/inventory"

const (
	DiagnosticSeverityWarning      = "warning"
	DiagnosticCodeGraphUnavailable = "dependency-graph-unavailable"
)

// Result is the source-local repository-scan result before inventory merge.
// It keeps package graph data and diagnostics alongside the flattened packages.
type Result struct {
	Packages    []Package              `json:"packages"`
	Graphs      []DependencyGraph      `json:"graphs,omitempty"`
	Diagnostics []inventory.Diagnostic `json:"diagnostics,omitempty"`
}

type DependencyGraph struct {
	Ecosystem   string                `json:"ecosystem"`
	Project     string                `json:"project"`
	ProjectPath string                `json:"projectPath,omitempty"`
	Roots       []string              `json:"roots,omitempty"`
	Nodes       []DependencyGraphNode `json:"nodes"`
	Edges       []DependencyGraphEdge `json:"edges,omitempty"`
}

type DependencyGraphNode struct {
	ID      string  `json:"id"`
	Package Package `json:"package"`
}

type DependencyGraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}
