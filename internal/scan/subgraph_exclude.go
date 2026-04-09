package scan

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"depaudit-license/internal/inventory"
	"depaudit-license/internal/policy"
)

const (
	DiagnosticSeverityInfo            = "info"
	DiagnosticCodeSubgraphApplied     = "subgraph-exclude-applied"
	DiagnosticCodeSubgraphUnsupported = "subgraph-exclude-unsupported"
)

type SubgraphExcludeConfig struct {
	Root     string
	SourceID string
	Rules    []policy.Rule
}

func ApplySubgraphExcludes(cfg SubgraphExcludeConfig, result Result) (Result, error) {
	if len(cfg.Rules) == 0 {
		return result, nil
	}

	updated := cloneResult(result)
	for _, rule := range cfg.Rules {
		unsupported := collectUnsupportedSubgraphMatches(updated, cfg.Root, rule)
		if len(unsupported) > 0 {
			switch subgraphUnsupportedMode(rule) {
			case policy.OnUnsupportedError:
				return Result{}, fmt.Errorf("subgraph exclude %q is unsupported for %s", ruleID(rule), strings.Join(unsupported, ", "))
			case policy.OnUnsupportedWarn:
				updated.Diagnostics = append(updated.Diagnostics, inventory.Diagnostic{
					SourceID:     strings.TrimSpace(cfg.SourceID),
					RuleID:       strings.TrimSpace(rule.ID),
					Code:         DiagnosticCodeSubgraphUnsupported,
					Severity:     DiagnosticSeverityWarning,
					Message:      fmt.Sprintf("subgraph exclude %q matched packages without graph support", ruleID(rule)),
					MatchedRoots: append([]string(nil), unsupported...),
				})
			}
		}

		for index := range updated.Graphs {
			diagnostic, changed := applySubgraphRuleToGraph(cfg.Root, cfg.SourceID, &updated.Graphs[index], rule)
			if changed {
				updated.Diagnostics = append(updated.Diagnostics, diagnostic)
			}
		}
	}

	updated.Packages = filterPackagesByGraphs(updated.Packages, updated.Graphs)
	sort.Slice(updated.Packages, func(i, j int) bool {
		left := updated.Packages[i]
		right := updated.Packages[j]
		return strings.Join([]string{left.Ecosystem, left.Project, left.Name, left.Version}, "\x00") <
			strings.Join([]string{right.Ecosystem, right.Project, right.Name, right.Version}, "\x00")
	})
	sort.Slice(updated.Diagnostics, func(i, j int) bool {
		left := updated.Diagnostics[i]
		right := updated.Diagnostics[j]
		return strings.Join([]string{left.SourceID, left.RuleID, left.Code, left.ProjectPath, left.Project, left.Message}, "\x00") <
			strings.Join([]string{right.SourceID, right.RuleID, right.Code, right.ProjectPath, right.Project, right.Message}, "\x00")
	})
	return updated, nil
}

func applySubgraphRuleToGraph(root string, sourceID string, graph *DependencyGraph, rule policy.Rule) (inventory.Diagnostic, bool) {
	nodesByID := map[string]DependencyGraphNode{}
	for _, node := range graph.Nodes {
		nodesByID[node.ID] = node
	}
	if len(nodesByID) == 0 {
		return inventory.Diagnostic{}, false
	}

	projectCandidates := graphProjectCandidates(root, graph.ProjectPath, graph.Project)
	matchedRoots := make([]string, 0)
	activeRoots := make([]string, 0, len(graph.Roots))
	for _, rootID := range graph.Roots {
		if _, ok := nodesByID[rootID]; !ok {
			continue
		}
		activeRoots = append(activeRoots, rootID)
		if policy.SelectorMatchesPackage(rule.Match, inventoryPackage(nodesByID[rootID].Package), projectCandidates...) {
			matchedRoots = append(matchedRoots, rootID)
		}
	}
	if len(matchedRoots) == 0 {
		return inventory.Diagnostic{}, false
	}

	matchedSet := sliceSet(matchedRoots)
	keepRoots := make([]string, 0, len(activeRoots))
	for _, rootID := range activeRoots {
		if _, excluded := matchedSet[rootID]; excluded {
			continue
		}
		keepRoots = append(keepRoots, rootID)
	}

	preservedSet := reachableNodes(keepRoots, graph.Edges, nodesByID)
	removedSet := map[string]struct{}{}
	for nodeID := range nodesByID {
		if _, preserved := preservedSet[nodeID]; preserved {
			continue
		}
		removedSet[nodeID] = struct{}{}
	}

	graph.Roots = append([]string(nil), keepRoots...)
	graph.Nodes = filterGraphNodes(graph.Nodes, removedSet)
	graph.Edges = filterGraphEdges(graph.Edges, removedSet)

	preserved := sortedKeys(preservedSet)
	removed := sortedKeys(removedSet)
	return inventory.Diagnostic{
		SourceID:          strings.TrimSpace(sourceID),
		RuleID:            strings.TrimSpace(rule.ID),
		Code:              DiagnosticCodeSubgraphApplied,
		Severity:          DiagnosticSeverityInfo,
		Message:           fmt.Sprintf("subgraph exclude %q applied to %s", ruleID(rule), firstProjectCandidate(append(projectCandidates, graph.Project)...)),
		Ecosystem:         graph.Ecosystem,
		Project:           graph.Project,
		ProjectPath:       firstProjectCandidate(append(projectCandidates, graph.ProjectPath)...),
		MatchedRoots:      append([]string(nil), matchedRoots...),
		RemovedPackages:   removed,
		PreservedPackages: preserved,
	}, true
}

func collectUnsupportedSubgraphMatches(result Result, root string, rule policy.Rule) []string {
	graphRootPackages := map[string]struct{}{}
	for _, graph := range result.Graphs {
		nodesByID := map[string]DependencyGraphNode{}
		for _, node := range graph.Nodes {
			nodesByID[node.ID] = node
		}
		for _, rootID := range graph.Roots {
			node, ok := nodesByID[rootID]
			if !ok {
				continue
			}
			graphRootPackages[packageIdentity(node.Package)] = struct{}{}
		}
	}

	projectCandidatesByIdentity := map[string][]string{}
	projectCandidatesByName := map[string][]string{}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code != DiagnosticCodeGraphUnavailable {
			continue
		}
		candidates := graphProjectCandidates(root, diagnostic.ProjectPath, diagnostic.Project)
		projectCandidatesByIdentity[projectIdentity(diagnostic.ProjectPath, diagnostic.Project)] = append(projectCandidatesByIdentity[projectIdentity(diagnostic.ProjectPath, diagnostic.Project)], candidates...)
		projectCandidatesByName[strings.TrimSpace(diagnostic.Project)] = append(projectCandidatesByName[strings.TrimSpace(diagnostic.Project)], candidates...)
	}

	unsupported := map[string]struct{}{}
	for _, pkg := range result.Packages {
		if !isDirectDependencyType(pkg.DependencyType) {
			continue
		}
		if _, supported := graphRootPackages[packageIdentity(pkg)]; supported {
			continue
		}
		projectCandidates := graphProjectCandidates(root, pkg.ProjectPath, pkg.Project)
		if candidates, ok := projectCandidatesByIdentity[projectIdentity(pkg.ProjectPath, pkg.Project)]; ok {
			projectCandidates = append(projectCandidates, candidates...)
		} else if strings.TrimSpace(pkg.ProjectPath) == "" {
			projectCandidates = append(projectCandidates, projectCandidatesByName[strings.TrimSpace(pkg.Project)]...)
		}
		projectCandidates = uniqueSubgraphStrings(projectCandidates)
		if !policy.SelectorMatchesPackage(rule.Match, inventoryPackage(pkg), projectCandidates...) {
			continue
		}
		unsupported[subgraphPackageID(pkg)] = struct{}{}
	}
	return sortedKeys(unsupported)
}

func filterPackagesByGraphs(packages []Package, graphs []DependencyGraph) []Package {
	managedProjects := map[string]struct{}{}
	activePackages := map[string]struct{}{}
	for _, graph := range graphs {
		managedProjects[projectIdentity(graph.ProjectPath, graph.Project)] = struct{}{}
		for _, node := range graph.Nodes {
			activePackages[packageIdentity(node.Package)] = struct{}{}
		}
	}

	result := make([]Package, 0, len(packages))
	for _, pkg := range packages {
		if pkg.Ecosystem != "dotnet" {
			result = append(result, pkg)
			continue
		}
		if _, ok := activePackages[packageIdentity(pkg)]; ok {
			result = append(result, pkg)
			continue
		}
		if _, managed := managedProjects[projectIdentity(pkg.ProjectPath, pkg.Project)]; !managed {
			result = append(result, pkg)
		}
	}
	return result
}

func filterGraphNodes(nodes []DependencyGraphNode, removed map[string]struct{}) []DependencyGraphNode {
	result := make([]DependencyGraphNode, 0, len(nodes))
	for _, node := range nodes {
		if _, ok := removed[node.ID]; ok {
			continue
		}
		result = append(result, node)
	}
	return result
}

func filterGraphEdges(edges []DependencyGraphEdge, removed map[string]struct{}) []DependencyGraphEdge {
	result := make([]DependencyGraphEdge, 0, len(edges))
	for _, edge := range edges {
		if _, ok := removed[edge.From]; ok {
			continue
		}
		if _, ok := removed[edge.To]; ok {
			continue
		}
		result = append(result, edge)
	}
	return result
}

func reachableNodes(roots []string, edges []DependencyGraphEdge, nodesByID map[string]DependencyGraphNode) map[string]struct{} {
	reachable := map[string]struct{}{}
	if len(roots) == 0 {
		return reachable
	}

	adjacency := map[string][]string{}
	for _, edge := range edges {
		if _, ok := nodesByID[edge.From]; !ok {
			continue
		}
		if _, ok := nodesByID[edge.To]; !ok {
			continue
		}
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
	}

	stack := append([]string(nil), roots...)
	for len(stack) > 0 {
		last := len(stack) - 1
		nodeID := stack[last]
		stack = stack[:last]
		if _, seen := reachable[nodeID]; seen {
			continue
		}
		if _, ok := nodesByID[nodeID]; !ok {
			continue
		}
		reachable[nodeID] = struct{}{}
		stack = append(stack, adjacency[nodeID]...)
	}
	return reachable
}

func graphProjectCandidates(root string, projectPath string, project string) []string {
	candidates := []string{strings.TrimSpace(project)}
	if rel := relativeProjectPath(root, projectPath); rel != "" {
		candidates = append(candidates, rel)
	}
	if strings.TrimSpace(projectPath) != "" {
		candidates = append(candidates, strings.TrimSpace(projectPath))
	}
	return uniqueSubgraphStrings(candidates)
}

func relativeProjectPath(root string, projectPath string) string {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(projectPath) == "" {
		return ""
	}
	relative, err := filepath.Rel(root, projectPath)
	if err != nil {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(relative))
}

func cloneResult(result Result) Result {
	cloned := Result{
		Packages:    append([]Package(nil), result.Packages...),
		Graphs:      make([]DependencyGraph, len(result.Graphs)),
		Diagnostics: make([]inventory.Diagnostic, len(result.Diagnostics)),
	}
	for index, graph := range result.Graphs {
		cloned.Graphs[index] = graph
		cloned.Graphs[index].Roots = append([]string(nil), graph.Roots...)
		cloned.Graphs[index].Nodes = append([]DependencyGraphNode(nil), graph.Nodes...)
		cloned.Graphs[index].Edges = append([]DependencyGraphEdge(nil), graph.Edges...)
	}
	for index, diagnostic := range result.Diagnostics {
		cloned.Diagnostics[index] = diagnostic
		cloned.Diagnostics[index].MatchedRoots = append([]string(nil), diagnostic.MatchedRoots...)
		cloned.Diagnostics[index].RemovedPackages = append([]string(nil), diagnostic.RemovedPackages...)
		cloned.Diagnostics[index].PreservedPackages = append([]string(nil), diagnostic.PreservedPackages...)
	}
	return cloned
}

func isDirectDependencyType(value string) bool {
	switch strings.TrimSpace(value) {
	case "dependency", "devDependency", "peerDependency":
		return true
	default:
		return false
	}
}

func packageIdentity(pkg Package) string {
	return strings.ToLower(strings.Join([]string{pkg.Ecosystem, projectIdentity(pkg.ProjectPath, pkg.Project), pkg.Name, pkg.Version}, "\x00"))
}

func projectIdentity(projectPath string, project string) string {
	if strings.TrimSpace(projectPath) != "" {
		return filepath.Clean(strings.TrimSpace(projectPath))
	}
	return strings.TrimSpace(project)
}

func inventoryPackage(pkg Package) inventory.Package {
	return inventory.Package{
		Ecosystem:        pkg.Ecosystem,
		Project:          pkg.Project,
		Name:             pkg.Name,
		Version:          pkg.Version,
		PURL:             pkg.PURL,
		DependencyType:   pkg.DependencyType,
		HasRuntimeAssets: pkg.HasRuntimeAssets,
	}
}

func subgraphPackageID(pkg Package) string {
	if pkg.Ecosystem == "dotnet" {
		return makeNugetPackageKey(pkg.Name, pkg.Version)
	}
	if strings.TrimSpace(pkg.Version) == "" {
		return pkg.Name
	}
	return pkg.Name + "@" + pkg.Version
}

func subgraphUnsupportedMode(rule policy.Rule) string {
	switch strings.TrimSpace(rule.OnUnsupported) {
	case policy.OnUnsupportedError:
		return policy.OnUnsupportedError
	case policy.OnUnsupportedWarn:
		return policy.OnUnsupportedWarn
	default:
		return policy.OnUnsupportedIgnore
	}
}

func ruleID(rule policy.Rule) string {
	if strings.TrimSpace(rule.ID) != "" {
		return strings.TrimSpace(rule.ID)
	}
	return "unnamed-rule"
}

func sortedKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sliceSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func uniqueSubgraphStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func firstProjectCandidate(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
