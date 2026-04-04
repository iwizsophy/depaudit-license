package coveragehotspots

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Entry struct {
	File     string  `json:"file"`
	Package  string  `json:"package"`
	Function string  `json:"function"`
	Percent  float64 `json:"percent"`
}

func ParseGoToolCoverFuncOutput(output string) ([]Entry, float64, error) {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	entries := make([]Entry, 0, len(lines))
	total := 0.0
	totalSeen := false

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, 0, fmt.Errorf("invalid go tool cover output line %q", line)
		}

		location := fields[0]
		function := fields[1]
		percentText := strings.TrimSuffix(fields[len(fields)-1], "%")
		percent, err := strconv.ParseFloat(percentText, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("parse coverage percent from %q: %w", line, err)
		}

		if location == "total:" && function == "(statements)" {
			total = percent
			totalSeen = true
			continue
		}

		filePart, _, ok := strings.Cut(location, ":")
		if !ok {
			return nil, 0, fmt.Errorf("invalid location %q", location)
		}
		normalizedFile := filepath.ToSlash(filePart)
		pkg := path.Dir(normalizedFile)
		if pkg == "." {
			pkg = "root"
		}

		entries = append(entries, Entry{
			File:     normalizedFile,
			Package:  pkg,
			Function: function,
			Percent:  percent,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		left := entries[i]
		right := entries[j]
		if left.Percent != right.Percent {
			return left.Percent < right.Percent
		}
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		if left.File != right.File {
			return left.File < right.File
		}
		return left.Function < right.Function
	})

	if !totalSeen {
		return nil, 0, fmt.Errorf("total coverage line not found")
	}
	return entries, total, nil
}

func Filter(entries []Entry, threshold float64, top int) []Entry {
	filtered := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Percent > threshold {
			continue
		}
		filtered = append(filtered, entry)
		if top > 0 && len(filtered) >= top {
			break
		}
	}
	return filtered
}
