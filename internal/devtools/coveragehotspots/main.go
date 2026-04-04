package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"text/tabwriter"

	"depaudit-license/internal/coveragehotspots"
)

var coverFuncOutput = func(coverprofile string) ([]byte, error) {
	return exec.Command("go", "tool", "cover", "-func", coverprofile).CombinedOutput()
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("coveragehotspots", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		coverprofile = fs.String("coverprofile", "coverage.out", "path to go cover profile")
		threshold    = fs.Float64("threshold", 95, "show functions at or below this percent")
		top          = fs.Int("top", 25, "maximum number of hotspot rows to print; 0 prints all")
		format       = fs.String("format", "text", "output format: text or json")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	output, err := coverFuncOutput(*coverprofile)
	if err != nil {
		fmt.Fprintf(stderr, "go tool cover -func %s: %v\n%s", *coverprofile, err, bytes.TrimSpace(output))
		return 1
	}

	entries, total, err := coveragehotspots.ParseGoToolCoverFuncOutput(string(output))
	if err != nil {
		fmt.Fprintf(stderr, "parse coverage output: %v\n", err)
		return 1
	}

	filtered := coveragehotspots.Filter(entries, *threshold, *top)
	switch *format {
	case "json":
		payload := struct {
			Threshold float64                  `json:"threshold"`
			Total     float64                  `json:"total"`
			Hotspots  []coveragehotspots.Entry `json:"hotspots"`
		}{
			Threshold: *threshold,
			Total:     total,
			Hotspots:  filtered,
		}
		if err := writeJSONOutput(stdout, payload); err != nil {
			fmt.Fprintf(stderr, "write json: %v\n", err)
			return 1
		}
	case "text":
		if err := writeTextOutput(stdout, total, *threshold, filtered); err != nil {
			fmt.Fprintf(stderr, "write text: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return 1
	}
	return 0
}

func writeJSONOutput(stdout io.Writer, payload any) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func writeTextOutput(stdout io.Writer, total float64, threshold float64, filtered []coveragehotspots.Entry) error {
	writer := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(writer, "TOTAL\t%.1f%%\n", total)
	fmt.Fprintf(writer, "THRESHOLD\t%.1f%%\n", threshold)
	fmt.Fprintln(writer, "PACKAGE\tFUNCTION\tCOVERAGE\tFILE")
	for _, entry := range filtered {
		fmt.Fprintf(writer, "%s\t%s\t%.1f%%\t%s\n", entry.Package, entry.Function, entry.Percent, entry.File)
	}
	return writer.Flush()
}
