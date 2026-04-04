package coveragehotspots

import "testing"

func TestParseGoToolCoverFuncOutputSortsEntriesAndReadsTotal(t *testing.T) {
	t.Parallel()

	output := `internal/report/report.go:95:	BuildDocument	92.3%
main.go:42:	run	88.1%
internal/scan/scan.go:300:	Collect	88.1%
total:	(statements)	93.7%`

	entries, total, err := ParseGoToolCoverFuncOutput(output)
	if err != nil {
		t.Fatalf("ParseGoToolCoverFuncOutput: %v", err)
	}
	if total != 93.7 {
		t.Fatalf("total = %v", total)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].Package != "internal/scan" || entries[0].Function != "Collect" {
		t.Fatalf("first entry = %#v", entries[0])
	}
	if entries[1].Package != "root" || entries[1].Function != "run" {
		t.Fatalf("second entry = %#v", entries[1])
	}
	if entries[2].Package != "internal/report" || entries[2].Function != "BuildDocument" {
		t.Fatalf("third entry = %#v", entries[2])
	}
}

func TestParseGoToolCoverFuncOutputRejectsInvalidLines(t *testing.T) {
	t.Parallel()

	if _, _, err := ParseGoToolCoverFuncOutput("broken"); err == nil {
		t.Fatal("expected parse error")
	}
	if _, _, err := ParseGoToolCoverFuncOutput("main.go run ninety\ntotal:\t(statements)\t100.0%"); err == nil {
		t.Fatal("expected percent parse error")
	}
	if _, _, err := ParseGoToolCoverFuncOutput("main.go run 90.0%"); err == nil {
		t.Fatal("expected location parse error")
	}
	if _, _, err := ParseGoToolCoverFuncOutput("main.go:1:\trun\t90.0%"); err == nil {
		t.Fatal("expected missing total error")
	}
}

func TestFilterAppliesThresholdAndTopLimit(t *testing.T) {
	t.Parallel()

	entries := []Entry{
		{Function: "A", Percent: 10},
		{Function: "B", Percent: 25},
		{Function: "C", Percent: 50},
	}

	filtered := Filter(entries, 25, 1)
	if len(filtered) != 1 || filtered[0].Function != "A" {
		t.Fatalf("filtered = %#v", filtered)
	}

	filtered = Filter(entries, 50, 0)
	if len(filtered) != 3 {
		t.Fatalf("filtered without top = %#v", filtered)
	}
}

func TestParseGoToolCoverFuncOutputHandlesCRLFAndTieBreakOrdering(t *testing.T) {
	t.Parallel()

	output := "pkg/file_b.go:10:\tBeta\t80.0%\r\n" +
		"other/file.go:10:\tAlpha\t80.0%\r\n" +
		"file_a.go:10:\tGamma\t80.0%\r\n" +
		"file_a.go:10:\tAlpha\t80.0%\r\n" +
		"\r\n" +
		"total:\t(statements)\t90.0%\r\n"

	entries, total, err := ParseGoToolCoverFuncOutput(output)
	if err != nil {
		t.Fatalf("ParseGoToolCoverFuncOutput: %v", err)
	}
	if total != 90.0 {
		t.Fatalf("total = %v", total)
	}
	if len(entries) != 4 {
		t.Fatalf("entries = %#v", entries)
	}

	got := []Entry{
		entries[0],
		entries[1],
		entries[2],
		entries[3],
	}
	want := []Entry{
		{Package: "other", File: "other/file.go", Function: "Alpha", Percent: 80.0},
		{Package: "pkg", File: "pkg/file_b.go", Function: "Beta", Percent: 80.0},
		{Package: "root", File: "file_a.go", Function: "Alpha", Percent: 80.0},
		{Package: "root", File: "file_a.go", Function: "Gamma", Percent: 80.0},
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("entry[%d] = %#v want %#v", index, got[index], want[index])
		}
	}
}

func TestFilterIncludesThresholdAndTreatsNegativeTopAsUnlimited(t *testing.T) {
	t.Parallel()

	entries := []Entry{
		{Function: "A", Percent: 10},
		{Function: "B", Percent: 25},
		{Function: "C", Percent: 25.1},
	}

	filtered := Filter(entries, 25, -1)
	if len(filtered) != 2 {
		t.Fatalf("filtered = %#v", filtered)
	}
	if filtered[0].Function != "A" || filtered[1].Function != "B" {
		t.Fatalf("filtered = %#v", filtered)
	}
}
