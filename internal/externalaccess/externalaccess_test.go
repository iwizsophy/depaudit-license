package externalaccess

import (
	"net/http"
	"testing"
)

func TestNormalizeDedupesAndSorts(t *testing.T) {
	t.Parallel()

	values := Normalize([]Service{
		{ID: "osv", Purpose: "vulnerability", BaseURL: " https://api.osv.dev ", CacheMode: "use", CacheTTL: "24h0m0s"},
		{ID: "osv", Purpose: "vulnerability", BaseURL: "https://api.osv.dev"},
		{ID: "npm-registry", Purpose: "metadata-enrichment", BaseURL: "https://registry.npmjs.org"},
		{ID: " ", Purpose: "metadata-enrichment", BaseURL: "https://skip.example.test"},
	})

	if len(values) != 2 {
		t.Fatalf("service count = %d", len(values))
	}
	if values[0].ID != "npm-registry" || values[0].Purpose != "metadata-enrichment" {
		t.Fatalf("first service = %#v", values[0])
	}
	if values[1].ID != "osv" || values[1].Purpose != "vulnerability" {
		t.Fatalf("second service = %#v", values[1])
	}
	if values[1].BaseURL != "https://api.osv.dev" {
		t.Fatalf("base url = %q", values[1].BaseURL)
	}
}

func TestTrackerRecordsAnnotatedRequests(t *testing.T) {
	t.Parallel()

	tracker := NewTracker([]Service{
		{ID: "osv", Purpose: "vulnerability", BaseURL: "https://api.osv.dev", CacheMode: "use", CacheTTL: "24h0m0s"},
	})
	req, err := http.NewRequest(http.MethodPost, "https://api.osv.dev/v1/querybatch", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	tracker.Observe(WithRequestService(req, Service{ID: "osv", Purpose: "vulnerability", BaseURL: "https://api.osv.dev"}))

	used := tracker.Used()
	if len(used) != 1 {
		t.Fatalf("used = %#v", used)
	}
	if used[0].ID != "osv" || used[0].CacheMode != "use" || used[0].CacheTTL != "24h0m0s" {
		t.Fatalf("used[0] = %#v", used[0])
	}
}

func TestTrackerUsesObservedOriginWhenRequestLeavesConfiguredBase(t *testing.T) {
	t.Parallel()

	tracker := NewTracker([]Service{
		{ID: "nuget-registration", Purpose: "metadata-enrichment", BaseURL: "https://mirror.example.test/v3/registration5-gz-semver2"},
	})
	req, err := http.NewRequest(http.MethodGet, "https://packages.example.test/v3-flatcontainer/widget/1.2.3/widget.1.2.3.nupkg", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	tracker.Observe(WithRequestService(req, Service{
		ID:      "nuget-registration",
		Purpose: "metadata-enrichment",
		BaseURL: "https://mirror.example.test/v3/registration5-gz-semver2",
	}))

	used := tracker.Used()
	if len(used) != 1 {
		t.Fatalf("used = %#v", used)
	}
	if used[0].BaseURL != "https://packages.example.test" {
		t.Fatalf("base url = %#v", used[0])
	}
}

func TestTrackerIgnoresUnannotatedRequests(t *testing.T) {
	t.Parallel()

	tracker := NewTracker([]Service{
		{ID: "npm-registry", Purpose: "metadata-enrichment", BaseURL: "https://registry.npmjs.org"},
	})
	req, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/react/19.2.4", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	tracker.Observe(req)

	if used := tracker.Used(); len(used) != 0 {
		t.Fatalf("used = %#v", used)
	}
}
