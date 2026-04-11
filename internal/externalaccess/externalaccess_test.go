package externalaccess

import "testing"

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
