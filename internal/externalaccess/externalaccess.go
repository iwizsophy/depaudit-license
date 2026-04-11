package externalaccess

import (
	"sort"
	"strings"
)

type Service struct {
	ID             string `json:"id"`
	Purpose        string `json:"purpose"`
	BaseURL        string `json:"baseUrl"`
	AuthConfigured bool   `json:"authConfigured,omitempty"`
	CacheMode      string `json:"cacheMode,omitempty"`
	CacheTTL       string `json:"cacheTtl,omitempty"`
}

func Normalize(values []Service) []Service {
	if len(values) == 0 {
		return nil
	}

	type key struct {
		id      string
		purpose string
		baseURL string
	}
	seen := map[key]struct{}{}
	result := make([]Service, 0, len(values))
	for _, value := range values {
		normalized := Service{
			ID:             strings.TrimSpace(value.ID),
			Purpose:        strings.TrimSpace(value.Purpose),
			BaseURL:        strings.TrimSpace(value.BaseURL),
			AuthConfigured: value.AuthConfigured,
			CacheMode:      strings.TrimSpace(value.CacheMode),
			CacheTTL:       strings.TrimSpace(value.CacheTTL),
		}
		if normalized.ID == "" || normalized.Purpose == "" || normalized.BaseURL == "" {
			continue
		}
		k := key{id: normalized.ID, purpose: normalized.Purpose, baseURL: normalized.BaseURL}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		result = append(result, normalized)
	}

	sort.Slice(result, func(i, j int) bool {
		left := result[i]
		right := result[j]
		switch {
		case left.Purpose != right.Purpose:
			return left.Purpose < right.Purpose
		case left.ID != right.ID:
			return left.ID < right.ID
		default:
			return left.BaseURL < right.BaseURL
		}
	})
	return result
}
