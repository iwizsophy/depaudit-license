package externalaccess

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type requestServiceContextKey struct{}

type Tracker struct {
	mu         sync.Mutex
	configured map[string]Service
	used       map[string]Service
}

func NewTracker(configured []Service) *Tracker {
	normalized := Normalize(configured)
	byKey := make(map[string]Service, len(normalized))
	for _, service := range normalized {
		byKey[serviceIdentityKey(service.ID, service.Purpose)] = service
	}
	return &Tracker{
		configured: byKey,
		used:       map[string]Service{},
	}
}

func WithRequestService(req *http.Request, service Service) *http.Request {
	if req == nil {
		return nil
	}
	return req.WithContext(context.WithValue(req.Context(), requestServiceContextKey{}, service))
}

func RequestService(req *http.Request) (Service, bool) {
	if req == nil {
		return Service{}, false
	}
	value, ok := req.Context().Value(requestServiceContextKey{}).(Service)
	if !ok {
		return Service{}, false
	}
	return value, true
}

func (t *Tracker) Observe(req *http.Request) {
	if t == nil || req == nil {
		return
	}

	observed, ok := RequestService(req)
	if !ok {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	configured := t.configured[serviceIdentityKey(observed.ID, observed.Purpose)]
	resolved := mergeObservedService(configured, observed, req.URL)
	if resolved.ID == "" || resolved.Purpose == "" || resolved.BaseURL == "" {
		return
	}
	t.used[serviceRecordKey(resolved)] = resolved
}

func (t *Tracker) Used() []Service {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	values := make([]Service, 0, len(t.used))
	for _, service := range t.used {
		values = append(values, service)
	}
	return Normalize(values)
}

func mergeObservedService(configured Service, observed Service, requestURL *url.URL) Service {
	result := Service{
		ID:             firstNonEmpty(observed.ID, configured.ID),
		Purpose:        firstNonEmpty(observed.Purpose, configured.Purpose),
		AuthConfigured: observed.AuthConfigured || configured.AuthConfigured,
		CacheMode:      firstNonEmpty(observed.CacheMode, configured.CacheMode),
		CacheTTL:       firstNonEmpty(observed.CacheTTL, configured.CacheTTL),
	}
	hintedBaseURL := firstNonEmpty(observed.BaseURL, configured.BaseURL)
	result.BaseURL = resolveObservedBaseURL(requestURL, hintedBaseURL)
	return result
}

func resolveObservedBaseURL(requestURL *url.URL, hintedBaseURL string) string {
	hintedBaseURL = strings.TrimRight(strings.TrimSpace(hintedBaseURL), "/")
	if requestURL == nil {
		return hintedBaseURL
	}

	requestValue := strings.TrimRight(strings.TrimSpace(requestURL.String()), "/")
	if hintedBaseURL != "" && strings.HasPrefix(requestValue, hintedBaseURL) {
		return hintedBaseURL
	}

	origin := OriginFromURL(requestValue)
	if origin != "" {
		return origin
	}
	return hintedBaseURL
}

func OriginFromURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	if strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme) + "://" + parsed.Host
}

func serviceIdentityKey(id string, purpose string) string {
	return strings.ToLower(strings.TrimSpace(id)) + "\x00" + strings.ToLower(strings.TrimSpace(purpose))
}

func serviceRecordKey(service Service) string {
	return serviceIdentityKey(service.ID, service.Purpose) + "\x00" + strings.TrimSpace(service.BaseURL)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
