package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ThreatProvider defines the interface for external threat intelligence sources
type ThreatProvider interface {
	CheckDomain(ctx context.Context, domain string) (int32, []string, error)
	Name() string
}

// DarkAPIProvider implements ThreatProvider for darkapi.io
type DarkAPIProvider struct {
	apiKey     string
	httpClient *http.Client
}

// NewDarkAPIProvider creates a new DarkAPI provider
func NewDarkAPIProvider(apiKey string) *DarkAPIProvider {
	return &DarkAPIProvider{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 2 * time.Second, // Fast timeout for real-time checks
		},
	}
}

func (p *DarkAPIProvider) Name() string {
	return "darkapi.io"
}

// CheckDomain queries darkapi.io for domain reputation
func (p *DarkAPIProvider) CheckDomain(ctx context.Context, domain string) (int32, []string, error) {
	if p.apiKey == "" {
		return 0, nil, nil
	}

	// Mocking the URL structure as per typical API standards since strict docs aren't provided
	// Assuming GET https://darkapi.io/api/v1/reputation?query=domain
	u := fmt.Sprintf("https://darkapi.io/api/v1/reputation?query=%s", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, nil, nil // Not found = benign usually
	}

	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("provider %s failed with status %d", p.Name(), resp.StatusCode)
	}

	var result struct {
		RiskScore  int      `json:"risk_score"` // 0-100
		Categories []string `json:"categories"`
		Verdict    string   `json:"verdict"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, nil, err
	}

	return int32(result.RiskScore), result.Categories, nil
}

// AggregateProvider combines multiple providers
type AggregateProvider struct {
	providers []ThreatProvider
}

// NewAggregateProvider creates a new aggregator
func NewAggregateProvider(providers ...ThreatProvider) *AggregateProvider {
	return &AggregateProvider{
		providers: providers,
	}
}

// CheckDomain queries all providers and returns the highest score
// Concurrent execution with "fail open" policy
func (ap *AggregateProvider) CheckDomain(ctx context.Context, domain string) (int32, []string, error) {
	var maxScore int32
	var allCategories []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ap.providers {
		wg.Add(1)
		go func(p ThreatProvider) {
			defer wg.Done()
			score, cats, err := p.CheckDomain(ctx, domain)
			if err != nil {
				// Log error but don't fail the aggregation
				// logging.Logger.Warn("Provider failed", zap.String("provider", p.Name()), zap.Error(err))
				return
			}

			mu.Lock()
			if score > maxScore {
				maxScore = score
			}
			allCategories = append(allCategories, cats...)
			mu.Unlock()
		}(p)
	}

	wg.Wait()

	// Dedup categories
	uniqueCats := make(map[string]struct{})
	var finalCats []string
	for _, c := range allCategories {
		if _, ok := uniqueCats[c]; !ok {
			uniqueCats[c] = struct{}{}
			finalCats = append(finalCats, c)
		}
	}

	return maxScore, finalCats, nil
}

func (ap *AggregateProvider) Name() string {
	return "aggregate"
}
