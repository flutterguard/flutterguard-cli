package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PubDevClient interacts with pub.dev API
type PubDevClient struct {
	httpClient *http.Client
	baseURL    string
}

// PubDevPackageScore represents package metrics from pub.dev
type PubDevPackageScore struct {
	GrantedPoints       int      `json:"grantedPoints"`
	MaxPoints           int      `json:"maxPoints"`
	LikeCount           int      `json:"likeCount"`
	DownloadCount30Days int      `json:"downloadCount30Days"`
	Tags                []string `json:"tags"`
}

// PubDevPackageInfo represents package information from pub.dev
type PubDevPackageInfo struct {
	Name        string `json:"name"`
	Latest      struct {
		Version string `json:"version"`
		Pubspec struct {
			Description string `json:"description"`
			Homepage    string `json:"homepage"`
			Repository  string `json:"repository"`
		} `json:"pubspec"`
	} `json:"latest"`
}

func NewPubDevClient() *PubDevClient {
	return &PubDevClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		baseURL: "https://pub.dev/api",
	}
}

// GetPackageScore fetches package scores and metrics from pub.dev
func (c *PubDevClient) GetPackageScore(ctx context.Context, packageName string) (*PubDevPackageScore, error) {
	url := fmt.Sprintf("%s/packages/%s/score", c.baseURL, packageName)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package score: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pub.dev API returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	var score PubDevPackageScore
	if err := json.Unmarshal(body, &score); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	return &score, nil
}

// GetPackageInfo fetches package information from pub.dev
func (c *PubDevClient) GetPackageInfo(ctx context.Context, packageName string) (*PubDevPackageInfo, error) {
	url := fmt.Sprintf("%s/packages/%s", c.baseURL, packageName)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pub.dev API returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	var info PubDevPackageInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	return &info, nil
}

// EnrichPackages enriches package list with pub.dev metrics
func (c *PubDevClient) EnrichPackages(ctx context.Context, packages []string) map[string]*PubDevPackageScore {
	results := make(map[string]*PubDevPackageScore)
	
	// Limit concurrent requests
	semaphore := make(chan struct{}, 5)
	resultChan := make(chan struct {
		name  string
		score *PubDevPackageScore
	}, len(packages))
	
	for _, pkg := range packages {
		go func(packageName string) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			score, err := c.GetPackageScore(ctx, packageName)
			if err == nil {
				resultChan <- struct {
					name  string
					score *PubDevPackageScore
				}{packageName, score}
			}
		}(pkg)
	}
	
	// Wait for all requests or timeout
	timeout := time.After(30 * time.Second)
	collected := 0
	
	for collected < len(packages) {
		select {
		case result := <-resultChan:
			results[result.name] = result.score
			collected++
		case <-timeout:
			return results
		case <-ctx.Done():
			return results
		}
	}
	
	return results
}
