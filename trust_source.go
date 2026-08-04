package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func loadTrustSource(caBundle, rawURL, smallstepURL, fingerprint string) (trustSource, error) {
	sources := 0
	for _, value := range []string{caBundle, rawURL, smallstepURL} {
		if strings.TrimSpace(value) != "" {
			sources++
		}
	}
	if sources != 1 {
		return trustSource{}, fmt.Errorf("provide exactly one source: --ca-bundle, --url, or --smallstep-url")
	}
	if strings.TrimSpace(caBundle) != "" {
		data, err := os.ReadFile(caBundle)
		if err != nil {
			return trustSource{}, err
		}
		return trustSource{Label: caBundle, PEM: data}, nil
	}
	if strings.TrimSpace(smallstepURL) != "" {
		rawURL = strings.TrimRight(strings.TrimSpace(smallstepURL), "/") + "/roots.pem"
	}
	if strings.TrimSpace(fingerprint) == "" {
		return trustSource{}, fmt.Errorf("--fingerprint is required when fetching CA material from URL")
	}
	if err := validateFingerprint(fingerprint); err != nil {
		return trustSource{}, err
	}
	if err := validateHTTPURL(rawURL); err != nil {
		return trustSource{}, err
	}
	data, err := fetchPEM(rawURL)
	if err != nil {
		return trustSource{}, err
	}
	_, rawCerts, err := parseTrustCerts(data)
	if err != nil {
		return trustSource{}, err
	}
	if !fingerprintMatches(rawCerts, fingerprint) {
		return trustSource{}, fmt.Errorf("no fetched certificate matches fingerprint %s", fingerprint)
	}
	return trustSource{Label: rawURL, PEM: data}, nil
}

func fetchPEM(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimSpace(rawURL), nil)
	if err != nil {
		return nil, err
	}
	resp, err := providerHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch failed: %s", resp.Status)
	}
	data, err := readLimited(resp.Body, 2<<20)
	if err != nil {
		return nil, err
	}
	return data, nil
}
