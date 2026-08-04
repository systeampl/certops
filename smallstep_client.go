package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func runSmallstep(action, baseURL, fingerprint string, timeout time.Duration, insecure bool) (smallstepReport, []byte, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	report := smallstepReport{
		Provider: "smallstep",
		Action:   action,
		BaseURL:  baseURL,
		Insecure: insecure,
		Status:   "ok",
	}

	var rootsPEM []byte
	var err error
	if action == "health" || action == "info" {
		report.Health = fetchSmallstepHealth(baseURL, timeout, insecure)
		if !report.Health.Healthy {
			report.Status = "critical"
			report.Findings = append(report.Findings, smallstepFinding{Severity: "critical", Message: "Smallstep health check failed"})
		}
	}
	if action == "roots" || action == "info" {
		report.Roots, rootsPEM, err = fetchSmallstepRoots(baseURL, fingerprint, timeout, insecure)
		if err != nil {
			return report, nil, err
		}
		for _, finding := range validateSmallstepRoots(report.Roots) {
			report.Status = worseTrustStatus(report.Status, finding.Severity)
			report.Findings = append(report.Findings, finding)
		}
	}
	return report, rootsPEM, nil
}

func fetchSmallstepHealth(baseURL string, timeout time.Duration, insecure bool) smallstepHealth {
	endpoint := baseURL + "/health"
	status, body, err := httpGet(endpoint, timeout, insecure)
	health := smallstepHealth{Endpoint: endpoint, HTTPStatus: status}
	if err != nil {
		health.Message = err.Error()
		return health
	}
	health.Message = strings.TrimSpace(string(body))
	health.Healthy = status >= 200 && status < 300 && smallstepHealthBodyOK(body)
	return health
}

func fetchSmallstepRoots(baseURL, fingerprint string, timeout time.Duration, insecure bool) (smallstepRoots, []byte, error) {
	endpoint := baseURL + "/roots.pem"
	status, body, err := httpGet(endpoint, timeout, insecure)
	roots := smallstepRoots{Endpoint: endpoint, HTTPStatus: status, Fingerprint: fingerprint}
	if err != nil {
		return roots, nil, err
	}
	if status < 200 || status >= 300 {
		return roots, nil, fmt.Errorf("Smallstep roots fetch failed: HTTP %d", status)
	}
	certs, _, err := parseTrustCerts(body)
	if err != nil {
		return roots, nil, err
	}
	roots.Count = len(certs)
	for _, cert := range certs {
		roots.Certs = append(roots.Certs, smallstepCert{
			Subject:  cert.Subject,
			Issuer:   cert.Issuer,
			NotAfter: cert.NotAfter,
			DaysLeft: cert.DaysLeft,
			IsCA:     cert.IsCA,
			SHA256:   cert.SHA256,
		})
	}
	return roots, body, nil
}

func httpGet(endpoint string, timeout time.Duration, insecure bool) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if insecure {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, 2<<20)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

func smallstepHealthBodyOK(body []byte) bool {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return true
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return strings.Contains(strings.ToLower(string(body)), "ok")
	}
	for _, key := range []string{"status", "message"} {
		if value, ok := decoded[key].(string); ok && strings.EqualFold(value, "ok") {
			return true
		}
	}
	if value, ok := decoded["ok"].(bool); ok {
		return value
	}
	return false
}

func validateSmallstepRoots(roots smallstepRoots) []smallstepFinding {
	var findings []smallstepFinding
	if roots.Count == 0 {
		return append(findings, smallstepFinding{Severity: "critical", Message: "Smallstep roots bundle is empty"})
	}
	if strings.TrimSpace(roots.Fingerprint) != "" {
		matched := false
		for _, cert := range roots.Certs {
			if normalizeFingerprint(cert.SHA256) == normalizeFingerprint(roots.Fingerprint) {
				matched = true
			}
		}
		if !matched {
			findings = append(findings, smallstepFinding{Severity: "critical", Message: "expected root fingerprint was not found"})
		}
	}
	for _, cert := range roots.Certs {
		if !cert.IsCA {
			findings = append(findings, smallstepFinding{Severity: "critical", Message: "root bundle contains a non-CA certificate: " + cert.Subject})
		}
		if cert.DaysLeft < 0 {
			findings = append(findings, smallstepFinding{Severity: "critical", Message: "root certificate is expired: " + cert.Subject})
		} else if cert.DaysLeft < 30 {
			findings = append(findings, smallstepFinding{Severity: "warn", Message: "root certificate expires soon: " + cert.Subject})
		}
	}
	return findings
}
