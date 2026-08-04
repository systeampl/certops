package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type cfsslAPIResponse struct {
	Success  bool                   `json:"success"`
	Result   map[string]interface{} `json:"result"`
	Errors   []cfsslMessage         `json:"errors"`
	Messages []cfsslMessage         `json:"messages"`
}

func runCFSSL(action string, opts cfsslOptions) (cfsslReport, []byte, error) {
	opts.BaseURL = strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	report := cfsslReport{
		Provider: "cfssl",
		Action:   action,
		BaseURL:  opts.BaseURL,
		Label:    opts.Label,
		Profile:  opts.Profile,
		Status:   "ok",
	}

	var caPEM []byte
	var err error
	if action == "health" || action == "info" {
		report.Health = fetchCFSSLHealth(opts)
		if !report.Health.Healthy {
			report.Status = "critical"
			report.Findings = append(report.Findings, cfsslFinding{Severity: "critical", Message: "CFSSL health check failed: " + report.Health.Message})
		}
	}
	if action == "info" {
		report.CA, caPEM, report.Messages, report.Errors, err = fetchCFSSLInfo(opts)
		if err != nil {
			return report, nil, err
		}
		for _, finding := range validateCFSSLCA(report.CA) {
			report.Status = worseTrustStatus(report.Status, finding.Severity)
			report.Findings = append(report.Findings, finding)
		}
	}
	return report, caPEM, nil
}

func fetchCFSSLHealth(opts cfsslOptions) cfsslHealth {
	endpoint := opts.BaseURL + "/api/v1/cfssl/health"
	status, body, err := cfsslGet(endpoint, opts)
	health := cfsslHealth{Endpoint: endpoint, HTTPStatus: status}
	if err != nil {
		health.Message = err.Error()
		return health
	}
	health.Healthy = status >= 200 && status < 300 && cfsslSuccessBody(body)
	health.Message = strings.TrimSpace(string(body))
	return health
}

func fetchCFSSLInfo(opts cfsslOptions) (cfsslCA, []byte, []cfsslMessage, []cfsslMessage, error) {
	endpoint := opts.BaseURL + "/api/v1/cfssl/info"
	body := map[string]string{}
	if strings.TrimSpace(opts.Label) != "" {
		body["label"] = opts.Label
	}
	if strings.TrimSpace(opts.Profile) != "" {
		body["profile"] = opts.Profile
	}
	status, raw, err := cfsslPostJSON(endpoint, body, opts)
	ca := cfsslCA{Endpoint: endpoint, HTTPStatus: status, Fingerprint: opts.Fingerprint}
	if err != nil {
		return ca, nil, nil, nil, err
	}
	if status < 200 || status >= 300 {
		return ca, nil, nil, nil, fmt.Errorf("CFSSL info failed: HTTP %d", status)
	}
	var decoded cfsslAPIResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return ca, nil, nil, nil, err
	}
	if !decoded.Success {
		return ca, nil, decoded.Messages, decoded.Errors, fmt.Errorf("CFSSL info returned success=false")
	}
	certPEM, _ := decoded.Result["certificate"].(string)
	if strings.TrimSpace(certPEM) == "" {
		certPEM, _ = decoded.Result["cert"].(string)
	}
	if strings.TrimSpace(certPEM) == "" {
		return ca, nil, decoded.Messages, decoded.Errors, fmt.Errorf("CFSSL info response did not include certificate")
	}
	certs, _, err := parseTrustCerts([]byte(certPEM))
	if err != nil {
		return ca, nil, decoded.Messages, decoded.Errors, err
	}
	ca.Count = len(certs)
	for _, cert := range certs {
		ca.Certs = append(ca.Certs, cfsslCert{
			Subject:  cert.Subject,
			Issuer:   cert.Issuer,
			NotAfter: cert.NotAfter,
			DaysLeft: cert.DaysLeft,
			IsCA:     cert.IsCA,
			SHA256:   cert.SHA256,
		})
	}
	return ca, []byte(certPEM), decoded.Messages, decoded.Errors, nil
}

func cfsslGet(endpoint string, opts cfsslOptions) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := providerHTTPClient(opts.Timeout).Do(req)
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

func cfsslPostJSON(endpoint string, payload any, opts cfsslOptions) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := providerHTTPClient(opts.Timeout).Do(req)
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

func providerHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func cfsslSuccessBody(body []byte) bool {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return true
	}
	var decoded cfsslAPIResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return strings.Contains(strings.ToLower(string(body)), "ok")
	}
	return decoded.Success
}

func validateCFSSLCA(ca cfsslCA) []cfsslFinding {
	var findings []cfsslFinding
	if ca.Count == 0 {
		return append(findings, cfsslFinding{Severity: "critical", Message: "CFSSL info did not return a CA certificate"})
	}
	if strings.TrimSpace(ca.Fingerprint) != "" {
		matched := false
		for _, cert := range ca.Certs {
			if normalizeFingerprint(cert.SHA256) == normalizeFingerprint(ca.Fingerprint) {
				matched = true
			}
		}
		if !matched {
			findings = append(findings, cfsslFinding{Severity: "critical", Message: "expected CA fingerprint was not found"})
		}
	}
	for _, cert := range ca.Certs {
		if !cert.IsCA {
			findings = append(findings, cfsslFinding{Severity: "critical", Message: "CFSSL info returned a non-CA certificate: " + cert.Subject})
		}
		if cert.DaysLeft < 0 {
			findings = append(findings, cfsslFinding{Severity: "critical", Message: "CA certificate is expired: " + cert.Subject})
		} else if cert.DaysLeft < 30 {
			findings = append(findings, cfsslFinding{Severity: "warn", Message: "CA certificate expires soon: " + cert.Subject})
		}
	}
	return findings
}
