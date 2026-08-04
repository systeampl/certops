package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func runVault(action string, opts vaultOptions) (vaultReport, []byte, error) {
	opts.BaseURL = strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	opts.Mount = strings.Trim(strings.TrimSpace(opts.Mount), "/")
	if opts.Mount == "" {
		opts.Mount = "pki"
	}
	report := vaultReport{
		Provider: "vault",
		Action:   action,
		BaseURL:  opts.BaseURL,
		Mount:    opts.Mount,
		Issuer:   opts.Issuer,
		Status:   "ok",
	}

	var caPEM []byte
	var err error
	if action == "health" || action == "info" {
		report.Health = fetchVaultHealth(opts)
		if !report.Health.Healthy {
			report.Status = "critical"
			report.Findings = append(report.Findings, vaultFinding{Severity: "critical", Message: "Vault health check failed: " + report.Health.Message})
		}
	}
	if action == "ca" || action == "info" {
		report.CA, caPEM, err = fetchVaultCA(opts)
		if err != nil {
			return report, nil, err
		}
		for _, finding := range validateVaultCA(report.CA) {
			report.Status = worseTrustStatus(report.Status, finding.Severity)
			report.Findings = append(report.Findings, finding)
		}
	}
	return report, caPEM, nil
}

func fetchVaultHealth(opts vaultOptions) vaultHealth {
	endpoint := opts.BaseURL + "/v1/sys/health"
	status, body, err := vaultGet(endpoint, opts)
	health := vaultHealth{Endpoint: endpoint, HTTPStatus: status}
	if err != nil {
		health.Message = err.Error()
		return health
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		health.Message = strings.TrimSpace(string(body))
		health.Healthy = status >= 200 && status < 300
		return health
	}
	health.Initialized = boolField(decoded, "initialized")
	health.Sealed = boolField(decoded, "sealed")
	health.Standby = boolField(decoded, "standby") || boolField(decoded, "performance_standby")
	health.Version = stringField(decoded, "version")
	health.Healthy = status == 200 || (opts.StandbyOK && status == 429 && health.Initialized && !health.Sealed)
	health.Message = vaultHealthMessage(status, health)
	return health
}

func fetchVaultCA(opts vaultOptions) (vaultCA, []byte, error) {
	endpoint := vaultCAEndpoint(opts)
	status, body, err := vaultGet(endpoint, opts)
	ca := vaultCA{Endpoint: endpoint, HTTPStatus: status, Fingerprint: opts.Fingerprint}
	if err != nil {
		return ca, nil, err
	}
	if status < 200 || status >= 300 {
		return ca, nil, fmt.Errorf("vault CA fetch failed: HTTP %d", status)
	}
	certs, _, err := parseTrustCerts(body)
	if err != nil {
		return ca, nil, err
	}
	ca.Count = len(certs)
	for _, cert := range certs {
		ca.Certs = append(ca.Certs, vaultCert{
			Subject:  cert.Subject,
			Issuer:   cert.Issuer,
			NotAfter: cert.NotAfter,
			DaysLeft: cert.DaysLeft,
			IsCA:     cert.IsCA,
			SHA256:   cert.SHA256,
		})
	}
	return ca, body, nil
}

func vaultCAEndpoint(opts vaultOptions) string {
	if strings.TrimSpace(opts.Issuer) != "" {
		return opts.BaseURL + "/v1/" + opts.Mount + "/issuer/" + strings.Trim(strings.TrimSpace(opts.Issuer), "/") + "/pem"
	}
	return opts.BaseURL + "/v1/" + opts.Mount + "/ca/pem"
}

func vaultGet(endpoint string, opts vaultOptions) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	if strings.TrimSpace(opts.Token) != "" {
		req.Header.Set("X-Vault-Token", opts.Token)
	}
	if strings.TrimSpace(opts.Namespace) != "" {
		req.Header.Set("X-Vault-Namespace", opts.Namespace)
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

func validateVaultCA(ca vaultCA) []vaultFinding {
	var findings []vaultFinding
	if ca.Count == 0 {
		return append(findings, vaultFinding{Severity: "critical", Message: "Vault CA bundle is empty"})
	}
	if strings.TrimSpace(ca.Fingerprint) != "" {
		matched := false
		for _, cert := range ca.Certs {
			if normalizeFingerprint(cert.SHA256) == normalizeFingerprint(ca.Fingerprint) {
				matched = true
			}
		}
		if !matched {
			findings = append(findings, vaultFinding{Severity: "critical", Message: "expected CA fingerprint was not found"})
		}
	}
	for _, cert := range ca.Certs {
		if !cert.IsCA {
			findings = append(findings, vaultFinding{Severity: "critical", Message: "CA endpoint returned a non-CA certificate: " + cert.Subject})
		}
		if cert.DaysLeft < 0 {
			findings = append(findings, vaultFinding{Severity: "critical", Message: "CA certificate is expired: " + cert.Subject})
		} else if cert.DaysLeft < 30 {
			findings = append(findings, vaultFinding{Severity: "warn", Message: "CA certificate expires soon: " + cert.Subject})
		}
	}
	return findings
}

func vaultHealthMessage(status int, health vaultHealth) string {
	switch {
	case status == 200:
		return "active"
	case status == 429:
		return "standby"
	case status == 501:
		return "not initialized"
	case status == 503:
		return "sealed"
	case health.Sealed:
		return "sealed"
	default:
		return fmt.Sprintf("HTTP %d", status)
	}
}

func boolField(values map[string]interface{}, key string) bool {
	value, _ := values[key].(bool)
	return value
}

func stringField(values map[string]interface{}, key string) string {
	value, _ := values[key].(string)
	return value
}
