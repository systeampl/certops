package main

import "strings"

func runGenericCA(caBundle, rawURL, fingerprint string) (genericCAReport, []byte, error) {
	source, err := loadTrustSource(caBundle, rawURL, "", fingerprint)
	if err != nil {
		return genericCAReport{}, nil, err
	}
	certs, _, err := parseTrustCerts(source.PEM)
	if err != nil {
		return genericCAReport{}, nil, err
	}
	report := genericCAReport{
		Provider: "generic",
		Action:   "info",
		Source:   source.Label,
		Status:   "ok",
		CA:       genericCA{Count: len(certs), Fingerprint: fingerprint},
	}
	for _, cert := range certs {
		report.CA.Certs = append(report.CA.Certs, genericCACert{
			Subject:  cert.Subject,
			Issuer:   cert.Issuer,
			NotAfter: cert.NotAfter,
			DaysLeft: cert.DaysLeft,
			IsCA:     cert.IsCA,
			SHA256:   cert.SHA256,
		})
	}
	for _, finding := range validateGenericCA(report.CA) {
		report.Status = worseTrustStatus(report.Status, finding.Severity)
		report.Findings = append(report.Findings, finding)
	}
	return report, source.PEM, nil
}

func validateGenericCA(ca genericCA) []genericCAFinding {
	var findings []genericCAFinding
	if ca.Count == 0 {
		return append(findings, genericCAFinding{Severity: "critical", Message: "generic CA bundle is empty"})
	}
	if strings.TrimSpace(ca.Fingerprint) != "" {
		matched := false
		for _, cert := range ca.Certs {
			if normalizeFingerprint(cert.SHA256) == normalizeFingerprint(ca.Fingerprint) {
				matched = true
			}
		}
		if !matched {
			findings = append(findings, genericCAFinding{Severity: "critical", Message: "expected CA fingerprint was not found"})
		}
	}
	for _, cert := range ca.Certs {
		if !cert.IsCA {
			findings = append(findings, genericCAFinding{Severity: "critical", Message: "bundle contains a non-CA certificate: " + cert.Subject})
		}
		if cert.DaysLeft < 0 {
			findings = append(findings, genericCAFinding{Severity: "critical", Message: "CA certificate is expired: " + cert.Subject})
		} else if cert.DaysLeft < 30 {
			findings = append(findings, genericCAFinding{Severity: "warn", Message: "CA certificate expires soon: " + cert.Subject})
		}
	}
	return findings
}
