package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	checker "github.com/systeampl/certops/internal/check"
	crlcheck "github.com/systeampl/certops/internal/crl"
)

func livePlanItems(cfg certopsConfig, opts planOptions) []planItem {
	items := []planItem{}
	rootDir, err := os.MkdirTemp("", "certops-plan-roots-*")
	if err != nil {
		return []planItem{{Action: "fail", Scope: "live", Target: "roots", Status: "critical", Change: "could not create temporary root directory", Actual: err.Error()}}
	}
	defer os.RemoveAll(rootDir)

	rootPaths := map[string]string{}
	for _, ca := range cfg.CAs {
		item, path := liveCAPlanItem(ca, rootDir, cfg)
		items = append(items, item)
		if path != "" {
			rootPaths[ca.Name] = path
		}
	}
	for _, crl := range cfg.CRLs {
		items = append(items, liveCRLPlanItem(crl, cfg, rootPaths, opts.Timeout))
	}
	for _, service := range cfg.Services {
		items = append(items, liveServicePlanItem(service, cfg, rootPaths, opts.Timeout))
	}
	return items
}

func liveCRLPlanItem(config configCRL, cfg certopsConfig, rootPaths map[string]string, timeout time.Duration) planItem {
	item := planItem{Action: "verify", Scope: "crl-live", Target: config.Name, Status: "ok"}
	source := configuredCRLSource(config)
	if strings.TrimSpace(source) == "" {
		item.Status = "critical"
		item.Change = "CRL live check target is invalid"
		item.Actual = "missing file or url"
		return item
	}
	report := crlcheck.Run(context.Background(), crlcheck.Options{
		Name:         config.Name,
		Source:       source,
		CABundle:     rootPaths[config.CA],
		WarnDays:     crlWarnDays(config, cfg),
		CriticalDays: crlCriticalDays(config),
		MaxAgeDays:   crlMaxAgeDays(config, cfg),
		Timeout:      timeout,
		Insecure:     config.Insecure,
	})
	item.Status = report.Status
	item.Change = fmt.Sprintf("CRL live check %s", report.Status)
	item.Actual = liveCRLActual(report)
	return item
}

func liveCAPlanItem(ca configCA, rootDir string, cfg certopsConfig) (planItem, string) {
	item := planItem{Action: "verify", Scope: "ca-live", Target: ca.Name, Status: "ok"}
	pemData, count, err := configuredCAPEM(ca)
	if err != nil {
		item.Status = "critical"
		item.Change = "CA live check failed"
		item.Actual = err.Error()
		return item, ""
	}
	certs, _, err := parseTrustCerts(pemData)
	if err != nil {
		item.Status = "critical"
		item.Change = "CA live check could not parse fetched bundle"
		item.Actual = err.Error()
		return item, ""
	}
	path := filepath.Join(rootDir, sanitizeTrustName(ca.Name)+".pem")
	if err := writeFileAtomic(path, pemData, 0644); err != nil {
		item.Status = "critical"
		item.Change = "CA live check could not write temporary bundle"
		item.Actual = err.Error()
		return item, ""
	}
	item.Change = fmt.Sprintf("CA live check ok, fetched %d certs", count)
	item.Actual = liveCAActual(certs)
	if policyMinCADays(cfg) > 0 {
		minDays := minTrustCertDays(certs)
		item.Expected = fmt.Sprintf(">= %d days remaining", policyMinCADays(cfg))
		switch {
		case hasExpiredTrustCert(certs):
			item.Status = "critical"
			item.Change = "CA live check found expired CA certificate"
		case minDays < policyMinCADays(cfg):
			item.Status = "warn"
			item.Change = "CA live check found CA certificate below policy threshold"
		}
	}
	return item, path
}

func liveServicePlanItem(service configService, cfg certopsConfig, rootPaths map[string]string, timeout time.Duration) planItem {
	targetName := servicePlanTarget(service)
	item := planItem{Action: "verify", Scope: "service-live", Target: targetName, Status: "ok"}
	host, address, err := serviceCheckEndpoint(service, cfg)
	if err != nil {
		item.Status = "critical"
		item.Change = "service live check target is invalid"
		item.Actual = err.Error()
		return item
	}
	report := checker.Run(context.Background(), host, address, checker.Options{
		WarnDays:           policyWarnDays(cfg),
		CriticalDays:       14,
		Timeout:            timeout,
		CABundle:           rootPaths[service.CA],
		CRLSources:         serviceCRLSources(service, cfg),
		CRLCABundle:        rootPaths[service.CA],
		CRLWarnDays:        policyCRLWarnDays(cfg),
		CRLMaxAgeDays:      cfg.Policy.MaxCRLAgeDays,
		AutoCRL:            service.AutoCRL,
		CRLInsecureSources: serviceCRLInsecureSources(service, cfg),
	})
	effectiveService := service
	if effectiveService.MinDaysRemaining == 0 {
		effectiveService.MinDaysRemaining = cfg.Policy.MinLeafDaysRemaining
	}
	policyFindings := servicePolicyFindings(effectiveService, report)
	item.Status = planStatusFromCheckStatus(statusWithPolicyFindings(report.Status, policyFindings))
	item.Change = fmt.Sprintf("service live check %s", item.Status)
	item.Actual = liveServiceActual(report, policyFindings)
	return item
}

func configuredCRLSource(config configCRL) string {
	if strings.TrimSpace(config.URL) != "" {
		return config.URL
	}
	return strings.TrimSpace(config.File)
}

func serviceCRLSources(service configService, cfg certopsConfig) []string {
	byName := map[string]configCRL{}
	for _, config := range cfg.CRLs {
		byName[config.Name] = config
	}
	out := make([]string, 0, len(service.CRLs))
	for _, name := range service.CRLs {
		if config, ok := byName[name]; ok {
			if source := configuredCRLSource(config); source != "" {
				out = append(out, source)
			}
		}
	}
	return out
}

func serviceCRLInsecureSources(service configService, cfg certopsConfig) map[string]bool {
	byName := map[string]configCRL{}
	for _, config := range cfg.CRLs {
		byName[config.Name] = config
	}
	out := map[string]bool{}
	for _, name := range service.CRLs {
		if config, ok := byName[name]; ok && config.Insecure {
			out[configuredCRLSource(config)] = true
		}
	}
	return out
}

func servicePlanTarget(service configService) string {
	if service.Name != "" {
		return service.Name
	}
	if service.URL != "" {
		return service.URL
	}
	return service.Host
}

func serviceCheckEndpoint(service configService, cfg certopsConfig) (string, string, error) {
	if strings.TrimSpace(service.URL) != "" {
		host, address, err := normalizeTarget(service.URL)
		if err != nil {
			return "", "", err
		}
		if strings.TrimSpace(service.ServerName) != "" {
			host, err = normalizeServerName(service.ServerName)
			if err != nil {
				return "", "", err
			}
		}
		return host, address, nil
	}
	if strings.TrimSpace(service.Host) == "" {
		return "", "", fmt.Errorf("service has no url or host")
	}
	identity := service.Host
	connectHost := service.Host
	if inventoryHost, ok := findInventoryHost(cfg, service.Host); ok {
		connectHost = inventoryHost.Address
	}
	port := service.Port
	if port == "" {
		port = "443"
	}
	address, err := normalizeConnect(connectHost, port)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(service.ServerName) != "" {
		identity = service.ServerName
	}
	identity, err = normalizeServerName(identity)
	if err != nil {
		return "", "", err
	}
	return identity, address, nil
}

func findInventoryHost(cfg certopsConfig, name string) (configHost, bool) {
	for _, group := range cfg.Inventory.Groups {
		if host, ok := group.Hosts[name]; ok {
			return host, true
		}
	}
	return configHost{}, false
}

func policyWarnDays(cfg certopsConfig) int {
	if cfg.Policy.MinLeafDaysRemaining > 0 {
		return cfg.Policy.MinLeafDaysRemaining
	}
	return 30
}

func policyMinCADays(cfg certopsConfig) int {
	return cfg.Policy.MinCADaysRemaining
}

func policyCRLWarnDays(cfg certopsConfig) int {
	if cfg.Policy.MinCRLDaysRemaining > 0 {
		return cfg.Policy.MinCRLDaysRemaining
	}
	return 3
}

func crlWarnDays(config configCRL, cfg certopsConfig) int {
	if config.WarnDays > 0 {
		return config.WarnDays
	}
	return policyCRLWarnDays(cfg)
}

func crlCriticalDays(config configCRL) int {
	if config.CriticalDays > 0 {
		return config.CriticalDays
	}
	return 1
}

func crlMaxAgeDays(config configCRL, cfg certopsConfig) int {
	if config.MaxAgeDays > 0 {
		return config.MaxAgeDays
	}
	return cfg.Policy.MaxCRLAgeDays
}

func planStatusFromCheckStatus(status string) string {
	switch status {
	case "ok", "warn":
		return status
	default:
		return "critical"
	}
}

func liveServiceActual(report checker.Report, policyFindings []checker.Finding) string {
	if report.Error != "" {
		return report.Error
	}
	actual := fmt.Sprintf("issuer=%s expires_in=%d days", shortIssuer(report.Certificate.Issuer), report.Certificate.DaysRemaining)
	if len(policyFindings) > 0 {
		actual += "; policy=" + policyFindings[0].Message
		if len(policyFindings) > 1 {
			actual += fmt.Sprintf(" (+%d more)", len(policyFindings)-1)
		}
	}
	return actual
}

func liveCRLActual(report crlcheck.Report) string {
	if report.Error != "" {
		return report.Error
	}
	signature := "unchecked"
	if report.SignatureChecked {
		signature = "invalid"
		if report.SignatureValid {
			signature = "valid"
		}
	}
	return fmt.Sprintf("issuer=%s next_update_in=%d days revoked=%d signature=%s number=%s", shortIssuer(report.Issuer), report.DaysRemaining, report.RevokedCertificates, signature, emptyDash(report.Number))
}

func liveCAActual(certs []trustCert) string {
	minDays := minTrustCertDays(certs)
	if minDays == 0 && len(certs) == 0 {
		return "temporary bundle fetched"
	}
	return fmt.Sprintf("fetched=%d min_expires_in=%d days", len(certs), minDays)
}

func minTrustCertDays(certs []trustCert) int {
	if len(certs) == 0 {
		return 0
	}
	minDays := certs[0].DaysLeft
	for _, cert := range certs[1:] {
		if cert.DaysLeft < minDays {
			minDays = cert.DaysLeft
		}
	}
	return minDays
}

func hasExpiredTrustCert(certs []trustCert) bool {
	now := time.Now()
	for _, cert := range certs {
		notAfter, err := time.Parse(time.RFC3339, cert.NotAfter)
		if err == nil && !notAfter.After(now) {
			return true
		}
	}
	return false
}

func servicePolicyFindings(service configService, report checker.Report) []checker.Finding {
	var findings []checker.Finding
	if service.MinDaysRemaining > 0 && report.Certificate.DaysRemaining < service.MinDaysRemaining {
		findings = append(findings, checker.Finding{Severity: "critical", Scope: "policy", Message: fmt.Sprintf("certificate has %d days remaining, expected at least %d", report.Certificate.DaysRemaining, service.MinDaysRemaining)})
	}
	if service.RequireTLS13 && !hasString(report.TLS.SupportedVersions, "TLS1.3") {
		findings = append(findings, checker.Finding{Severity: "critical", Scope: "policy", Message: "TLS 1.3 is required but not supported"})
	}
	if service.RequireHSTS && !report.HTTPS.HSTSEnabled {
		findings = append(findings, checker.Finding{Severity: "critical", Scope: "policy", Message: "HSTS is required but missing"})
	}
	if service.ForbidTLS10 && hasString(report.TLS.SupportedVersions, "TLS1.0") {
		findings = append(findings, checker.Finding{Severity: "critical", Scope: "policy", Message: "TLS 1.0 is forbidden but supported"})
	}
	if service.ForbidTLS11 && hasString(report.TLS.SupportedVersions, "TLS1.1") {
		findings = append(findings, checker.Finding{Severity: "critical", Scope: "policy", Message: "TLS 1.1 is forbidden but supported"})
	}
	for _, name := range service.ExpectedNames {
		if !hasString(report.Certificate.DNSNames, name) {
			findings = append(findings, checker.Finding{Severity: "critical", Scope: "policy", Message: "expected DNS name missing from SAN: " + name})
		}
	}
	if len(service.AllowedIssuers) > 0 && !containsAnyFold(report.Certificate.Issuer, service.AllowedIssuers) {
		findings = append(findings, checker.Finding{Severity: "critical", Scope: "policy", Message: "issuer is not allowed: " + report.Certificate.Issuer})
	}
	return findings
}

func statusWithPolicyFindings(base string, findings []checker.Finding) string {
	status := base
	if status == "" {
		status = "ok"
	}
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			return "critical"
		case "warn":
			if status == "ok" {
				status = "warn"
			}
		}
	}
	return status
}

func containsAnyFold(value string, wants []string) bool {
	value = strings.ToLower(value)
	for _, want := range wants {
		if strings.Contains(value, strings.ToLower(strings.TrimSpace(want))) {
			return true
		}
	}
	return false
}
