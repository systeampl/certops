package verify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	checker "github.com/pawel-cygal/certops/internal/check"

	"gopkg.in/yaml.v3"
)

type Spec struct {
	Defaults Defaults `yaml:"defaults" json:"defaults"`
	Targets  []Target `yaml:"targets" json:"targets"`
}

type Defaults struct {
	WarnDays        int    `yaml:"warn_days" json:"warn_days"`
	CriticalDays    int    `yaml:"critical_days" json:"critical_days"`
	Timeout         string `yaml:"timeout" json:"timeout"`
	CABundle        string `yaml:"ca_bundle" json:"ca_bundle"`
	CRLCABundle     string `yaml:"crl_ca_bundle" json:"crl_ca_bundle"`
	CRLWarnDays     int    `yaml:"crl_warn_days" json:"crl_warn_days"`
	CRLCriticalDays int    `yaml:"crl_critical_days" json:"crl_critical_days"`
	CRLMaxAgeDays   int    `yaml:"crl_max_age_days" json:"crl_max_age_days"`
}

type Target struct {
	Name             string   `yaml:"name" json:"name"`
	Host             string   `yaml:"host" json:"host"`
	Port             string   `yaml:"port" json:"port"`
	URL              string   `yaml:"url" json:"url"`
	ServerName       string   `yaml:"server_name" json:"server_name"`
	Connect          string   `yaml:"connect" json:"connect"`
	AutoCRL          bool     `yaml:"auto_crl" json:"auto_crl"`
	CRLs             []string `yaml:"crls" json:"crls"`
	CRLCABundle      string   `yaml:"crl_ca_bundle" json:"crl_ca_bundle"`
	CRLInsecure      bool     `yaml:"crl_insecure" json:"crl_insecure"`
	MinDaysRemaining int      `yaml:"min_days_remaining" json:"min_days_remaining"`
	RequireTLS13     bool     `yaml:"require_tls13" json:"require_tls13"`
	RequireHSTS      bool     `yaml:"require_hsts" json:"require_hsts"`
	ForbidTLS10      bool     `yaml:"forbid_tls10" json:"forbid_tls10"`
	ForbidTLS11      bool     `yaml:"forbid_tls11" json:"forbid_tls11"`
	ExpectedNames    []string `yaml:"expected_names" json:"expected_names"`
	AllowedIssuers   []string `yaml:"allowed_issuers" json:"allowed_issuers"`
	CABundle         string   `yaml:"ca_bundle" json:"ca_bundle"`
}

type CheckFinding struct {
	Severity string `json:"severity" yaml:"severity"`
	Scope    string `json:"scope" yaml:"scope"`
	Message  string `json:"message" yaml:"message"`
}

type TargetResult struct {
	Name     string            `json:"name" yaml:"name"`
	Target   string            `json:"target" yaml:"target"`
	Status   string            `json:"status" yaml:"status"`
	Report   checker.Report    `json:"report" yaml:"report"`
	Findings []CheckFinding    `json:"findings,omitempty" yaml:"findings,omitempty"`
	Error    string            `json:"error,omitempty" yaml:"error,omitempty"`
	Meta     map[string]string `json:"meta,omitempty" yaml:"meta,omitempty"`
}

type Report struct {
	File    string         `json:"file" yaml:"file"`
	Results []TargetResult `json:"results" yaml:"results"`
	Matched int            `json:"matched" yaml:"matched"`
	Total   int            `json:"total" yaml:"total"`
	Errors  int            `json:"errors" yaml:"errors"`
}

func Load(path string) (Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, err
	}
	var spec Spec
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&spec); err != nil {
		return Spec{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Spec{}, fmt.Errorf("spec contains multiple YAML documents")
		}
		return Spec{}, err
	}
	if len(spec.Targets) == 0 {
		return Spec{}, fmt.Errorf("spec has no targets")
	}
	for i, target := range spec.Targets {
		if err := validateTarget(target); err != nil {
			return Spec{}, fmt.Errorf("targets[%d]: %w", i, err)
		}
	}
	if spec.Defaults.WarnDays < -1 || spec.Defaults.CriticalDays < -1 {
		return Spec{}, fmt.Errorf("defaults expiry thresholds must be -1 or greater")
	}
	effectiveWarn := defaultInt(spec.Defaults.WarnDays, 30)
	effectiveCritical := defaultInt(spec.Defaults.CriticalDays, 14)
	if effectiveWarn >= 0 && effectiveCritical >= 0 && effectiveCritical > effectiveWarn {
		return Spec{}, fmt.Errorf("defaults critical_days cannot be greater than warn_days")
	}
	if spec.Defaults.CRLWarnDays < -1 || spec.Defaults.CRLCriticalDays < -1 {
		return Spec{}, fmt.Errorf("defaults CRL expiry thresholds must be -1 or greater")
	}
	effectiveCRLWarn := defaultInt(spec.Defaults.CRLWarnDays, 3)
	effectiveCRLCritical := defaultInt(spec.Defaults.CRLCriticalDays, 1)
	if effectiveCRLWarn >= 0 && effectiveCRLCritical >= 0 && effectiveCRLCritical > effectiveCRLWarn {
		return Spec{}, fmt.Errorf("defaults crl_critical_days cannot be greater than crl_warn_days")
	}
	if spec.Defaults.CRLMaxAgeDays < 0 {
		return Spec{}, fmt.Errorf("defaults crl_max_age_days cannot be negative")
	}
	if strings.TrimSpace(spec.Defaults.Timeout) != "" {
		parsed, err := time.ParseDuration(spec.Defaults.Timeout)
		if err != nil || parsed <= 0 {
			return Spec{}, fmt.Errorf("defaults timeout must be a positive duration")
		}
	}
	return spec, nil
}

func Run(ctx context.Context, file string, spec Spec, normalize func(string) (string, string, error)) Report {
	report := Report{
		File:    file,
		Total:   len(spec.Targets),
		Results: make([]TargetResult, 0, len(spec.Targets)),
	}
	timeout := 10 * time.Second
	if strings.TrimSpace(spec.Defaults.Timeout) != "" {
		parsed, _ := time.ParseDuration(spec.Defaults.Timeout)
		timeout = parsed
	}
	for _, target := range spec.Targets {
		targetString := targetString(target)
		result := TargetResult{
			Name:   targetName(target),
			Target: targetString,
		}
		host, address, err := normalize(targetString)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
			report.Errors++
			report.Results = append(report.Results, result)
			continue
		}
		if strings.TrimSpace(target.ServerName) != "" {
			host, _, err = normalize(target.ServerName)
			if err != nil {
				result.Status = "error"
				result.Error = "invalid server_name: " + err.Error()
				report.Errors++
				report.Results = append(report.Results, result)
				continue
			}
		}
		if strings.TrimSpace(target.Connect) != "" {
			connectHost, connectAddress, connectErr := normalize(target.Connect)
			err = connectErr
			if err != nil {
				result.Status = "error"
				result.Error = "invalid connect destination: " + err.Error()
				report.Errors++
				report.Results = append(report.Results, result)
				continue
			}
			if _, _, splitErr := net.SplitHostPort(strings.TrimSpace(target.Connect)); splitErr != nil {
				_, targetPort, _ := net.SplitHostPort(address)
				connectAddress = net.JoinHostPort(connectHost, targetPort)
			}
			address = connectAddress
		}
		caBundle := firstNonEmpty(target.CABundle, spec.Defaults.CABundle)
		crlCABundle := firstNonEmpty(target.CRLCABundle, spec.Defaults.CRLCABundle, caBundle)
		insecureSources := map[string]bool{}
		if target.CRLInsecure {
			for _, source := range target.CRLs {
				insecureSources[source] = true
			}
		}
		checkReport := checker.Run(ctx, host, address, checker.Options{
			WarnDays:           defaultInt(spec.Defaults.WarnDays, 30),
			CriticalDays:       defaultInt(spec.Defaults.CriticalDays, 14),
			Timeout:            timeout,
			CABundle:           caBundle,
			CRLSources:         append([]string(nil), target.CRLs...),
			CRLCABundle:        crlCABundle,
			CRLWarnDays:        defaultInt(spec.Defaults.CRLWarnDays, 3),
			CRLCriticalDays:    defaultInt(spec.Defaults.CRLCriticalDays, 1),
			CRLMaxAgeDays:      spec.Defaults.CRLMaxAgeDays,
			AutoCRL:            target.AutoCRL,
			CRLInsecureSources: insecureSources,
		})
		result.Report = checkReport
		result.Findings = evaluateTarget(target, checkReport)
		result.Status = aggregateStatus(checkReport.Status, result.Findings)
		if result.Status == "ok" {
			report.Matched++
		} else {
			report.Errors++
		}
		report.Results = append(report.Results, result)
	}
	return report
}

func validateTarget(target Target) error {
	if strings.TrimSpace(target.URL) == "" && strings.TrimSpace(target.Host) == "" {
		return fmt.Errorf("host or url is required")
	}
	if target.URL != "" && target.Host != "" {
		return fmt.Errorf("host and url are mutually exclusive")
	}
	if target.MinDaysRemaining < 0 {
		return fmt.Errorf("min_days_remaining cannot be negative")
	}
	if target.CRLInsecure && len(target.CRLs) == 0 {
		return fmt.Errorf("crl_insecure requires at least one CRL source")
	}
	for index, source := range target.CRLs {
		if strings.TrimSpace(source) == "" {
			return fmt.Errorf("crls[%d] cannot be empty", index)
		}
	}
	return nil
}

func evaluateTarget(target Target, report checker.Report) []CheckFinding {
	var findings []CheckFinding
	for _, finding := range report.Findings {
		findings = append(findings, CheckFinding(finding))
	}
	if target.MinDaysRemaining > 0 && report.Certificate.DaysRemaining < target.MinDaysRemaining {
		findings = append(findings, CheckFinding{
			Severity: "critical",
			Scope:    "policy",
			Message:  fmt.Sprintf("certificate has %d days remaining, expected at least %d", report.Certificate.DaysRemaining, target.MinDaysRemaining),
		})
	}
	if target.RequireTLS13 && !hasString(report.TLS.SupportedVersions, "TLS1.3") {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "TLS 1.3 is required but not supported"})
	}
	if target.RequireHSTS && !report.HTTPS.HSTSEnabled {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "HSTS is required but missing"})
	}
	if target.ForbidTLS10 && hasString(report.TLS.SupportedVersions, "TLS1.0") {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "TLS 1.0 is forbidden but supported"})
	}
	if target.ForbidTLS11 && hasString(report.TLS.SupportedVersions, "TLS1.1") {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "TLS 1.1 is forbidden but supported"})
	}
	for _, name := range target.ExpectedNames {
		if !hasString(report.Certificate.DNSNames, name) {
			findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "expected DNS name missing from SAN: " + name})
		}
	}
	if len(target.AllowedIssuers) > 0 && !containsAnyFold(report.Certificate.Issuer, target.AllowedIssuers) {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "issuer is not allowed: " + report.Certificate.Issuer})
	}
	return findings
}

func targetString(target Target) string {
	if strings.TrimSpace(target.URL) != "" {
		return target.URL
	}
	host := strings.TrimSpace(target.Host)
	if target.Port != "" && !strings.Contains(host, ":") {
		return host + ":" + strings.TrimSpace(target.Port)
	}
	return host
}

func targetName(target Target) string {
	if strings.TrimSpace(target.Name) != "" {
		return target.Name
	}
	return targetString(target)
}

func aggregateStatus(base string, findings []CheckFinding) string {
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

func defaultInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
