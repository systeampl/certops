package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	checker "github.com/pawel-cygal/certops/internal/check"
)

func TestEvaluateTargetPolicyFindings(t *testing.T) {
	target := Target{
		MinDaysRemaining: 30,
		RequireTLS13:     true,
		RequireHSTS:      true,
		ForbidTLS10:      true,
		ExpectedNames:    []string{"api.example.com"},
		AllowedIssuers:   []string{"Smallstep"},
	}
	report := checker.Report{
		Status: "ok",
		Certificate: checker.Certificate{
			DaysRemaining: 12,
			DNSNames:      []string{"www.example.com"},
			Issuer:        "CN=Other CA",
		},
		TLS: checker.TLSInfo{
			SupportedVersions: []string{"TLS1.0", "TLS1.2"},
		},
		HTTPS: checker.HTTPSInfo{},
	}

	findings := evaluateTarget(target, report)
	joined := findingMessages(findings)
	for _, want := range []string{
		"expected at least 30",
		"TLS 1.3 is required",
		"HSTS is required",
		"TLS 1.0 is forbidden",
		"expected DNS name missing",
		"issuer is not allowed",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing finding containing %q in:\n%s", want, joined)
		}
	}
}

func TestLoadRejectsUnknownFieldsAndInvalidDefaults(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		yaml string
		want string
	}{
		{name: "unknown", yaml: "targets:\n  - host: example.com\n    require_tls_14: true\n", want: "field require_tls_14 not found"},
		{name: "timeout", yaml: "defaults:\n  timeout: forever\ntargets:\n  - host: example.com\n", want: "positive duration"},
		{name: "thresholds", yaml: "defaults:\n  warn_days: 10\n  critical_days: 20\ntargets:\n  - host: example.com\n", want: "cannot be greater"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadAcceptsServerNameConnectAndAutoCRL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verify.yaml")
	data := "defaults:\n  crl_ca_bundle: issuer.pem\n  crl_warn_days: 4\n  crl_critical_days: 2\n  crl_max_age_days: 7\ntargets:\n  - name: api\n    host: api.example.com\n    server_name: tls.example.com\n    connect: 192.0.2.10:8443\n    auto_crl: true\n    crls:\n      - issuer.crl\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	spec, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Targets) != 1 || !spec.Targets[0].AutoCRL || spec.Targets[0].ServerName != "tls.example.com" || len(spec.Targets[0].CRLs) != 1 || spec.Defaults.CRLCABundle != "issuer.pem" {
		t.Fatalf("spec = %+v", spec)
	}
}

func TestLoadRejectsInvalidCRLConfiguration(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		yaml string
		want string
	}{
		{name: "thresholds", yaml: "defaults:\n  crl_warn_days: 1\n  crl_critical_days: 2\ntargets:\n  - host: example.com\n", want: "crl_critical_days"},
		{name: "max-age", yaml: "defaults:\n  crl_max_age_days: -1\ntargets:\n  - host: example.com\n", want: "cannot be negative"},
		{name: "insecure-without-source", yaml: "targets:\n  - host: example.com\n    crl_insecure: true\n", want: "requires at least one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAggregateStatus(t *testing.T) {
	if got := aggregateStatus("ok", nil); got != "ok" {
		t.Fatalf("status = %q, want ok", got)
	}
	if got := aggregateStatus("ok", []CheckFinding{{Severity: "warn"}}); got != "warn" {
		t.Fatalf("status = %q, want warn", got)
	}
	if got := aggregateStatus("warn", []CheckFinding{{Severity: "critical"}}); got != "critical" {
		t.Fatalf("status = %q, want critical", got)
	}
}

func findingMessages(findings []CheckFinding) string {
	var out []string
	for _, finding := range findings {
		out = append(out, finding.Message)
	}
	return strings.Join(out, "\n")
}
