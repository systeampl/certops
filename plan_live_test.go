package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	checker "github.com/pawel-cygal/certops/internal/check"
)

func TestLiveCAPlanItemWarnsBelowPolicyThreshold(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caPath, testPolicyRootPEM(t, time.Now().Add(48*time.Hour)), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := certopsConfig{Policy: configPolicy{MinCADaysRemaining: 180}}
	ca := configCA{Name: "short-root", Provider: "generic", CABundle: caPath}

	item, path := liveCAPlanItem(ca, t.TempDir(), cfg)
	if path == "" {
		t.Fatalf("expected temporary bundle path")
	}
	if item.Status != "warn" {
		t.Fatalf("status = %q, want warn: %+v", item.Status, item)
	}
	if !strings.Contains(item.Expected, "180 days") {
		t.Fatalf("expected threshold missing: %+v", item)
	}
}

func TestServicePolicyFindingsCoverConfiguredPolicy(t *testing.T) {
	service := configService{
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
	}

	findings := servicePolicyFindings(service, report)
	joined := livePolicyMessages(findings)
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
	if got := statusWithPolicyFindings(report.Status, findings); got != "critical" {
		t.Fatalf("status = %q, want critical", got)
	}
}

func TestEffectiveFailOnPrefersCLIThenConfigThenFallback(t *testing.T) {
	if got := effectiveFailOn("critical", "warn", "warn"); got != "critical" {
		t.Fatalf("fail_on = %q, want critical", got)
	}
	if got := effectiveFailOn("", "warn", "critical"); got != "warn" {
		t.Fatalf("fail_on = %q, want warn", got)
	}
	if got := effectiveFailOn("", "", "critical"); got != "critical" {
		t.Fatalf("fail_on = %q, want critical", got)
	}
}

func TestValidateConfigRejectsInvalidFailOn(t *testing.T) {
	cfg := certopsConfig{Policy: configPolicy{FailOn: "notice"}}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected invalid fail_on error")
	}
}

func livePolicyMessages(findings []checker.Finding) string {
	var out []string
	for _, finding := range findings {
		out = append(out, finding.Message)
	}
	return strings.Join(out, "\n")
}

func testPolicyRootPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Policy Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
