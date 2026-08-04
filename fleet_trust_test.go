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
)

func TestExpandFleetTrustTargetsHostAndGroup(t *testing.T) {
	cfg := certopsConfig{
		Inventory: configInventory{Groups: map[string]configGroup{
			"web": {Hosts: map[string]configHost{
				"web-01": {Address: "10.0.0.1", User: "ops", Port: "22", OS: "linux"},
				"web-02": {Address: "10.0.0.2", User: "ops", Port: "2222", OS: "linux"},
			}},
		}},
		Trust: configTrust{Targets: []configTrustTarget{
			{Group: "web", Required: []string{"root-a"}},
			{Host: "web-01", Required: []string{"root-b"}},
		}},
	}

	targets, failures := expandFleetTrustTargets(cfg, "")
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %+v", failures)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}

	targets, failures = expandFleetTrustTargets(cfg, "web-02")
	if len(failures) != 0 {
		t.Fatalf("unexpected failures with limit: %+v", failures)
	}
	if len(targets) != 1 || targets[0].Host.Name != "web-02" || targets[0].CAName != "root-a" {
		t.Fatalf("unexpected limited targets: %+v", targets)
	}
}

func TestFleetSSHUsesPersistentHostKeyVerification(t *testing.T) {
	args := strings.Join(fleetSSHArgs(fleetHost{Address: "192.0.2.10", User: "ops", Port: "22"}, "true"), " ")
	if !strings.Contains(args, "StrictHostKeyChecking=accept-new") {
		t.Fatalf("SSH args do not enable TOFU host key verification: %s", args)
	}
	for _, unsafe := range []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=/tmp"} {
		if strings.Contains(args, unsafe) {
			t.Fatalf("SSH args contain unsafe option %q: %s", unsafe, args)
		}
	}
}

func TestExpandFleetTrustTargetsIsDeterministic(t *testing.T) {
	cfg := certopsConfig{
		Inventory: configInventory{Groups: map[string]configGroup{"web": {Hosts: map[string]configHost{
			"web-02": {Address: "10.0.0.2"},
			"web-01": {Address: "10.0.0.1"},
		}}}},
		Trust: configTrust{Targets: []configTrustTarget{{Group: "web", Required: []string{"root"}}}},
	}
	targets, failures := expandFleetTrustTargets(cfg, "")
	if len(failures) != 0 || len(targets) != 2 {
		t.Fatalf("targets/failures = %+v/%+v", targets, failures)
	}
	if targets[0].Host.Name != "web-01" || targets[1].Host.Name != "web-02" {
		t.Fatalf("target order = %s, %s", targets[0].Host.Name, targets[1].Host.Name)
	}
}

func TestRunFleetTrustPlanWithGenericCA(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caPath, testRootPEM(t), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := certopsConfig{
		CAs: []configCA{{Name: "lab-root", Provider: "generic", CABundle: caPath}},
		Inventory: configInventory{Groups: map[string]configGroup{
			"lab": {Hosts: map[string]configHost{
				"target": {Address: "127.0.0.1", User: "ops", Port: "2222", OS: "linux"},
			}},
		}},
		Trust: configTrust{Targets: []configTrustTarget{{Host: "target", Required: []string{"lab-root"}}}},
	}

	report := runFleetTrust("plan", "certops.yaml", cfg, "target")
	if report.Status != "ok" {
		t.Fatalf("expected ok report, got %s: %+v", report.Status, report)
	}
	if report.Summary.Total != 1 || report.Summary.OK != 1 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
	if report.Items[0].Path != "/usr/local/share/ca-certificates/certops-lab-root.crt" {
		t.Fatalf("unexpected remote path: %s", report.Items[0].Path)
	}
}

func TestFleetTrustMissingCAIsCritical(t *testing.T) {
	cfg := certopsConfig{
		Inventory: configInventory{Groups: map[string]configGroup{
			"lab": {Hosts: map[string]configHost{"target": {Address: "127.0.0.1", OS: "linux"}}},
		}},
		Trust: configTrust{Targets: []configTrustTarget{{Host: "target", Required: []string{"missing"}}}},
	}
	report := runFleetTrust("plan", "certops.yaml", cfg, "")
	if report.Status != "critical" {
		t.Fatalf("expected critical report, got %s", report.Status)
	}
	if len(report.Items) != 1 || report.Items[0].Message != "CA is not configured" {
		t.Fatalf("unexpected items: %+v", report.Items)
	}
}

func TestShellQuote(t *testing.T) {
	got := shellQuote("/tmp/certops it's ok.crt")
	want := "'/tmp/certops it'\\''s ok.crt'"
	if got != want {
		t.Fatalf("unexpected quote: got %q want %q", got, want)
	}
}

func testRootPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fleet Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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
