package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildTrustReportRejectsNonCAAndExpiredCertificates(t *testing.T) {
	for _, cert := range []trustCert{
		{Subject: "CN=leaf", IsCA: false, DaysLeft: 30},
		{Subject: "CN=expired-root", IsCA: true, DaysLeft: -1},
	} {
		report := buildTrustReport("plan", trustSource{Label: "test.pem"}, []trustCert{cert}, [][]byte{{1}}, trustPlan{Store: "test"})
		if report.Status != "critical" {
			t.Fatalf("certificate %+v produced status %q, findings=%+v", cert, report.Status, report.Findings)
		}
	}
}

func TestProviderValidationRejectsNonCACertificates(t *testing.T) {
	if got := validateGenericCA(genericCA{Count: 1, Certs: []genericCACert{{Subject: "CN=leaf", IsCA: false, DaysLeft: 30}}}); len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("generic CA findings = %+v", got)
	}
}

func TestWriteTempBundleUsesPrivateUniqueFile(t *testing.T) {
	first, err := writeTempBundle("company root", []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(first)
	second, err := writeTempBundle("company root", []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(second)
	if first == second {
		t.Fatalf("temporary paths must be unique: %s", first)
	}
	if filepath.Dir(first) != os.TempDir() {
		t.Fatalf("temporary file directory = %s", filepath.Dir(first))
	}
	info, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("temporary file permissions = %o, want 600", info.Mode().Perm())
	}
}
