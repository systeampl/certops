package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantHost    string
		wantAddress string
	}{
		{name: "bare host", in: "example.com", wantHost: "example.com", wantAddress: "example.com:443"},
		{name: "host port", in: "example.com:8443", wantHost: "example.com", wantAddress: "example.com:8443"},
		{name: "https url", in: "https://api.example.com/path", wantHost: "api.example.com", wantAddress: "api.example.com:443"},
		{name: "https url custom port", in: "https://api.example.com:9443/path", wantHost: "api.example.com", wantAddress: "api.example.com:9443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, address, err := normalizeTarget(tt.in)
			if err != nil {
				t.Fatalf("normalizeTarget returned error: %v", err)
			}
			if host != tt.wantHost {
				t.Fatalf("host = %q, want %q", host, tt.wantHost)
			}
			if address != tt.wantAddress {
				t.Fatalf("address = %q, want %q", address, tt.wantAddress)
			}
		})
	}
}

func TestNormalizeTargetRejectsNonHTTPSAndInvalidPort(t *testing.T) {
	for _, input := range []string{"http://example.com", "ftp://example.com", "example.com:70000", "https://user@example.com"} {
		if _, _, err := normalizeTarget(input); err == nil {
			t.Fatalf("normalizeTarget(%q) unexpectedly succeeded", input)
		}
	}
}

func TestNormalizeServerNameAndConnect(t *testing.T) {
	name, err := normalizeServerName("API.Example.com.")
	if err != nil || name != "api.example.com" {
		t.Fatalf("server name = %q, %v", name, err)
	}
	address, err := normalizeConnect("192.0.2.10", "8443")
	if err != nil || address != "192.0.2.10:8443" {
		t.Fatalf("connect address = %q, %v", address, err)
	}
	if _, err := normalizeConnect("-oProxyCommand=bad", "443"); err == nil {
		t.Fatal("unsafe connect destination unexpectedly succeeded")
	}
}

func TestValidationHelpers(t *testing.T) {
	if err := validateFailOn("notice"); err == nil {
		t.Fatal("invalid fail-on unexpectedly succeeded")
	}
	if err := validateThresholds(10, 20); err == nil {
		t.Fatal("reversed thresholds unexpectedly succeeded")
	}
	if err := validateThresholds(-1, -1); err != nil {
		t.Fatalf("disabled thresholds failed: %v", err)
	}
	if err := validateFingerprint("SHA256:" + "00"); err == nil {
		t.Fatal("short fingerprint unexpectedly succeeded")
	}
	if err := validateFingerprint("SHA256:0000000000000000000000000000000000000000000000000000000000000000"); err != nil {
		t.Fatalf("valid fingerprint failed: %v", err)
	}
}

func TestWriteFileAtomicReplacesContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new"), 0640); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("contents = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}
