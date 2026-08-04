package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigUsesStrictYAMLAndAcceptsStarter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certops.yaml")
	if err := os.WriteFile(path, []byte(starterConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("starter config is invalid: %v", err)
	}

	bad := strings.Replace(starterConfig, "  fail_on: warn", "  fail_onn: warn", 1)
	if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "field fail_onn not found") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestLoadConfigRejectsMultipleDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certops.yaml")
	if err := os.WriteFile(path, []byte("policy: {}\n---\npolicy: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("multiple document error = %v", err)
	}
}

func TestValidateConfigRejectsUnsafeTrustInputs(t *testing.T) {
	validFingerprint := "SHA256:" + strings.Repeat("00", 32)
	tests := []struct {
		name string
		cfg  certopsConfig
		want string
	}{
		{
			name: "insecure CA without fingerprint",
			cfg:  certopsConfig{CAs: []configCA{{Name: "step", Provider: "smallstep", URL: "https://ca.example", Insecure: true}}},
			want: "fingerprint is required",
		},
		{
			name: "colliding CA paths",
			cfg: certopsConfig{CAs: []configCA{
				{Name: "root one", Provider: "generic", CABundle: "one.pem"},
				{Name: "root-one", Provider: "generic", CABundle: "two.pem"},
			}},
			want: "same trust-store path",
		},
		{
			name: "duplicate inventory host",
			cfg: certopsConfig{Inventory: configInventory{Groups: map[string]configGroup{
				"one": {Hosts: map[string]configHost{"node": {Address: "192.0.2.1"}}},
				"two": {Hosts: map[string]configHost{"node": {Address: "192.0.2.2"}}},
			}}},
			want: "duplicated",
		},
		{
			name: "unsafe SSH address",
			cfg: certopsConfig{Inventory: configInventory{Groups: map[string]configGroup{
				"one": {Hosts: map[string]configHost{"node": {Address: "-oProxyCommand=bad"}}},
			}}},
			want: "address is unsafe",
		},
		{
			name: "HTTP service URL",
			cfg:  certopsConfig{Services: []configService{{Name: "api", URL: "http://api.example"}}},
			want: "scheme must be https",
		},
		{
			name: "invalid fingerprint",
			cfg:  certopsConfig{CAs: []configCA{{Name: "root", Provider: "generic", CABundle: "root.pem", Fingerprint: validFingerprint + "0"}}},
			want: "exactly 64",
		},
		{
			name: "provider base URL with query",
			cfg:  certopsConfig{CAs: []configCA{{Name: "step", Provider: "smallstep", URL: "https://ca.example?redirect=1"}}},
			want: "query or fragment",
		},
		{
			name: "CRL without issuer",
			cfg:  certopsConfig{CRLs: []configCRL{{Name: "revocations", File: "ca.crl"}}},
			want: "requires ca",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
