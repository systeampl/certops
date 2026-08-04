package certops

import "testing"

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		input   string
		host    string
		address string
	}{
		{input: "example.com", host: "example.com", address: "example.com:443"},
		{input: "example.com:8443", host: "example.com", address: "example.com:8443"},
		{input: "https://example.com/path", host: "example.com", address: "example.com:443"},
		{input: "[2001:db8::1]:9443", host: "2001:db8::1", address: "[2001:db8::1]:9443"},
	}
	for _, tt := range tests {
		host, address, err := NormalizeTarget(tt.input)
		if err != nil {
			t.Fatalf("NormalizeTarget(%q): %v", tt.input, err)
		}
		if host != tt.host || address != tt.address {
			t.Fatalf("NormalizeTarget(%q) = %q, %q; want %q, %q", tt.input, host, address, tt.host, tt.address)
		}
	}
}

func TestNormalizeTargetRejectsUnsafeOrUnsupportedInput(t *testing.T) {
	for _, input := range []string{"", "http://example.com", "https://user@example.com", "example.com:70000"} {
		if _, _, err := NormalizeTarget(input); err == nil {
			t.Fatalf("NormalizeTarget(%q) unexpectedly succeeded", input)
		}
	}
}
