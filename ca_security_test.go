package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFetchConfiguredCARejectsFingerprintMismatchWithoutWriting(t *testing.T) {
	caPEM := testRootPEM(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/roots.pem" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(caPEM)
	}))
	defer server.Close()

	outDir := t.TempDir()
	result := fetchConfiguredCA(configCA{
		Name:        "mismatch",
		Provider:    "smallstep",
		URL:         server.URL,
		Fingerprint: "SHA256:" + strings.Repeat("00", 32),
	}, outDir)
	if result.Status != "critical" || !strings.Contains(result.Error, "fingerprint") {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(outDir, "mismatch.pem")); !os.IsNotExist(err) {
		t.Fatalf("untrusted CA output exists or stat failed unexpectedly: %v", err)
	}
}

func TestVaultClientDoesNotForwardTokenAcrossRedirect(t *testing.T) {
	forwarded := make(chan string, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded <- r.Header.Get("X-Vault-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer source.Close()

	status, _, err := vaultGet(source.URL, vaultOptions{Token: "secret", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusFound {
		t.Fatalf("status = %d, want %d", status, http.StatusFound)
	}
	select {
	case token := <-forwarded:
		t.Fatalf("redirect was followed and token %q was forwarded", token)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestReadLimitedRejectsOversizedResponse(t *testing.T) {
	if _, err := readLimited(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized response unexpectedly succeeded")
	}
}
