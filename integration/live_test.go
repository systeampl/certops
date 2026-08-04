//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pawel-cygal/certops/pkg/certops"
)

func TestLivePublicTLSEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("live integration test disabled in short mode")
	}
	target := os.Getenv("CERTOPS_TEST_TARGET")
	if target == "" {
		target = "example.com"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := certops.CheckTarget(ctx, target, certops.CheckOptions{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("normalize live target: %v", err)
	}
	if report.Error != "" {
		t.Fatalf("live check failed: %s", report.Error)
	}
	if report.SchemaVersion != certops.SchemaVersion {
		t.Fatalf("schema version = %q, want %q", report.SchemaVersion, certops.SchemaVersion)
	}
	if !report.Certificate.Trusted || !report.Certificate.MatchesHost {
		t.Fatalf("unexpected certificate state: trusted=%t matches_host=%t", report.Certificate.Trusted, report.Certificate.MatchesHost)
	}
	if !contains(report.TLS.SupportedVersions, "TLS1.2") && !contains(report.TLS.SupportedVersions, "TLS1.3") {
		t.Fatalf("modern TLS is unavailable: %v", report.TLS.SupportedVersions)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
