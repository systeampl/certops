package main

import (
	"context"
	"testing"

	checker "github.com/systeampl/certops/internal/check"
)

func TestRunScanTargetsPreservesOrderForInvalidTargets(t *testing.T) {
	targets := []string{"", "http://example.com", "example.com:70000"}
	reports := runScanTargets(context.Background(), targets, 3, checker.Options{})
	if len(reports) != len(targets) {
		t.Fatalf("reports = %d, want %d", len(reports), len(targets))
	}
	for index, report := range reports {
		if report.Target != targets[index] || report.Status != "error" || report.Error == "" {
			t.Fatalf("report[%d] = %+v", index, report)
		}
		if report.SchemaVersion != checker.SchemaVersion {
			t.Fatalf("schema version = %q", report.SchemaVersion)
		}
	}
}
