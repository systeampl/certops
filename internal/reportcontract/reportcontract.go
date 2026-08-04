// Package reportcontract defines the machine-readable contract shared by the
// certops command implementations and the supported public Go package.
package reportcontract

const (
	SchemaVersion    = "certops.report.v1"
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
	SeverityError    = "error"
)
