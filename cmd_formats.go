package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	checker "github.com/systeampl/certops/internal/check"
)

func printYAMLReports(reports []checker.Report) {
	printYAMLValue(struct {
		Reports []checker.Report `yaml:"reports"`
	}{Reports: reports})
}

func printPromReports(reports []checker.Report) {
	fmt.Println("# HELP certops_status TLS/HTTPS aggregate status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE certops_status gauge")
	fmt.Println("# HELP certops_certificate_days_remaining Days remaining until certificate expiration.")
	fmt.Println("# TYPE certops_certificate_days_remaining gauge")
	fmt.Println("# HELP certops_certificate_trusted Certificate chain trust status (1=trusted, 0=untrusted).")
	fmt.Println("# TYPE certops_certificate_trusted gauge")
	fmt.Println("# HELP certops_certificate_matches_host Certificate hostname match status (1=match, 0=mismatch).")
	fmt.Println("# TYPE certops_certificate_matches_host gauge")
	fmt.Println("# HELP certops_tls_version_supported TLS version support status (1=supported, 0=not supported).")
	fmt.Println("# TYPE certops_tls_version_supported gauge")
	fmt.Println("# HELP certops_tls_ocsp_stapling OCSP stapling status (1=present, 0=missing).")
	fmt.Println("# TYPE certops_tls_ocsp_stapling gauge")
	fmt.Println("# HELP certops_tls_ocsp_staple_valid OCSP staple validation status (1=valid and good, 0=missing, invalid, revoked, or unknown).")
	fmt.Println("# TYPE certops_tls_ocsp_staple_valid gauge")
	fmt.Println("# HELP certops_https_hsts HSTS header status (1=present, 0=missing).")
	fmt.Println("# TYPE certops_https_hsts gauge")
	fmt.Println("# HELP certops_certificate_revocation_checked Certificate CRL revocation check status (1=checked, 0=not checked).")
	fmt.Println("# TYPE certops_certificate_revocation_checked gauge")
	fmt.Println("# HELP certops_certificate_revoked Certificate revocation status (1=revoked, 0=not revoked or unchecked).")
	fmt.Println("# TYPE certops_certificate_revoked gauge")

	for _, report := range reports {
		base := map[string]string{"target": report.Target, "host": report.Host}
		for _, status := range []string{"ok", "warn", "critical", "error"} {
			fmt.Printf("certops_status{%s} %d\n", promLabels(map[string]string{
				"target": report.Target,
				"host":   report.Host,
				"status": status,
			}), boolInt(report.Status == status))
		}
		fmt.Printf("certops_certificate_days_remaining{%s} %d\n", promLabels(base), report.Certificate.DaysRemaining)
		fmt.Printf("certops_certificate_trusted{%s} %d\n", promLabels(base), boolInt(report.Certificate.Trusted))
		fmt.Printf("certops_certificate_matches_host{%s} %d\n", promLabels(base), boolInt(report.Certificate.MatchesHost))
		for _, version := range []string{"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"} {
			fmt.Printf("certops_tls_version_supported{%s} %d\n", promLabels(map[string]string{
				"target":  report.Target,
				"host":    report.Host,
				"version": version,
			}), boolInt(hasString(report.TLS.SupportedVersions, version)))
		}
		fmt.Printf("certops_tls_ocsp_stapling{%s} %d\n", promLabels(base), boolInt(report.TLS.OCSPStapling))
		fmt.Printf("certops_tls_ocsp_staple_valid{%s} %d\n", promLabels(base), boolInt(report.TLS.OCSPStatus == "good"))
		fmt.Printf("certops_https_hsts{%s} %d\n", promLabels(base), boolInt(report.HTTPS.HSTSEnabled))
		fmt.Printf("certops_certificate_revocation_checked{%s} %d\n", promLabels(base), boolInt(report.Revocation.Checked))
		fmt.Printf("certops_certificate_revoked{%s} %d\n", promLabels(base), boolInt(report.Revocation.Revoked))
	}
}

func promLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key, value := range labels {
		if strings.TrimSpace(value) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Quote(labels[key]))
	}
	return strings.Join(parts, ",")
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
