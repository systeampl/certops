package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	crlcheck "github.com/systeampl/certops/internal/crl"
)

func cmdCRL(args []string) {
	if len(args) < 1 {
		fatal("usage: certops crl check --file ca.crl|--url https://pki.example.com/ca.crl")
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "check":
		cmdCRLCheck(args[1:])
	default:
		fatal("unknown CRL command: " + args[0])
	}
}

func cmdCRLCheck(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--file": true, "--url": true, "--ca-bundle": true, "--warn-days": true, "--critical-days": true, "--max-age-days": true, "--timeout": true, "--fail-on": true, "--otel-endpoint": true, "--name": true})
	fs := flag.NewFlagSet("crl check", flag.ExitOnError)
	file := fs.String("file", "", "CRL file path")
	url := fs.String("url", "", "CRL URL")
	name := fs.String("name", "", "CRL name for labels")
	caBundle := fs.String("ca-bundle", "", "PEM CA bundle used to verify the CRL signature")
	warnDays := fs.Int("warn-days", 3, "warning threshold for CRL nextUpdate")
	criticalDays := fs.Int("critical-days", 1, "critical threshold for CRL nextUpdate")
	maxAgeDays := fs.Int("max-age-days", 0, "warning threshold for CRL thisUpdate age (0 = disabled)")
	timeout := fs.Duration("timeout", 10*time.Second, "network timeout")
	insecure := fs.Bool("insecure", false, "skip TLS verification when fetching CRL URL")
	failOn := fs.String("fail-on", "critical", "exit non-zero on warn or critical")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	promOut := fs.Bool("prom", false, "emit Prometheus text output")
	otelEndpoint := fs.String("otel-endpoint", "", "export OTLP/HTTP metrics to endpoint, for example http://localhost:4318")
	fs.Parse(args)

	format, err := resolveOutput(*jsonOut, *yamlOut, *promOut)
	if err != nil {
		fatal(err.Error())
	}
	if err := validateFailOn(*failOn); err != nil {
		fatal(err.Error())
	}
	if err := validateThresholds(*warnDays, *criticalDays); err != nil {
		fatal(err.Error())
	}
	if *maxAgeDays < 0 {
		fatal("--max-age-days cannot be negative")
	}
	if err := validateTimeout(*timeout); err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(*caBundle) == "" {
		fatal("--ca-bundle is required to verify the CRL signature")
	}
	source, err := crlSource(*file, *url)
	if err != nil {
		fatal(err.Error())
	}
	report := crlcheck.Run(context.Background(), crlcheck.Options{
		Name:             *name,
		Source:           source,
		CABundle:         *caBundle,
		WarnDays:         *warnDays,
		CriticalDays:     *criticalDays,
		MaxAgeDays:       *maxAgeDays,
		Timeout:          *timeout,
		Insecure:         *insecure,
		RequireSignature: true,
	})
	if err := exportCRLReportsOTEL(*otelEndpoint, []crlcheck.Report{report}); err != nil {
		fatal(err.Error())
	}
	printCRLReports([]crlcheck.Report{report}, format)
	os.Exit(exitForCRLReports([]crlcheck.Report{report}, *failOn))
}

func crlSource(file, url string) (string, error) {
	file = strings.TrimSpace(file)
	url = strings.TrimSpace(url)
	if file != "" && url != "" {
		return "", fmt.Errorf("--file and --url are mutually exclusive")
	}
	if file == "" && url == "" {
		return "", fmt.Errorf("--file or --url is required")
	}
	if file != "" {
		return file, nil
	}
	return url, nil
}

func printCRLReports(reports []crlcheck.Report, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(reports)
	case outputYAML:
		printYAMLValue(reports)
	case outputProm:
		printPromCRLReports(reports)
	default:
		for i, report := range reports {
			if i > 0 {
				fmt.Println()
			}
			printRawCRLReport(report)
		}
	}
}

func printRawCRLReport(report crlcheck.Report) {
	title := report.Name
	if strings.TrimSpace(title) == "" {
		title = report.Source
	}
	fmt.Printf("%s  crl report\n", title)
	fmt.Printf("source: %s\n", report.Source)
	fmt.Printf("status: %s\n", statusColor(report.Status))
	if report.Error != "" {
		fmt.Printf("error: %s\n", report.Error)
	}
	fmt.Println()

	rows := [][]string{
		{"crl", "issuer", emptyDash(shortIssuer(report.Issuer)), "info"},
		{"crl", "this_update", prettyTimestamp(report.ThisUpdate), "info"},
		{"crl", "next_update", prettyTimestamp(report.NextUpdate), crlExpiryStatus(report)},
		{"crl", "expires_in", crlDaysCell(report), crlExpiryStatus(report)},
		{"crl", "age_seconds", fmt.Sprintf("%d", report.AgeSeconds), "info"},
		{"crl", "number", emptyDash(report.Number), "info"},
		{"crl", "revoked_certs", fmt.Sprintf("%d", report.RevokedCertificates), "info"},
		{"crl", "signature", crlSignatureCell(report), crlSignatureStatus(report)},
	}
	if report.HTTPStatus != 0 {
		rows = append(rows, []string{"crl", "http_status", fmt.Sprintf("%d", report.HTTPStatus), "info"})
	}
	renderTable([]string{"scope", "check", "value", "status"}, rows)
	fmt.Println()
	renderCRLFindings(report.Findings)
	fmt.Printf("\nsummary: status=%s, findings=%d\n", statusColor(report.Status), len(report.Findings))
}

func renderCRLFindings(findings []crlcheck.Finding) {
	fmt.Println("findings:")
	if len(findings) == 0 {
		fmt.Println("  none")
		return
	}
	rows := make([][]string, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, []string{statusColor(finding.Severity), finding.Message})
	}
	renderTable([]string{"severity", "message"}, rows)
}

func printPromCRLReports(reports []crlcheck.Report) {
	fmt.Println("# HELP certops_crl_status CRL aggregate status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE certops_crl_status gauge")
	fmt.Println("# HELP certops_crl_next_update_days Days remaining until CRL nextUpdate.")
	fmt.Println("# TYPE certops_crl_next_update_days gauge")
	fmt.Println("# HELP certops_crl_age_seconds Seconds since CRL thisUpdate.")
	fmt.Println("# TYPE certops_crl_age_seconds gauge")
	fmt.Println("# HELP certops_crl_fetch_ok CRL fetch and parse status (1=ok, 0=failed).")
	fmt.Println("# TYPE certops_crl_fetch_ok gauge")
	fmt.Println("# HELP certops_crl_signature_valid CRL signature validation status (1=valid, 0=invalid or unchecked).")
	fmt.Println("# TYPE certops_crl_signature_valid gauge")
	fmt.Println("# HELP certops_crl_revoked_certificates Number of revoked certificate entries in the CRL.")
	fmt.Println("# TYPE certops_crl_revoked_certificates gauge")
	fmt.Println("# HELP certops_crl_number CRL number extension value.")
	fmt.Println("# TYPE certops_crl_number gauge")
	for _, report := range reports {
		base := crlPromLabels(report)
		for _, status := range []string{"ok", "warn", "critical"} {
			labels := crlPromLabels(report)
			labels["status"] = status
			fmt.Printf("certops_crl_status{%s} %d\n", promLabels(labels), boolInt(report.Status == status))
		}
		fmt.Printf("certops_crl_next_update_days{%s} %d\n", promLabels(base), report.DaysRemaining)
		fmt.Printf("certops_crl_age_seconds{%s} %d\n", promLabels(base), report.AgeSeconds)
		fmt.Printf("certops_crl_fetch_ok{%s} %d\n", promLabels(base), boolInt(report.Error == ""))
		fmt.Printf("certops_crl_signature_valid{%s} %d\n", promLabels(base), boolInt(report.SignatureValid))
		fmt.Printf("certops_crl_revoked_certificates{%s} %d\n", promLabels(base), report.RevokedCertificates)
		if report.Number != "" {
			fmt.Printf("certops_crl_number{%s} %s\n", promLabels(base), report.Number)
		}
	}
}

func crlPromLabels(report crlcheck.Report) map[string]string {
	return map[string]string{"name": report.Name, "source": report.Source, "issuer": shortIssuer(report.Issuer)}
}

func crlExpiryStatus(report crlcheck.Report) string {
	for _, finding := range report.Findings {
		if strings.Contains(finding.Message, "CRL expired") || strings.Contains(finding.Message, "CRL expires") || strings.Contains(finding.Message, "nextUpdate") {
			return statusColor(finding.Severity)
		}
	}
	return statusColor("ok")
}

func crlDaysCell(report crlcheck.Report) string {
	if report.NextUpdate == "" {
		return "-"
	}
	value := fmt.Sprintf("%d days", report.DaysRemaining)
	switch strings.TrimSpace(ansiPattern.ReplaceAllString(crlExpiryStatus(report), "")) {
	case "critical":
		return colorize(value, "\x1b[31m")
	case "warn":
		return colorize(value, "\x1b[33m")
	default:
		return colorize(value, "\x1b[32m")
	}
}

func crlSignatureCell(report crlcheck.Report) string {
	if !report.SignatureChecked {
		return "not checked"
	}
	if report.SignatureValid {
		return statusColor("valid")
	}
	return statusColor("invalid")
}

func crlSignatureStatus(report crlcheck.Report) string {
	if !report.SignatureChecked {
		return "info"
	}
	return statusColor(okCritical(report.SignatureValid))
}

func exitForCRLReports(reports []crlcheck.Report, failOn string) int {
	failOn = strings.ToLower(strings.TrimSpace(failOn))
	if failOn == "" {
		failOn = "critical"
	}
	for _, report := range reports {
		switch report.Status {
		case "critical", "error":
			return 1
		case "warn":
			if failOn == "warn" {
				return 1
			}
		}
	}
	return 0
}
