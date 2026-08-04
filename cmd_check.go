package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	checker "github.com/systeampl/certops/internal/check"
)

func cmdCheck(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--warn-days": true, "--critical-days": true, "--ca-bundle": true, "--crl": true, "--crl-ca-bundle": true, "--crl-warn-days": true, "--crl-critical-days": true, "--crl-max-age-days": true, "--fail-on": true, "--timeout": true, "--html": true, "--otel-endpoint": true, "--interval": true, "--watch-timeout": true, "--max-iterations": true, "--server-name": true, "--connect": true})
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	promOut := fs.Bool("prom", false, "emit Prometheus text output")
	htmlOut := fs.String("html", "", "write HTML report to path")
	otelEndpoint := fs.String("otel-endpoint", "", "export OTLP/HTTP metrics to endpoint, for example http://localhost:4318")
	warnDays := fs.Int("warn-days", 30, "warning threshold for certificate expiry")
	criticalDays := fs.Int("critical-days", 14, "critical threshold for certificate expiry")
	caBundle := fs.String("ca-bundle", "", "PEM root/intermediate CA bundle used for additional trust validation")
	var crls stringListFlag
	fs.Var(&crls, "crl", "CRL file or URL used for revocation validation (repeatable or comma-separated)")
	crlCABundle := fs.String("crl-ca-bundle", "", "PEM CA bundle used to verify CRL signatures")
	crlWarnDays := fs.Int("crl-warn-days", 3, "warning threshold for CRL nextUpdate")
	crlCriticalDays := fs.Int("crl-critical-days", 1, "critical threshold for CRL nextUpdate")
	crlMaxAgeDays := fs.Int("crl-max-age-days", 0, "warning threshold for CRL thisUpdate age (0 = disabled)")
	crlInsecure := fs.Bool("crl-insecure", false, "skip TLS verification when fetching CRLs; signatures are still required")
	autoCRL := fs.Bool("auto-crl", false, "fetch and verify CRLs advertised by the leaf certificate")
	serverName := fs.String("server-name", "", "override TLS SNI and hostname verification name")
	connect := fs.String("connect", "", "override TCP destination as host[:port]")
	failOn := fs.String("fail-on", "critical", "exit non-zero on warn or critical")
	timeout := fs.Duration("timeout", 10*time.Second, "network timeout")
	watch := fs.Bool("watch", false, "rerun the check until interrupted")
	interval := fs.Duration("interval", 5*time.Second, "watch interval")
	watchTimeout := fs.Duration("watch-timeout", 0, "maximum watch duration (0 = unlimited)")
	maxIterations := fs.Int("max-iterations", 0, "maximum watch iterations (0 = unlimited)")
	untilOK := fs.Bool("until-ok", false, "in watch mode, stop automatically once the check is healthy")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fatal("usage: certops check <host|url> [--json|--yaml|--prom]")
	}
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
	if err := validateThresholds(*crlWarnDays, *crlCriticalDays); err != nil {
		fatal("CRL " + err.Error())
	}
	if *crlMaxAgeDays < 0 {
		fatal("--crl-max-age-days cannot be negative")
	}
	if err := validateTimeout(*timeout); err != nil {
		fatal(err.Error())
	}
	watchCfg, err := normalizeWatchConfig(*watch, *untilOK, *interval, *watchTimeout, *maxIterations)
	if err != nil {
		fatal(err.Error())
	}
	if watchCfg.Enabled && *promOut {
		fatal("--prom is not supported with --watch")
	}
	if watchCfg.Enabled && strings.TrimSpace(*htmlOut) != "" {
		fatal("--html is not supported with --watch")
	}
	if watchCfg.Enabled && strings.TrimSpace(*otelEndpoint) != "" {
		fatal("--otel-endpoint is not supported with --watch")
	}
	host, address, err := normalizeTarget(fs.Arg(0))
	if err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(*serverName) != "" {
		host, err = normalizeServerName(*serverName)
		if err != nil {
			fatal(err.Error())
		}
	}
	if strings.TrimSpace(*connect) != "" {
		_, port, _ := net.SplitHostPort(address)
		address, err = normalizeConnect(*connect, port)
		if err != nil {
			fatal(err.Error())
		}
	}

	runOnce := func() checker.Report {
		crlBundle := defaultCRLCABundle(*crlCABundle, *caBundle)
		insecureSources := map[string]bool{}
		if *crlInsecure {
			for _, source := range crls {
				insecureSources[source] = true
			}
		}
		return checker.Run(context.Background(), host, address, checker.Options{
			WarnDays:           *warnDays,
			CriticalDays:       *criticalDays,
			Timeout:            *timeout,
			CABundle:           *caBundle,
			CRLSources:         []string(crls),
			CRLCABundle:        crlBundle,
			CRLWarnDays:        *crlWarnDays,
			CRLCriticalDays:    *crlCriticalDays,
			CRLMaxAgeDays:      *crlMaxAgeDays,
			AutoCRL:            *autoCRL,
			CRLInsecureSources: insecureSources,
		})
	}
	if watchCfg.Enabled {
		err := watchLoop(watchCfg, format, func() (any, bool, error) {
			report := runOnce()
			return []checker.Report{report}, exitForReports([]checker.Report{report}, *failOn) == 0, nil
		}, func(v any) {
			reports := v.([]checker.Report)
			printReports(reports, outputRaw)
		})
		if err != nil {
			fatal(err.Error())
		}
		return
	}

	report := runOnce()
	if strings.TrimSpace(*htmlOut) != "" {
		if err := writeReportsHTML(*htmlOut, "certops check", []checker.Report{report}); err != nil {
			fatal(err.Error())
		}
	}
	if err := exportReportsOTEL(*otelEndpoint, []checker.Report{report}); err != nil {
		fatal(err.Error())
	}
	printReports([]checker.Report{report}, format)
	os.Exit(exitForReports([]checker.Report{report}, *failOn))
}

func printReports(reports []checker.Report, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(reports)
	case outputYAML:
		printYAMLReports(reports)
	case outputProm:
		printPromReports(reports)
	default:
		for i, report := range reports {
			if i > 0 {
				fmt.Println()
			}
			printRawReport(report)
		}
	}
}

func printRawReport(report checker.Report) {
	fmt.Printf("%s  cert report\n", report.Host)
	fmt.Printf("target: %s\n", report.Target)
	fmt.Printf("status: %s\n", statusColor(report.Status))
	if report.Error != "" {
		fmt.Printf("error: %s\n", report.Error)
	}
	fmt.Println()

	rows := [][]string{
		{"certificate", "issuer", emptyDash(shortIssuer(report.Certificate.Issuer)), "info"},
		{"certificate", "expires_at", prettyTimestamp(report.Certificate.NotAfter), expiryStatus(report)},
		{"certificate", "expires_in", expiryDaysCell(report), expiryStatus(report)},
		{"certificate", "chain", statusColor(okWord(report.Certificate.Trusted, "trusted", "untrusted")), statusColor(okCritical(report.Certificate.Trusted))},
		{"certificate", "hostname", statusColor(okWord(report.Certificate.MatchesHost, "matches", "mismatch")), statusColor(okCritical(report.Certificate.MatchesHost))},
		{"certificate", "sans", compactList(report.Certificate.DNSNames, 3), "info"},
		{"certificate", "public_key", certificateKeyCell(report), certificateCryptoStatus(report)},
		{"certificate", "signature", emptyDash(report.Certificate.SignatureAlgorithm), certificateCryptoStatus(report)},
		{"certificate", "chain_length", strconv.Itoa(len(report.Chain)), "info"},
		{"tls", "negotiated", emptyDash(report.TLS.NegotiatedVersion) + " / " + emptyDash(report.TLS.CipherSuite), "info"},
		{"tls", "versions", strings.Join(report.TLS.SupportedVersions, ", "), tlsVersionsStatus(report)},
		{"tls", "alpn", emptyDash(report.TLS.ALPN), "info"},
		{"tls", "ocsp_stapling", ocspCell(report), ocspStatus(report)},
		{"tls", "handshake_ms", strconv.FormatInt(report.TLS.HandshakeMS, 10), "info"},
		{"https", "http_redirect", statusColor(httpRedirectCell(report)), statusColor(httpRedirectStatus(report))},
		{"https", "hsts", hstsCell(report.HTTPS.HSTS), statusColor(warnIfFalse(report.HTTPS.HSTSEnabled))},
		{"revocation", "crl", revocationCell(report), revocationStatus(report)},
	}
	renderTable([]string{"scope", "check", "value", "status"}, rows)

	fmt.Println()
	renderFindings(report.Findings)
	fmt.Printf("\nsummary: status=%s, findings=%d\n", statusColor(report.Status), len(report.Findings))
}

func certificateKeyCell(report checker.Report) string {
	if report.Certificate.PublicKeyAlgorithm == "" {
		return "-"
	}
	if report.Certificate.PublicKeyBits == 0 {
		return report.Certificate.PublicKeyAlgorithm
	}
	return fmt.Sprintf("%s %d-bit", report.Certificate.PublicKeyAlgorithm, report.Certificate.PublicKeyBits)
}

func certificateCryptoStatus(report checker.Report) string {
	for _, finding := range report.Findings {
		if finding.Scope == "certificate" && (strings.Contains(finding.Message, "public key") || strings.Contains(finding.Message, "signature algorithm")) {
			return statusColor(finding.Severity)
		}
	}
	return statusColor("ok")
}

func ocspCell(report checker.Report) string {
	if !report.TLS.OCSPStapling {
		return statusColor("missing")
	}
	if report.TLS.OCSPStatus == "" {
		return statusColor("present")
	}
	return statusColor(report.TLS.OCSPStatus)
}

func ocspStatus(report checker.Report) string {
	switch report.TLS.OCSPStatus {
	case "good":
		return statusColor("ok")
	case "revoked", "invalid":
		return statusColor("critical")
	case "unknown", "unverified":
		return statusColor("warn")
	default:
		return statusColor(warnIfFalse(report.TLS.OCSPStapling))
	}
}

func renderFindings(findings []checker.Finding) {
	fmt.Println("findings:")
	if len(findings) == 0 {
		fmt.Println("  none")
		return
	}
	rows := make([][]string, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, []string{statusColor(finding.Severity), finding.Scope, finding.Message})
	}
	renderTable([]string{"severity", "scope", "message"}, rows)
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func yesNo(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func okWord(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func okCritical(ok bool) string {
	if ok {
		return "ok"
	}
	return "critical"
}

func httpRedirectCell(report checker.Report) string {
	if !report.HTTPS.HTTPRedirectChecked {
		return "skipped"
	}
	return okWord(report.HTTPS.HTTPRedirectOK, "ok", "not confirmed")
}

func httpRedirectStatus(report checker.Report) string {
	if !report.HTTPS.HTTPRedirectChecked {
		return "info"
	}
	return warnIfFalse(report.HTTPS.HTTPRedirectOK)
}

func warnIfFalse(ok bool) string {
	if ok {
		return "ok"
	}
	return "warn"
}

func expiryDaysCell(report checker.Report) string {
	if report.Certificate.NotAfter == "" {
		return "-"
	}
	value := fmt.Sprintf("%d days", report.Certificate.DaysRemaining)
	switch strings.TrimSpace(ansiPattern.ReplaceAllString(expiryStatus(report), "")) {
	case "critical":
		return colorize(value, "\x1b[31m")
	case "warn":
		return colorize(value, "\x1b[33m")
	default:
		return colorize(value, "\x1b[32m")
	}
}

func prettyTimestamp(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return ts.UTC().Format("2006-01-02 15:04 UTC")
}

func expiryStatus(report checker.Report) string {
	for _, finding := range report.Findings {
		if finding.Scope == "certificate" && strings.Contains(finding.Message, "expires") {
			return statusColor(finding.Severity)
		}
	}
	return statusColor("ok")
}

func tlsVersionsStatus(report checker.Report) string {
	if hasString(report.TLS.SupportedVersions, "TLS1.0") || hasString(report.TLS.SupportedVersions, "TLS1.1") {
		return statusColor("warn")
	}
	if !hasString(report.TLS.SupportedVersions, "TLS1.2") && !hasString(report.TLS.SupportedVersions, "TLS1.3") {
		return statusColor("critical")
	}
	return statusColor("ok")
}

func hstsCell(value string) string {
	if strings.TrimSpace(value) == "" {
		return statusColor("missing")
	}
	return value
}

func revocationCell(report checker.Report) string {
	if !report.Revocation.Checked {
		return "not checked"
	}
	if report.Revocation.Revoked {
		return statusColor("revoked")
	}
	if len(report.Revocation.Errors) > 0 {
		return statusColor("errors")
	}
	return statusColor("not revoked")
}

func revocationStatus(report checker.Report) string {
	if !report.Revocation.Checked {
		return "info"
	}
	if report.Revocation.Revoked || len(report.Revocation.Errors) > 0 {
		return statusColor("critical")
	}
	status := "ok"
	for _, finding := range report.Findings {
		if finding.Scope != "revocation" {
			continue
		}
		if finding.Severity == "critical" {
			return statusColor("critical")
		}
		if finding.Severity == "warn" {
			status = "warn"
		}
	}
	return statusColor(status)
}

func compactList(values []string, max int) string {
	if len(values) == 0 {
		return "-"
	}
	if len(values) <= max {
		return strings.Join(values, ", ")
	}
	return strings.Join(values[:max], ", ") + fmt.Sprintf(" (+%d more)", len(values)-max)
}

func shortIssuer(issuer string) string {
	if strings.TrimSpace(issuer) == "" {
		return "-"
	}
	parts := strings.Split(issuer, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return issuer
}

func exitForReports(reports []checker.Report, failOn string) int {
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

func defaultCRLCABundle(crlCABundle, caBundle string) string {
	if strings.TrimSpace(crlCABundle) != "" {
		return crlCABundle
	}
	return caBundle
}
