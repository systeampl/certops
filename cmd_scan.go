package main

import (
	"bufio"
	"context"
	"flag"
	"os"
	"strings"
	"sync"
	"time"

	checker "github.com/systeampl/certops/internal/check"
)

func cmdScan(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--input": true, "--warn-days": true, "--critical-days": true, "--ca-bundle": true, "--crl": true, "--crl-ca-bundle": true, "--crl-warn-days": true, "--crl-critical-days": true, "--crl-max-age-days": true, "--fail-on": true, "--timeout": true, "--html": true, "--otel-endpoint": true, "--concurrency": true})
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	input := fs.String("input", "", "input file with one host/url per line")
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
	autoCRL := fs.Bool("auto-crl", false, "fetch and verify CRLs advertised by leaf certificates")
	concurrency := fs.Int("concurrency", 4, "maximum concurrent target checks")
	failOn := fs.String("fail-on", "critical", "exit non-zero on warn or critical")
	timeout := fs.Duration("timeout", 10*time.Second, "network timeout")
	fs.Parse(args)

	targets := append([]string(nil), fs.Args()...)
	if *input != "" {
		rows, err := readInput(*input)
		if err != nil {
			fatal(err.Error())
		}
		targets = append(targets, rows...)
	}
	if len(targets) == 0 {
		fatal("usage: certops scan --input domains.txt [--json|--yaml|--prom]")
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
	if *concurrency < 1 || *concurrency > 128 {
		fatal("--concurrency must be between 1 and 128")
	}

	crlBundle := defaultCRLCABundle(*crlCABundle, *caBundle)
	insecureSources := map[string]bool{}
	if *crlInsecure {
		for _, source := range crls {
			insecureSources[source] = true
		}
	}
	reports := runScanTargets(context.Background(), targets, *concurrency, checker.Options{
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
	if strings.TrimSpace(*htmlOut) != "" {
		if err := writeReportsHTML(*htmlOut, "certops scan", reports); err != nil {
			fatal(err.Error())
		}
	}
	if err := exportReportsOTEL(*otelEndpoint, reports); err != nil {
		fatal(err.Error())
	}
	printReports(reports, format)
	os.Exit(exitForReports(reports, *failOn))
}

func readInput(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func runScanTargets(ctx context.Context, targets []string, concurrency int, opts checker.Options) []checker.Report {
	reports := make([]checker.Report, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				target := targets[index]
				host, address, err := normalizeTarget(target)
				if err != nil {
					reports[index] = checker.Report{
						SchemaVersion: checker.SchemaVersion,
						Target:        target,
						Host:          target,
						Status:        "error",
						Error:         err.Error(),
					}
					continue
				}
				reports[index] = checker.Run(ctx, host, address, opts)
			}
		}()
	}
	for index := range targets {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	return reports
}
