package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cmdCA(args []string) {
	if len(args) < 1 {
		fatal("usage: certops ca <provider> <command>")
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "fetch":
		cmdCAFetch(args[1:])
	case "list":
		cmdCAList(args[1:])
	case "cfssl":
		cmdCACFSSL(args[1:])
	case "generic":
		cmdCAGeneric(args[1:])
	case "smallstep":
		cmdCASmallstep(args[1:])
	case "vault":
		cmdCAVault(args[1:])
	default:
		fatal("unknown CA provider: " + args[0])
	}
}

type caConfigRow struct {
	Name        string `json:"name" yaml:"name"`
	Provider    string `json:"provider" yaml:"provider"`
	URL         string `json:"url,omitempty" yaml:"url,omitempty"`
	CABundle    string `json:"ca_bundle,omitempty" yaml:"ca_bundle,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Insecure    bool   `json:"insecure,omitempty" yaml:"insecure,omitempty"`
	Mount       string `json:"mount,omitempty" yaml:"mount,omitempty"`
	Issuer      string `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Label       string `json:"label,omitempty" yaml:"label,omitempty"`
	Profile     string `json:"profile,omitempty" yaml:"profile,omitempty"`
}

func cmdCAList(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true})
	fs := flag.NewFlagSet("ca list", flag.ExitOnError)
	file := fs.String("f", "certops.yaml", "config file")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	fs.Parse(args)
	format, err := resolveOutput(*jsonOut, *yamlOut, false)
	if err != nil {
		fatal(err.Error())
	}
	cfg, err := loadConfig(*file)
	if err != nil {
		fatal(err.Error())
	}
	rows := make([]caConfigRow, 0, len(cfg.CAs))
	for _, ca := range cfg.CAs {
		rows = append(rows, caConfigRow{
			Name:        ca.Name,
			Provider:    ca.Provider,
			URL:         ca.URL,
			CABundle:    ca.CABundle,
			Fingerprint: ca.Fingerprint,
			Insecure:    ca.Insecure,
			Mount:       ca.Mount,
			Issuer:      ca.Issuer,
			Label:       ca.Label,
			Profile:     ca.Profile,
		})
	}
	printCARows(rows, format)
}

func cmdCAFetch(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true, "--out": true})
	fs := flag.NewFlagSet("ca fetch", flag.ExitOnError)
	file := fs.String("f", "certops.yaml", "config file")
	outDir := fs.String("out", "roots", "directory for fetched PEM bundles")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	fs.Parse(args)
	format, err := resolveOutput(*jsonOut, *yamlOut, false)
	if err != nil {
		fatal(err.Error())
	}
	cfg, err := loadConfig(*file)
	if err != nil {
		fatal(err.Error())
	}
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fatal(err.Error())
	}
	results := []caFetchResult{}
	for _, ca := range cfg.CAs {
		result := fetchConfiguredCA(ca, *outDir)
		results = append(results, result)
	}
	printCAFetchResults(results, format)
	if hasCAFetchFailure(results) {
		os.Exit(1)
	}
}

type caFetchResult struct {
	Name     string `json:"name" yaml:"name"`
	Provider string `json:"provider" yaml:"provider"`
	Status   string `json:"status" yaml:"status"`
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`
	Error    string `json:"error,omitempty" yaml:"error,omitempty"`
	Count    int    `json:"count" yaml:"count"`
}

func fetchConfiguredCA(ca configCA, outDir string) caFetchResult {
	result := caFetchResult{Name: ca.Name, Provider: ca.Provider, Status: "ok"}
	path := filepath.Join(outDir, sanitizeTrustName(ca.Name)+".pem")
	pemData, count, err := configuredCAPEM(ca)
	if err != nil {
		result.Status = "critical"
		result.Error = err.Error()
		return result
	}
	if err := writeFileAtomic(path, pemData, 0644); err != nil {
		result.Status = "critical"
		result.Error = err.Error()
		return result
	}
	result.Path = path
	result.Count = count
	return result
}

func configuredCAPEM(ca configCA) ([]byte, int, error) {
	switch strings.ToLower(strings.TrimSpace(ca.Provider)) {
	case "smallstep":
		report, pemData, err := runSmallstep("roots", ca.URL, ca.Fingerprint, 10*time.Second, ca.Insecure)
		if err != nil {
			return nil, 0, err
		}
		if report.Status == "critical" {
			return nil, 0, fmt.Errorf("Smallstep root validation failed: %s", firstSmallstepFinding(report))
		}
		certs, _, err := parseTrustCerts(pemData)
		return pemData, len(certs), err
	case "vault":
		opts := vaultOptions{
			BaseURL:     ca.URL,
			Mount:       ca.Mount,
			Issuer:      ca.Issuer,
			Fingerprint: ca.Fingerprint,
			Token:       os.Getenv("VAULT_TOKEN"),
			Timeout:     10 * time.Second,
		}
		report, pemData, err := runVault("ca", opts)
		if err != nil {
			return nil, 0, err
		}
		if report.Status == "critical" {
			return nil, 0, fmt.Errorf("Vault CA validation failed: %s", firstVaultFinding(report))
		}
		certs, _, err := parseTrustCerts(pemData)
		return pemData, len(certs), err
	case "cfssl":
		opts := cfsslOptions{
			BaseURL:     ca.URL,
			Label:       ca.Label,
			Profile:     ca.Profile,
			Fingerprint: ca.Fingerprint,
			Timeout:     10 * time.Second,
		}
		report, pemData, err := runCFSSL("info", opts)
		if err != nil {
			return nil, 0, err
		}
		if report.Status == "critical" {
			return nil, 0, fmt.Errorf("CFSSL CA validation failed: %s", firstCFSSLFinding(report))
		}
		certs, _, err := parseTrustCerts(pemData)
		return pemData, len(certs), err
	case "generic":
		report, pemData, err := runGenericCA(ca.CABundle, ca.URL, ca.Fingerprint)
		if err != nil {
			return nil, 0, err
		}
		if report.Status == "critical" {
			return nil, 0, fmt.Errorf("generic CA validation failed")
		}
		return pemData, report.CA.Count, nil
	default:
		return nil, 0, fmt.Errorf("unsupported provider: %s", ca.Provider)
	}
}

func firstSmallstepFinding(report smallstepReport) string {
	if len(report.Findings) > 0 {
		return report.Findings[0].Message
	}
	return report.Status
}

func firstVaultFinding(report vaultReport) string {
	if len(report.Findings) > 0 {
		return report.Findings[0].Message
	}
	return report.Status
}

func firstCFSSLFinding(report cfsslReport) string {
	if len(report.Findings) > 0 {
		return report.Findings[0].Message
	}
	return report.Status
}

func printCARows(rows []caConfigRow, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(rows)
	case outputYAML:
		printYAMLValue(rows)
	default:
		table := make([][]string, 0, len(rows))
		for _, row := range rows {
			source := row.URL
			if source == "" {
				source = row.CABundle
			}
			table = append(table, []string{row.Name, row.Provider, emptyDash(source), emptyDash(row.Fingerprint)})
		}
		renderTable([]string{"name", "provider", "source", "fingerprint"}, table)
		fmt.Printf("\nsummary: cas=%d\n", len(rows))
	}
}

func printCAFetchResults(results []caFetchResult, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(results)
	case outputYAML:
		printYAMLValue(results)
	default:
		rows := make([][]string, 0, len(results))
		for _, result := range results {
			detail := result.Path
			if result.Error != "" {
				detail = result.Error
			}
			rows = append(rows, []string{result.Name, result.Provider, statusColor(result.Status), fmt.Sprintf("%d", result.Count), detail})
		}
		renderTable([]string{"name", "provider", "status", "certs", "detail"}, rows)
	}
}

func hasCAFetchFailure(results []caFetchResult) bool {
	for _, result := range results {
		if result.Status == "critical" || result.Status == "error" {
			return true
		}
	}
	return false
}

func cmdCASmallstep(args []string) {
	if len(args) < 1 {
		fatal("usage: certops ca smallstep <health|roots|info> --url https://ca.example.com")
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	switch action {
	case "health", "roots", "info":
		cmdCASmallstepAction(action, args[1:])
	default:
		fatal("unknown Smallstep command: " + args[0])
	}
}

func cmdCASmallstepAction(action string, args []string) {
	args = normalizeFlagArgs(args, map[string]bool{
		"--fingerprint": true,
		"--out":         true,
		"--timeout":     true,
		"--url":         true,
	})
	fs := flag.NewFlagSet("ca smallstep "+action, flag.ExitOnError)
	baseURL := fs.String("url", "", "Smallstep CA base URL")
	fingerprint := fs.String("fingerprint", "", "expected root SHA256 fingerprint")
	insecure := fs.Bool("insecure", false, "skip HTTPS certificate verification for CA bootstrap")
	out := fs.String("out", "", "write roots PEM bundle to path")
	timeout := fs.Duration("timeout", 10*time.Second, "network timeout")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	promOut := fs.Bool("prom", false, "emit Prometheus text output")
	fs.Parse(args)

	format, err := resolveOutput(*jsonOut, *yamlOut, *promOut)
	if err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(*baseURL) == "" {
		fatal("--url is required")
	}
	if err := validateHTTPURL(*baseURL); err != nil {
		fatal(err.Error())
	}
	if err := validateTimeout(*timeout); err != nil {
		fatal(err.Error())
	}
	if err := validateFingerprint(*fingerprint); err != nil {
		fatal(err.Error())
	}
	if *insecure && action != "health" && strings.TrimSpace(*fingerprint) == "" {
		fatal("--fingerprint is required with --insecure when fetching CA material")
	}
	if strings.TrimSpace(*out) != "" && action == "health" {
		fatal("--out is only supported for roots and info")
	}

	report, rootsPEM, err := runSmallstep(action, *baseURL, *fingerprint, *timeout, *insecure)
	if err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(*out) != "" && report.Status != "critical" {
		if err := writeFileAtomic(*out, rootsPEM, 0644); err != nil {
			fatal(err.Error())
		}
		report.Roots.OutputPath = *out
	}

	printSmallstepReport(report, format)
	if report.Status == "critical" {
		os.Exit(1)
	}
}
