package main

import (
	"flag"
	"os"
	"strings"
	"time"
)

func cmdCACFSSL(args []string) {
	if len(args) < 1 {
		fatal("usage: certops ca cfssl <health|info> --url http://127.0.0.1:8888")
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	switch action {
	case "health", "info":
		cmdCACFSSLAction(action, args[1:])
	default:
		fatal("unknown CFSSL command: " + args[0])
	}
}

func cmdCACFSSLAction(action string, args []string) {
	args = normalizeFlagArgs(args, map[string]bool{
		"--fingerprint": true,
		"--label":       true,
		"--out":         true,
		"--profile":     true,
		"--timeout":     true,
		"--url":         true,
	})
	fs := flag.NewFlagSet("ca cfssl "+action, flag.ExitOnError)
	baseURL := fs.String("url", "", "CFSSL API base URL")
	label := fs.String("label", "", "CFSSL CA label")
	profile := fs.String("profile", "", "CFSSL signing profile")
	fingerprint := fs.String("fingerprint", "", "expected CA SHA256 fingerprint")
	out := fs.String("out", "", "write CA PEM to path")
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
	if strings.TrimSpace(*out) != "" && action == "health" {
		fatal("--out is only supported for info")
	}

	opts := cfsslOptions{
		BaseURL:     *baseURL,
		Label:       *label,
		Profile:     *profile,
		Fingerprint: *fingerprint,
		Timeout:     *timeout,
	}
	report, caPEM, err := runCFSSL(action, opts)
	if err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(*out) != "" && report.Status != "critical" {
		if err := writeFileAtomic(*out, caPEM, 0644); err != nil {
			fatal(err.Error())
		}
		report.CA.OutputPath = *out
	}

	printCFSSLReport(report, format)
	if report.Status == "critical" {
		os.Exit(1)
	}
}
