package main

import (
	"flag"
	"os"
	"strings"
	"time"
)

func cmdCAVault(args []string) {
	if len(args) < 1 {
		fatal("usage: certops ca vault <health|ca|info> --url http://127.0.0.1:8200")
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	switch action {
	case "health", "ca", "info":
		cmdCAVaultAction(action, args[1:])
	default:
		fatal("unknown Vault command: " + args[0])
	}
}

func cmdCAVaultAction(action string, args []string) {
	args = normalizeFlagArgs(args, map[string]bool{
		"--fingerprint": true,
		"--issuer":      true,
		"--mount":       true,
		"--namespace":   true,
		"--out":         true,
		"--timeout":     true,
		"--token":       true,
		"--url":         true,
	})
	fs := flag.NewFlagSet("ca vault "+action, flag.ExitOnError)
	baseURL := fs.String("url", "", "Vault base URL")
	mount := fs.String("mount", "pki", "Vault PKI mount path")
	issuer := fs.String("issuer", "", "Vault PKI issuer ref; empty uses default CA endpoint")
	fingerprint := fs.String("fingerprint", "", "expected CA SHA256 fingerprint")
	out := fs.String("out", "", "write CA PEM to path")
	token := fs.String("token", "", "Vault token; defaults to VAULT_TOKEN")
	namespace := fs.String("namespace", "", "Vault namespace header")
	timeout := fs.Duration("timeout", 10*time.Second, "network timeout")
	standbyOK := fs.Bool("standby-ok", false, "treat Vault standby health as ok")
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
	if err := validateAPIPath("mount", *mount); err != nil {
		fatal(err.Error())
	}
	if err := validateAPIPath("issuer", *issuer); err != nil {
		fatal(err.Error())
	}
	if err := validateTimeout(*timeout); err != nil {
		fatal(err.Error())
	}
	if err := validateFingerprint(*fingerprint); err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(*out) != "" && action == "health" {
		fatal("--out is only supported for ca and info")
	}
	if strings.TrimSpace(*token) == "" {
		*token = os.Getenv("VAULT_TOKEN")
	}

	opts := vaultOptions{
		BaseURL:     *baseURL,
		Mount:       *mount,
		Issuer:      *issuer,
		Fingerprint: *fingerprint,
		Token:       *token,
		Namespace:   *namespace,
		Timeout:     *timeout,
		StandbyOK:   *standbyOK,
	}
	report, caPEM, err := runVault(action, opts)
	if err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(*out) != "" && report.Status != "critical" {
		if err := writeFileAtomic(*out, caPEM, 0644); err != nil {
			fatal(err.Error())
		}
		report.CA.OutputPath = *out
	}

	printVaultReport(report, format)
	if report.Status == "critical" {
		os.Exit(1)
	}
}
