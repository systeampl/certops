package main

import (
	"flag"
	"os"
	"strings"
)

func cmdCAGeneric(args []string) {
	if len(args) < 1 {
		fatal("usage: certops ca generic info --ca-bundle root.pem|--url https://pki.example.com/root.pem")
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	if action != "info" {
		fatal("unknown generic CA command: " + args[0])
	}
	cmdCAGenericInfo(args[1:])
}

func cmdCAGenericInfo(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{
		"--ca-bundle":   true,
		"--fingerprint": true,
		"--out":         true,
		"--url":         true,
	})
	fs := flag.NewFlagSet("ca generic info", flag.ExitOnError)
	caBundle := fs.String("ca-bundle", "", "local PEM CA bundle")
	rawURL := fs.String("url", "", "generic PEM bundle URL")
	fingerprint := fs.String("fingerprint", "", "expected CA SHA256 fingerprint; required for URL source")
	out := fs.String("out", "", "write CA PEM to path")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	promOut := fs.Bool("prom", false, "emit Prometheus text output")
	fs.Parse(args)

	format, err := resolveOutput(*jsonOut, *yamlOut, *promOut)
	if err != nil {
		fatal(err.Error())
	}
	if err := validateFingerprint(*fingerprint); err != nil {
		fatal(err.Error())
	}
	report, caPEM, err := runGenericCA(*caBundle, *rawURL, *fingerprint)
	if err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(*out) != "" && report.Status != "critical" {
		if err := writeFileAtomic(*out, caPEM, 0644); err != nil {
			fatal(err.Error())
		}
		report.CA.OutputPath = *out
	}

	printGenericCAReport(report, format)
	if report.Status == "critical" {
		os.Exit(1)
	}
}
