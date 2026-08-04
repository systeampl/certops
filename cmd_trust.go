package main

import (
	"flag"
	"os"
	"strings"
)

func cmdTrust(args []string) {
	if len(args) < 1 {
		fatal("usage: certops trust <plan|verify|install> --ca-bundle root.pem")
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	switch action {
	case "plan", "verify", "install":
		cmdTrustAction(action, args[1:])
	default:
		fatal("unknown trust action: " + args[0])
	}
}

func cmdTrustAction(action string, args []string) {
	args = normalizeFlagArgs(args, map[string]bool{
		"--ca-bundle":     true,
		"--fingerprint":   true,
		"--name":          true,
		"--fail-on":       true,
		"--smallstep-url": true,
		"--url":           true,
	})
	fs := flag.NewFlagSet("trust "+action, flag.ExitOnError)
	caBundle := fs.String("ca-bundle", "", "local PEM CA bundle")
	url := fs.String("url", "", "generic PEM bundle URL")
	smallstepURL := fs.String("smallstep-url", "", "Smallstep CA base URL; certops fetches /roots.pem")
	fingerprint := fs.String("fingerprint", "", "required SHA256 fingerprint when fetching CA material over HTTP(S)")
	name := fs.String("name", "", "trust-store friendly name")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	promOut := fs.Bool("prom", false, "emit Prometheus text output")
	yes := fs.Bool("yes", false, "allow trust-store changes for install")
	failOn := fs.String("fail-on", "critical", "exit non-zero on warn or critical")
	fs.Parse(args)

	format, err := resolveOutput(*jsonOut, *yamlOut, *promOut)
	if err != nil {
		fatal(err.Error())
	}
	if err := validateFailOn(*failOn); err != nil {
		fatal(err.Error())
	}
	source, err := loadTrustSource(*caBundle, *url, *smallstepURL, *fingerprint)
	if err != nil {
		fatal(err.Error())
	}
	certs, rawCerts, err := parseTrustCerts(source.PEM)
	if err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(*name) == "" {
		*name = defaultTrustName(source.Label, certs)
	}
	plan := buildTrustPlan(*name)
	report := buildTrustReport(action, source, certs, rawCerts, plan)

	if action == "install" {
		if report.Status == "critical" {
			printTrustReport(report, format)
			os.Exit(1)
		}
		if !*yes {
			report.Status = "warn"
			report.Findings = append(report.Findings, trustFinding{
				Severity: "warn",
				Message:  "install was not executed; rerun with --yes to modify the system trust store",
			})
			printTrustReport(report, format)
			os.Exit(1)
		}
		if plan.Install == nil {
			fatal("install is not supported on this OS yet")
		}
		if err := plan.Install(source.PEM); err != nil {
			fatal(err.Error())
		}
		report = buildTrustReport(action, source, certs, rawCerts, plan)
	}

	printTrustReport(report, format)
	if report.Status == "critical" || (report.Status == "warn" && strings.EqualFold(*failOn, "warn")) {
		os.Exit(1)
	}
}
