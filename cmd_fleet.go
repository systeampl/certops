package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type fleetTrustReport struct {
	Action  string              `json:"action" yaml:"action"`
	File    string              `json:"file" yaml:"file"`
	Status  string              `json:"status" yaml:"status"`
	Summary fleetTrustSummary   `json:"summary" yaml:"summary"`
	Items   []fleetTrustItem    `json:"items" yaml:"items"`
	Errors  []fleetTrustFailure `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type fleetTrustSummary struct {
	Total    int `json:"total" yaml:"total"`
	OK       int `json:"ok" yaml:"ok"`
	Warn     int `json:"warn" yaml:"warn"`
	Critical int `json:"critical" yaml:"critical"`
}

type fleetTrustItem struct {
	Host    string `json:"host" yaml:"host"`
	Address string `json:"address" yaml:"address"`
	User    string `json:"user,omitempty" yaml:"user,omitempty"`
	Port    string `json:"port,omitempty" yaml:"port,omitempty"`
	OS      string `json:"os,omitempty" yaml:"os,omitempty"`
	CA      string `json:"ca" yaml:"ca"`
	Status  string `json:"status" yaml:"status"`
	Path    string `json:"path,omitempty" yaml:"path,omitempty"`
	Message string `json:"message" yaml:"message"`
}

type fleetTrustFailure struct {
	Host  string `json:"host" yaml:"host"`
	CA    string `json:"ca,omitempty" yaml:"ca,omitempty"`
	Error string `json:"error" yaml:"error"`
}

func cmdFleet(args []string) {
	if len(args) < 1 {
		fatal("usage: certops fleet trust <plan|verify|install|apply|remove> -f certops.yaml")
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "trust":
		cmdFleetTrust(args[1:])
	default:
		fatal("unknown fleet command: " + args[0])
	}
}

func cmdFleetTrust(args []string) {
	if len(args) < 1 {
		fatal("usage: certops fleet trust <plan|verify|install|apply|remove> -f certops.yaml")
	}
	displayAction := strings.ToLower(strings.TrimSpace(args[0]))
	action := displayAction
	switch action {
	case "apply":
		action = "install"
	case "plan", "verify", "install", "remove":
	default:
		fatal("unknown fleet trust action: " + args[0])
	}
	args = normalizeFlagArgs(args[1:], map[string]bool{"-f": true, "--limit": true, "--html": true, "--fail-on": true})
	fs := flag.NewFlagSet("fleet trust "+displayAction, flag.ExitOnError)
	file := fs.String("f", "certops.yaml", "config file")
	limit := fs.String("limit", "", "limit to host or group")
	htmlOut := fs.String("html", "", "write HTML report to path")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	yes := fs.Bool("yes", false, "allow remote trust-store changes for install")
	failOn := fs.String("fail-on", "", "exit non-zero on warn or critical; defaults to policy.fail_on or critical")
	fs.Parse(args)

	format, err := resolveOutput(*jsonOut, *yamlOut, false)
	if err != nil {
		fatal(err.Error())
	}
	if err := validateFailOn(*failOn); err != nil {
		fatal(err.Error())
	}
	if (action == "install" || action == "remove") && !*yes {
		fatal("fleet trust install/apply/remove requires --yes")
	}
	cfg, err := loadConfig(*file)
	if err != nil {
		fatal(err.Error())
	}
	report := runFleetTrust(action, defaultConfigPath(*file), cfg, *limit)
	report.Action = displayAction
	if strings.TrimSpace(*htmlOut) != "" {
		if err := writeFleetTrustHTML(*htmlOut, report); err != nil {
			fatal(err.Error())
		}
	}
	printFleetTrustReport(report, format)
	effective := effectiveFailOn(*failOn, cfg.Policy.FailOn, "critical")
	if report.Status == "critical" || (report.Status == "warn" && effective == "warn") {
		os.Exit(1)
	}
}

func printFleetTrustReport(report fleetTrustReport, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(report)
	case outputYAML:
		printYAMLValue(report)
	default:
		fmt.Printf("fleet trust %s  %s\n", report.Action, report.File)
		fmt.Printf("status: %s\n\n", report.Status)
		rows := make([][]string, 0, len(report.Items))
		for _, item := range report.Items {
			rows = append(rows, []string{item.Host, hostEndpoint(item.Address, item.Port), item.CA, statusColor(item.Status), emptyDash(item.Path), item.Message})
		}
		renderTable([]string{"host", "endpoint", "ca", "status", "path", "message"}, rows)
		fmt.Printf("\nsummary: total=%d ok=%d warn=%d critical=%d\n", report.Summary.Total, report.Summary.OK, report.Summary.Warn, report.Summary.Critical)
	}
}
