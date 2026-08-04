package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type driftReport struct {
	File    string      `json:"file" yaml:"file"`
	Status  string      `json:"status" yaml:"status"`
	Summary planSummary `json:"summary" yaml:"summary"`
	Items   []planItem  `json:"items" yaml:"items"`
	Errors  []planError `json:"errors,omitempty" yaml:"errors,omitempty"`
}

func cmdDrift(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true, "--fail-on": true, "--html": true, "--timeout": true})
	fs := flag.NewFlagSet("drift", flag.ExitOnError)
	file := fs.String("f", "certops.yaml", "config file")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	htmlOut := fs.String("html", "", "write HTML report to path")
	failOn := fs.String("fail-on", "", "exit non-zero on warn or critical; defaults to policy.fail_on or warn")
	timeout := fs.Duration("timeout", 10*time.Second, "network timeout for live checks")
	noLive := fs.Bool("no-live", false, "skip live CA and service checks")
	fs.Parse(args)

	format, err := resolveOutput(*jsonOut, *yamlOut, false)
	if err != nil {
		fatal(err.Error())
	}
	if err := validateFailOn(*failOn); err != nil {
		fatal(err.Error())
	}
	if err := validateTimeout(*timeout); err != nil {
		fatal(err.Error())
	}
	cfg, err := loadConfig(*file)
	if err != nil {
		fatal(err.Error())
	}
	plan := buildPlanReport(defaultConfigPath(*file), cfg, planOptions{Live: !*noLive, Timeout: *timeout})
	report := buildDriftReport(plan)
	if strings.TrimSpace(*htmlOut) != "" {
		if err := writeDriftHTML(*htmlOut, report); err != nil {
			fatal(err.Error())
		}
	}
	printDriftReport(report, format)
	os.Exit(exitForDrift(report, effectiveFailOn(*failOn, cfg.Policy.FailOn, "warn")))
}

func buildDriftReport(plan planReport) driftReport {
	items := make([]planItem, 0, len(plan.Items))
	for _, item := range plan.Items {
		if item.Status != "ok" || item.Action == "manual" {
			items = append(items, item)
		}
	}
	summary := summarizePlan(items)
	return driftReport{
		File:    plan.File,
		Status:  statusFromSummary(summary),
		Summary: summary,
		Items:   items,
		Errors:  plan.Errors,
	}
}

func printDriftReport(report driftReport, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(report)
	case outputYAML:
		printYAMLValue(report)
	default:
		fmt.Printf("drift  %s\n", report.File)
		fmt.Printf("status: %s\n\n", statusColor(report.Status))
		if len(report.Items) == 0 {
			fmt.Println("no drift detected")
			fmt.Println()
			fmt.Println("summary: total=0 warn=0 critical=0 manual=0")
			return
		}
		rows := make([][]string, 0, len(report.Items))
		for _, item := range report.Items {
			rows = append(rows, []string{item.Scope, item.Target, statusColor(item.Status), item.Change, emptyDash(item.Expected), emptyDash(item.Actual)})
		}
		renderTable([]string{"scope", "target", "severity", "drift", "expected", "actual"}, rows)
		fmt.Printf("\nsummary: total=%d warn=%d critical=%d manual=%d\n", report.Summary.Total, report.Summary.Warn, report.Summary.Critical, report.Summary.Manual)
	}
}

func exitForDrift(report driftReport, failOn string) int {
	failOn = effectiveFailOn(failOn, "", "warn")
	if report.Summary.Critical > 0 {
		return 1
	}
	if failOn == "warn" && report.Summary.Warn > 0 {
		return 1
	}
	return 0
}
