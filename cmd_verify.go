package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/systeampl/certops/internal/verify"

	"gopkg.in/yaml.v3"
)

func cmdVerify(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true, "--fail-on": true, "--html": true, "--otel-endpoint": true, "--interval": true, "--watch-timeout": true, "--max-iterations": true})
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	file := fs.String("f", "", "YAML verification spec")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	promOut := fs.Bool("prom", false, "emit Prometheus text output")
	htmlOut := fs.String("html", "", "write HTML report to path")
	otelEndpoint := fs.String("otel-endpoint", "", "export OTLP/HTTP metrics to endpoint, for example http://localhost:4318")
	failOn := fs.String("fail-on", "critical", "exit non-zero on warn or critical")
	watch := fs.Bool("watch", false, "rerun the check until interrupted")
	interval := fs.Duration("interval", 5*time.Second, "watch interval")
	watchTimeout := fs.Duration("watch-timeout", 0, "maximum watch duration (0 = unlimited)")
	maxIterations := fs.Int("max-iterations", 0, "maximum watch iterations (0 = unlimited)")
	untilOK := fs.Bool("until-ok", false, "in watch mode, stop automatically once the check is healthy")
	fs.Parse(args)

	if strings.TrimSpace(*file) == "" {
		fatal("usage: certops verify -f certs.yaml [--json|--yaml|--prom]")
	}
	format, err := resolveOutput(*jsonOut, *yamlOut, *promOut)
	if err != nil {
		fatal(err.Error())
	}
	if err := validateFailOn(*failOn); err != nil {
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
	spec, err := verify.Load(*file)
	if err != nil {
		fatal(err.Error())
	}
	runOnce := func() verify.Report {
		return verify.Run(context.Background(), *file, spec, normalizeTarget)
	}
	if watchCfg.Enabled {
		err := watchLoop(watchCfg, format, func() (any, bool, error) {
			report := runOnce()
			return report, exitForVerify(report, *failOn) == 0, nil
		}, func(v any) {
			printVerifyReport(v.(verify.Report), outputRaw)
		})
		if err != nil {
			fatal(err.Error())
		}
		return
	}

	report := runOnce()
	if strings.TrimSpace(*htmlOut) != "" {
		if err := writeVerifyHTML(*htmlOut, report); err != nil {
			fatal(err.Error())
		}
	}
	if err := exportVerifyOTEL(*otelEndpoint, report); err != nil {
		fatal(err.Error())
	}
	printVerifyReport(report, format)
	os.Exit(exitForVerify(report, *failOn))
}

func printVerifyReport(report verify.Report, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(report)
	case outputYAML:
		enc := yaml.NewEncoder(os.Stdout)
		defer enc.Close()
		if err := enc.Encode(report); err != nil {
			fatal(err.Error())
		}
	case outputProm:
		printVerifyProm(report)
	default:
		printVerifyRaw(report)
	}
}

func printVerifyRaw(report verify.Report) {
	fmt.Printf("verify  %s\n\n", report.File)
	rows := make([][]string, 0, len(report.Results))
	for _, result := range report.Results {
		detail := "-"
		if len(result.Findings) > 0 {
			detail = result.Findings[0].Message
			if len(result.Findings) > 1 {
				detail += fmt.Sprintf(" (+%d more)", len(result.Findings)-1)
			}
		} else if result.Error != "" {
			detail = result.Error
		}
		rows = append(rows, []string{result.Name, result.Target, statusColor(result.Status), detail})
	}
	renderTable([]string{"name", "target", "status", "detail"}, rows)
	fmt.Printf("\nsummary: %d/%d matched, %d failed\n", report.Matched, report.Total, report.Errors)
}

func printVerifyProm(report verify.Report) {
	fmt.Println("# HELP certops_verify_target_ok Certificate verification target status (1=ok, 0=failed).")
	fmt.Println("# TYPE certops_verify_target_ok gauge")
	fmt.Println("# HELP certops_verify_summary_matched Number of matched targets.")
	fmt.Println("# TYPE certops_verify_summary_matched gauge")
	fmt.Println("# HELP certops_verify_summary_total Total number of targets.")
	fmt.Println("# TYPE certops_verify_summary_total gauge")
	fmt.Println("# HELP certops_verify_summary_errors Number of failed targets.")
	fmt.Println("# TYPE certops_verify_summary_errors gauge")
	for _, result := range report.Results {
		fmt.Printf("certops_verify_target_ok{%s} %d\n", promLabels(map[string]string{
			"file":   report.File,
			"name":   result.Name,
			"target": result.Target,
		}), boolInt(result.Status == "ok"))
	}
	fmt.Printf("certops_verify_summary_matched{%s} %d\n", promLabels(map[string]string{"file": report.File}), report.Matched)
	fmt.Printf("certops_verify_summary_total{%s} %d\n", promLabels(map[string]string{"file": report.File}), report.Total)
	fmt.Printf("certops_verify_summary_errors{%s} %d\n", promLabels(map[string]string{"file": report.File}), report.Errors)
}

func exitForVerify(report verify.Report, failOn string) int {
	failOn = strings.ToLower(strings.TrimSpace(failOn))
	if failOn == "" {
		failOn = "critical"
	}
	for _, result := range report.Results {
		switch result.Status {
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
