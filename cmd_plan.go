package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type planReport struct {
	File    string      `json:"file" yaml:"file"`
	Status  string      `json:"status" yaml:"status"`
	Summary planSummary `json:"summary" yaml:"summary"`
	Items   []planItem  `json:"items" yaml:"items"`
	Errors  []planError `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type planSummary struct {
	Total    int `json:"total" yaml:"total"`
	OK       int `json:"ok" yaml:"ok"`
	Warn     int `json:"warn" yaml:"warn"`
	Critical int `json:"critical" yaml:"critical"`
	Manual   int `json:"manual" yaml:"manual"`
}

type planItem struct {
	Action   string `json:"action" yaml:"action"`
	Scope    string `json:"scope" yaml:"scope"`
	Target   string `json:"target" yaml:"target"`
	Status   string `json:"status" yaml:"status"`
	Change   string `json:"change" yaml:"change"`
	Expected string `json:"expected,omitempty" yaml:"expected,omitempty"`
	Actual   string `json:"actual,omitempty" yaml:"actual,omitempty"`
}

type planError struct {
	Scope  string `json:"scope" yaml:"scope"`
	Target string `json:"target" yaml:"target"`
	Error  string `json:"error" yaml:"error"`
}

type planOptions struct {
	Live    bool
	Timeout time.Duration
}

func cmdPlan(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true, "--fail-on": true, "--html": true, "--timeout": true})
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	file := fs.String("f", "certops.yaml", "config file")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	htmlOut := fs.String("html", "", "write HTML report to path")
	failOn := fs.String("fail-on", "", "exit non-zero on warn or critical; defaults to policy.fail_on or critical")
	live := fs.Bool("live", false, "run live CA and service checks")
	timeout := fs.Duration("timeout", 10*time.Second, "network timeout for live checks")
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
	report := buildPlanReport(defaultConfigPath(*file), cfg, planOptions{Live: *live, Timeout: *timeout})
	if strings.TrimSpace(*htmlOut) != "" {
		if err := writePlanHTML(*htmlOut, report); err != nil {
			fatal(err.Error())
		}
	}
	printPlanReport(report, format)
	os.Exit(exitForPlan(report, effectiveFailOn(*failOn, cfg.Policy.FailOn, "critical")))
}

func buildPlanReport(file string, cfg certopsConfig, opts planOptions) planReport {
	report := planReport{File: file, Status: "ok"}
	report.Items = append(report.Items, planCAItems(cfg)...)
	report.Items = append(report.Items, planCRLItems(cfg)...)
	report.Items = append(report.Items, planInventoryItems(cfg)...)
	report.Items = append(report.Items, planTrustItems(cfg)...)
	report.Items = append(report.Items, planServiceItems(cfg)...)
	if opts.Live {
		report.Items = append(report.Items, livePlanItems(cfg, opts)...)
	}
	report.Summary = summarizePlan(report.Items)
	report.Status = statusFromSummary(report.Summary)
	return report
}

func planCRLItems(cfg certopsConfig) []planItem {
	items := []planItem{}
	cas := caNameSet(cfg)
	for _, crl := range cfg.CRLs {
		item := planItem{Action: "verify", Scope: "crl", Target: crl.Name, Status: "ok", Change: "CRL source configured"}
		source := configuredCRLSource(crl)
		item.Expected = source
		if strings.TrimSpace(source) == "" {
			item.Status = "critical"
			item.Change = "CRL source is incomplete"
			item.Expected = "file or url"
			item.Actual = "missing"
		}
		if strings.TrimSpace(crl.CA) != "" && !cas[crl.CA] {
			item.Status = "critical"
			item.Change = "CRL references unknown CA"
			item.Expected = crl.CA
			item.Actual = "missing"
		}
		items = append(items, item)
	}
	for _, service := range cfg.Services {
		target := servicePlanTarget(service)
		for _, name := range service.CRLs {
			if !crlNameSet(cfg)[name] {
				items = append(items, planItem{Action: "fail", Scope: "service", Target: target, Status: "critical", Change: "service references unknown CRL", Expected: name, Actual: "missing"})
			}
		}
	}
	return items
}

func planCAItems(cfg certopsConfig) []planItem {
	items := []planItem{}
	for _, ca := range cfg.CAs {
		item := planItem{Action: "verify", Scope: "ca", Target: ca.Name, Status: "ok"}
		switch strings.ToLower(strings.TrimSpace(ca.Provider)) {
		case "smallstep":
			item.Change = "Smallstep CA configured"
			item.Expected = "url and fingerprint"
			if ca.URL == "" || ca.Fingerprint == "" {
				item.Status = "warn"
				item.Actual = "missing url or fingerprint"
			}
		case "vault":
			item.Change = "Vault PKI configured"
			item.Expected = "url, mount and fingerprint"
			if ca.URL == "" || ca.Fingerprint == "" {
				item.Status = "warn"
				item.Actual = "missing url or fingerprint"
			}
			if ca.Mount == "" {
				item.Actual = strings.TrimSpace(item.Actual + " missing mount")
			}
		case "cfssl":
			item.Change = "CFSSL CA configured"
			item.Expected = "url and fingerprint"
			if ca.URL == "" || ca.Fingerprint == "" {
				item.Status = "warn"
				item.Actual = "missing url or fingerprint"
			}
		case "generic":
			item.Change = "generic CA source configured"
			item.Expected = "ca_bundle or url with fingerprint"
			if ca.CABundle == "" && ca.URL == "" {
				item.Status = "critical"
				item.Change = "generic CA source is incomplete"
				item.Actual = "missing ca_bundle or url"
			} else if ca.URL != "" && ca.Fingerprint == "" {
				item.Status = "critical"
				item.Change = "generic CA URL source is missing fingerprint"
				item.Actual = "URL source requires fingerprint"
			}
		default:
			item.Status = "critical"
			item.Change = "unsupported CA provider"
			item.Actual = ca.Provider
		}
		if ca.Fingerprint != "" {
			item.Expected = ca.Fingerprint
		}
		items = append(items, item)
	}
	if len(cfg.CAs) == 0 {
		items = append(items, planItem{Action: "fail", Scope: "ca", Target: "cas", Status: "critical", Change: "no CA providers configured"})
	}
	return items
}

func planInventoryItems(cfg certopsConfig) []planItem {
	rows := inventoryRows(cfg)
	items := []planItem{{
		Action: "verify",
		Scope:  "inventory",
		Target: "hosts",
		Status: "ok",
		Change: fmt.Sprintf("%d hosts configured", len(rows)),
	}}
	if len(rows) == 0 {
		items[0].Status = "warn"
		items[0].Change = "no inventory hosts configured"
	}
	for _, row := range rows {
		if strings.TrimSpace(row.Address) == "" {
			items = append(items, planItem{Action: "warn", Scope: "inventory", Target: row.Name, Status: "warn", Change: "host has no address", Expected: "address", Actual: "-"})
		}
	}
	return items
}

func planTrustItems(cfg certopsConfig) []planItem {
	items := []planItem{}
	cas := caNameSet(cfg)
	hosts := hostNameSet(cfg)
	groups := groupNameSet(cfg)
	for _, target := range cfg.Trust.Targets {
		name, status, change := trustTargetName(target, groups, hosts)
		item := planItem{Action: "manual", Scope: "trust", Target: name, Status: status, Change: change}
		if status == "ok" {
			item.Change = "trust policy configured; remote verification not run in plan"
		}
		item.Expected = strings.Join(target.Required, ",")
		items = append(items, item)
		for _, required := range target.Required {
			if !cas[required] {
				items = append(items, planItem{Action: "fail", Scope: "trust", Target: name, Status: "critical", Change: "required CA is not configured", Expected: required, Actual: "missing"})
			}
		}
	}
	return items
}

func planServiceItems(cfg certopsConfig) []planItem {
	items := []planItem{}
	cas := caNameSet(cfg)
	hosts := hostNameSet(cfg)
	for _, service := range cfg.Services {
		target := service.Name
		if target == "" {
			target = service.URL
		}
		item := planItem{Action: "verify", Scope: "service", Target: target, Status: "ok", Change: "service TLS check configured"}
		if service.URL == "" && service.Host == "" {
			item.Status = "critical"
			item.Change = "service has no url or host"
		}
		if service.CA != "" && !cas[service.CA] {
			item.Status = "critical"
			item.Change = "service references unknown CA"
			item.Expected = service.CA
			item.Actual = "missing"
		}
		if service.Host != "" && !hosts[service.Host] && !strings.Contains(service.Host, ".") {
			items = append(items, planItem{Action: "warn", Scope: "service", Target: target, Status: "warn", Change: "service host is not in inventory", Expected: "inventory host or DNS name", Actual: service.Host})
		}
		items = append(items, item)
	}
	return items
}

func trustTargetName(target configTrustTarget, groups, hosts map[string]bool) (string, string, string) {
	if target.Group != "" {
		if !groups[target.Group] {
			return target.Group, "critical", "trust target group not found"
		}
		return target.Group, "ok", ""
	}
	if target.Host != "" {
		if !hosts[target.Host] {
			return target.Host, "critical", "trust target host not found"
		}
		return target.Host, "ok", ""
	}
	return "-", "critical", "trust target has no group or host"
}

func caNameSet(cfg certopsConfig) map[string]bool {
	out := map[string]bool{}
	for _, ca := range cfg.CAs {
		out[ca.Name] = true
	}
	return out
}

func crlNameSet(cfg certopsConfig) map[string]bool {
	out := map[string]bool{}
	for _, crl := range cfg.CRLs {
		out[crl.Name] = true
	}
	return out
}

func groupNameSet(cfg certopsConfig) map[string]bool {
	out := map[string]bool{}
	for name := range cfg.Inventory.Groups {
		out[name] = true
	}
	return out
}

func hostNameSet(cfg certopsConfig) map[string]bool {
	out := map[string]bool{}
	for _, row := range inventoryRows(cfg) {
		out[row.Name] = true
	}
	return out
}

func summarizePlan(items []planItem) planSummary {
	summary := planSummary{Total: len(items)}
	for _, item := range items {
		switch item.Status {
		case "critical", "error":
			summary.Critical++
		case "warn":
			summary.Warn++
		default:
			summary.OK++
		}
		if item.Action == "manual" {
			summary.Manual++
		}
	}
	return summary
}

func statusFromSummary(summary planSummary) string {
	if summary.Critical > 0 {
		return "critical"
	}
	if summary.Warn > 0 {
		return "warn"
	}
	return "ok"
}

func printPlanReport(report planReport, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(report)
	case outputYAML:
		printYAMLValue(report)
	default:
		fmt.Printf("plan  %s\n", report.File)
		fmt.Printf("status: %s\n\n", statusColor(report.Status))
		rows := make([][]string, 0, len(report.Items))
		for _, item := range report.Items {
			rows = append(rows, []string{item.Action, item.Scope, item.Target, statusColor(item.Status), item.Change})
		}
		renderTable([]string{"action", "scope", "target", "status", "change"}, rows)
		fmt.Printf("\nsummary: total=%d ok=%d warn=%d critical=%d manual=%d\n", report.Summary.Total, report.Summary.OK, report.Summary.Warn, report.Summary.Critical, report.Summary.Manual)
	}
}

func exitForPlan(report planReport, failOn string) int {
	failOn = effectiveFailOn(failOn, "", "critical")
	if report.Summary.Critical > 0 {
		return 1
	}
	if failOn == "warn" && report.Summary.Warn > 0 {
		return 1
	}
	return 0
}

func effectiveFailOn(cliValue, configValue, fallback string) string {
	for _, value := range []string{cliValue, configValue, fallback} {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			return value
		}
	}
	return "critical"
}
