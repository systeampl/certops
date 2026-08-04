package main

import "runtime"

func buildTrustReport(action string, source trustSource, certs []trustCert, rawCerts [][]byte, plan trustPlan) trustReport {
	report := trustReport{
		Action:      action,
		Status:      "ok",
		Source:      source.Label,
		OS:          runtime.GOOS,
		Name:        plan.Name,
		Store:       plan.Store,
		InstallPath: plan.InstallPath,
		Commands:    plan.Commands,
		Certs:       certs,
	}
	for i := range report.Certs {
		report.Certs[i].Installed, report.Certs[i].InstallNote = trustCertInstalled(plan, rawCerts[i])
		if !report.Certs[i].IsCA {
			report.Status = "critical"
			report.Findings = append(report.Findings, trustFinding{
				Severity: "critical",
				Message:  "certificate is not marked as a CA: " + report.Certs[i].Subject,
			})
		}
		if report.Certs[i].DaysLeft < 0 {
			report.Status = "critical"
			report.Findings = append(report.Findings, trustFinding{
				Severity: "critical",
				Message:  "certificate is expired: " + report.Certs[i].Subject,
			})
		} else if report.Certs[i].DaysLeft < 30 {
			report.Status = worseTrustStatus(report.Status, "warn")
			report.Findings = append(report.Findings, trustFinding{
				Severity: "warn",
				Message:  "certificate expires soon: " + report.Certs[i].Subject,
			})
		}
	}
	if action == "verify" {
		for _, cert := range report.Certs {
			if !cert.Installed {
				report.Status = worseTrustStatus(report.Status, "warn")
				report.Findings = append(report.Findings, trustFinding{
					Severity: "warn",
					Message:  "certificate is not installed in the detected trust store: " + cert.Subject,
				})
			}
		}
	}
	if plan.Store == "unsupported" {
		report.Status = worseTrustStatus(report.Status, "warn")
		report.Findings = append(report.Findings, trustFinding{
			Severity: "warn",
			Message:  "automatic trust-store install is not supported on this OS",
		})
	}
	return report
}

func worseTrustStatus(current, next string) string {
	order := map[string]int{"ok": 0, "warn": 1, "critical": 2}
	if order[next] > order[current] {
		return next
	}
	return current
}
