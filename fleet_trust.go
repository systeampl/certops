package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

func runFleetTrust(action, file string, cfg certopsConfig, limit string) fleetTrustReport {
	report := fleetTrustReport{Action: action, File: file, Status: "ok"}
	targets, failures := expandFleetTrustTargets(cfg, limit)
	report.Errors = append(report.Errors, failures...)
	cas := caByName(cfg)
	pemCache := map[string][]byte{}
	for _, target := range targets {
		item := fleetTrustItem{
			Host:    target.Host.Name,
			Address: target.Host.Address,
			User:    target.Host.User,
			Port:    target.Host.Port,
			OS:      target.Host.OS,
			CA:      target.CAName,
			Path:    remoteTrustPath(target.CAName),
			Status:  "ok",
		}
		ca, ok := cas[target.CAName]
		if !ok {
			item.Status = "critical"
			item.Message = "CA is not configured"
			report.Items = append(report.Items, item)
			continue
		}
		pemData, err := cachedCAPEM(ca, pemCache)
		if err != nil {
			item.Status = "critical"
			item.Message = err.Error()
			report.Items = append(report.Items, item)
			continue
		}
		item = runFleetTrustItem(action, target.Host, target.CAName, pemData, item)
		report.Items = append(report.Items, item)
	}
	if action == "verify" && !cfg.Policy.AllowUnmanagedRoots {
		report.Items = append(report.Items, verifyNoUnmanagedRoots(targets)...)
	}
	report.Summary = summarizeFleetTrust(report.Items, report.Errors)
	report.Status = fleetStatus(report.Summary)
	return report
}

func verifyNoUnmanagedRoots(targets []fleetTrustTarget) []fleetTrustItem {
	type hostState struct {
		host     fleetHost
		required map[string]bool
	}
	byHost := map[string]*hostState{}
	for _, target := range targets {
		state := byHost[target.Host.Name]
		if state == nil {
			state = &hostState{host: target.Host, required: map[string]bool{}}
			byHost[target.Host.Name] = state
		}
		state.required[filepath.Base(remoteTrustPath(target.CAName))] = true
	}
	names := make([]string, 0, len(byHost))
	for name := range byHost {
		names = append(names, name)
	}
	sort.Strings(names)
	var items []fleetTrustItem
	for _, name := range names {
		state := byHost[name]
		if !strings.EqualFold(strings.TrimSpace(state.host.OS), "linux") {
			continue
		}
		paths, err := remoteManagedLinuxTrustPaths(state.host)
		if err != nil {
			items = append(items, fleetTrustItem{Host: name, Address: state.host.Address, User: state.host.User, Port: state.host.Port, OS: state.host.OS, CA: "*", Status: "critical", Message: "could not inventory Certops-managed roots: " + err.Error()})
			continue
		}
		for _, path := range paths {
			if state.required[filepath.Base(path)] {
				continue
			}
			items = append(items, fleetTrustItem{Host: name, Address: state.host.Address, User: state.host.User, Port: state.host.Port, OS: state.host.OS, CA: "unmanaged", Path: path, Status: "warn", Message: "Certops-managed root is not declared by this host's trust policy"})
		}
	}
	return items
}

func runFleetTrustItem(action string, host fleetHost, caName string, pemData []byte, item fleetTrustItem) fleetTrustItem {
	if strings.ToLower(strings.TrimSpace(host.OS)) != "linux" {
		item.Status = "warn"
		item.Message = "remote trust install is only implemented for linux targets"
		return item
	}
	switch action {
	case "plan":
		item.Message = "would install CA bundle and run update-ca-certificates"
	case "install":
		if err := remoteInstallLinuxTrust(host, caName, pemData); err != nil {
			item.Status = "critical"
			item.Message = err.Error()
		} else {
			item.Message = "installed and refreshed trust store"
		}
	case "verify":
		ok, note, err := remoteVerifyLinuxTrust(host, caName, pemData)
		if err != nil {
			item.Status = "critical"
			item.Message = err.Error()
		} else if !ok {
			item.Status = "warn"
			item.Message = note
		} else {
			item.Message = note
		}
	case "remove":
		if err := remoteRemoveLinuxTrust(host, caName); err != nil {
			item.Status = "critical"
			item.Message = err.Error()
		} else {
			item.Message = "removed CA bundle and refreshed trust store"
		}
	}
	return item
}

func cachedCAPEM(ca configCA, cache map[string][]byte) ([]byte, error) {
	if data, ok := cache[ca.Name]; ok {
		return data, nil
	}
	data, _, err := configuredCAPEM(ca)
	if err != nil {
		return nil, err
	}
	cache[ca.Name] = data
	return data, nil
}

func remoteTrustPath(caName string) string {
	return "/usr/local/share/ca-certificates/certops-" + sanitizeTrustName(caName) + ".crt"
}

func remoteInstallLinuxTrust(host fleetHost, caName string, pemData []byte) error {
	path := remoteTrustPath(caName)
	remote := fmt.Sprintf("sudo tee %s >/dev/null && sudo chmod 0644 %s && sudo update-ca-certificates >/dev/null", shellQuote(path), shellQuote(path))
	_, err := fleetSSH(host, remote, pemData)
	return err
}

func remoteVerifyLinuxTrust(host fleetHost, caName string, pemData []byte) (bool, string, error) {
	path := remoteTrustPath(caName)
	out, err := fleetSSH(host, "sudo cat "+shellQuote(path), nil)
	if err != nil {
		return false, "", err
	}
	want, _, err := parseTrustCerts(pemData)
	if err != nil {
		return false, "", err
	}
	got, _, err := parseTrustCerts(out)
	if err != nil {
		return false, "", err
	}
	for _, cert := range want {
		found := false
		for _, candidate := range got {
			if normalizeFingerprint(cert.SHA256) == normalizeFingerprint(candidate.SHA256) {
				found = true
				break
			}
		}
		if !found {
			return false, "expected CA fingerprint not found at install path", nil
		}
	}
	return true, "expected CA fingerprint found at install path", nil
}

func remoteRemoveLinuxTrust(host fleetHost, caName string) error {
	path := remoteTrustPath(caName)
	remote := fmt.Sprintf("sudo rm -f %s && sudo update-ca-certificates >/dev/null", shellQuote(path))
	_, err := fleetSSH(host, remote, nil)
	return err
}

func remoteManagedLinuxTrustPaths(host fleetHost) ([]string, error) {
	const command = "find /usr/local/share/ca-certificates -maxdepth 1 -type f -name 'certops-*.crt' -print"
	out, err := fleetSSH(host, command, nil)
	if err != nil {
		return nil, err
	}
	paths := strings.Fields(string(out))
	sort.Strings(paths)
	return paths, nil
}

func summarizeFleetTrust(items []fleetTrustItem, failures []fleetTrustFailure) fleetTrustSummary {
	summary := fleetTrustSummary{Total: len(items) + len(failures), Critical: len(failures)}
	for _, item := range items {
		switch item.Status {
		case "critical":
			summary.Critical++
		case "warn":
			summary.Warn++
		default:
			summary.OK++
		}
	}
	return summary
}

func fleetStatus(summary fleetTrustSummary) string {
	if summary.Critical > 0 {
		return "critical"
	}
	if summary.Warn > 0 {
		return "warn"
	}
	return "ok"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
