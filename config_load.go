package main

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func loadConfig(path string) (certopsConfig, error) {
	if strings.TrimSpace(path) == "" {
		path = "certops.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return certopsConfig{}, err
	}
	var cfg certopsConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return certopsConfig{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return certopsConfig{}, fmt.Errorf("config contains multiple YAML documents")
		}
		return certopsConfig{}, err
	}
	if err := validateConfig(cfg); err != nil {
		return certopsConfig{}, err
	}
	return cfg, nil
}

func validateConfig(cfg certopsConfig) error {
	if strings.TrimSpace(cfg.Policy.FailOn) != "" {
		switch strings.ToLower(strings.TrimSpace(cfg.Policy.FailOn)) {
		case "warn", "critical":
		default:
			return fmt.Errorf("policy fail_on must be warn or critical")
		}
	}
	for name, value := range map[string]int{
		"min_ca_days_remaining":   cfg.Policy.MinCADaysRemaining,
		"min_leaf_days_remaining": cfg.Policy.MinLeafDaysRemaining,
		"min_crl_days_remaining":  cfg.Policy.MinCRLDaysRemaining,
		"max_crl_age_days":        cfg.Policy.MaxCRLAgeDays,
	} {
		if value < 0 {
			return fmt.Errorf("policy %s cannot be negative", name)
		}
	}
	seenCA := map[string]bool{}
	seenCAPath := map[string]string{}
	for _, ca := range cfg.CAs {
		if err := validateConfigName("ca", ca.Name); err != nil {
			return err
		}
		if seenCA[ca.Name] {
			return fmt.Errorf("duplicate ca name: %s", ca.Name)
		}
		seenCA[ca.Name] = true
		safeName := sanitizeTrustName(ca.Name)
		if prior := seenCAPath[safeName]; prior != "" {
			return fmt.Errorf("ca names %q and %q map to the same trust-store path", prior, ca.Name)
		}
		seenCAPath[safeName] = ca.Name
		if err := validateFingerprint(ca.Fingerprint); err != nil {
			return fmt.Errorf("ca %s: %w", ca.Name, err)
		}
		switch strings.ToLower(strings.TrimSpace(ca.Provider)) {
		case "smallstep":
			if err := validateProviderURL(ca.URL); err != nil {
				return fmt.Errorf("ca %s: %w", ca.Name, err)
			}
			if ca.Insecure && strings.TrimSpace(ca.Fingerprint) == "" {
				return fmt.Errorf("ca %s: fingerprint is required when insecure is true", ca.Name)
			}
		case "vault":
			if err := validateProviderURL(ca.URL); err != nil {
				return fmt.Errorf("ca %s: %w", ca.Name, err)
			}
			if err := validateAPIPath("mount", ca.Mount); err != nil {
				return fmt.Errorf("ca %s: %w", ca.Name, err)
			}
			if err := validateAPIPath("issuer", ca.Issuer); err != nil {
				return fmt.Errorf("ca %s: %w", ca.Name, err)
			}
		case "cfssl":
			if err := validateProviderURL(ca.URL); err != nil {
				return fmt.Errorf("ca %s: %w", ca.Name, err)
			}
		case "generic":
			hasFile := strings.TrimSpace(ca.CABundle) != ""
			hasURL := strings.TrimSpace(ca.URL) != ""
			if hasFile == hasURL {
				return fmt.Errorf("ca %s: exactly one of ca_bundle or url is required", ca.Name)
			}
			if hasURL {
				if err := validateHTTPURL(ca.URL); err != nil {
					return fmt.Errorf("ca %s: %w", ca.Name, err)
				}
				if strings.TrimSpace(ca.Fingerprint) == "" {
					return fmt.Errorf("ca %s: fingerprint is required for URL source", ca.Name)
				}
			}
		default:
			return fmt.Errorf("unsupported ca provider for %s: %s", ca.Name, ca.Provider)
		}
	}
	seenCRL := map[string]bool{}
	for _, crl := range cfg.CRLs {
		if err := validateConfigName("crl", crl.Name); err != nil {
			return err
		}
		if seenCRL[crl.Name] {
			return fmt.Errorf("duplicate crl name: %s", crl.Name)
		}
		seenCRL[crl.Name] = true
		if strings.TrimSpace(crl.File) == "" && strings.TrimSpace(crl.URL) == "" {
			return fmt.Errorf("crl %s requires file or url", crl.Name)
		}
		if strings.TrimSpace(crl.File) != "" && strings.TrimSpace(crl.URL) != "" {
			return fmt.Errorf("crl %s cannot define both file and url", crl.Name)
		}
		if crl.URL != "" {
			if err := validateHTTPURL(crl.URL); err != nil {
				return fmt.Errorf("crl %s: %w", crl.Name, err)
			}
		}
		if strings.TrimSpace(crl.CA) == "" {
			return fmt.Errorf("crl %s requires ca for signature verification", crl.Name)
		}
		if !seenCA[crl.CA] {
			return fmt.Errorf("crl %s references unknown ca: %s", crl.Name, crl.CA)
		}
		if crl.WarnDays < 0 || crl.CriticalDays < 0 || crl.MaxAgeDays < 0 {
			return fmt.Errorf("crl %s: thresholds cannot be negative", crl.Name)
		}
		effectiveWarn := crl.WarnDays
		if effectiveWarn == 0 {
			effectiveWarn = cfg.Policy.MinCRLDaysRemaining
			if effectiveWarn == 0 {
				effectiveWarn = 3
			}
		}
		effectiveCritical := crl.CriticalDays
		if effectiveCritical == 0 {
			effectiveCritical = 1
		}
		if effectiveCritical > effectiveWarn {
			return fmt.Errorf("crl %s: critical_days cannot be greater than warn_days", crl.Name)
		}
	}
	hosts := map[string]string{}
	for groupName, group := range cfg.Inventory.Groups {
		if err := validateConfigName("inventory group", groupName); err != nil {
			return err
		}
		for hostName, host := range group.Hosts {
			if err := validateConfigName("inventory host", hostName); err != nil {
				return err
			}
			if prior := hosts[hostName]; prior != "" {
				return fmt.Errorf("inventory host %s is duplicated in groups %s and %s", hostName, prior, groupName)
			}
			hosts[hostName] = groupName
			if err := validateSSHHost(host); err != nil {
				return fmt.Errorf("inventory host %s: %w", hostName, err)
			}
		}
	}
	for i, target := range cfg.Trust.Targets {
		if (strings.TrimSpace(target.Group) == "") == (strings.TrimSpace(target.Host) == "") {
			return fmt.Errorf("trust target %d requires exactly one of group or host", i)
		}
		if target.Group != "" {
			if _, ok := cfg.Inventory.Groups[target.Group]; !ok {
				return fmt.Errorf("trust target references unknown group: %s", target.Group)
			}
		}
		if target.Host != "" && hosts[target.Host] == "" {
			return fmt.Errorf("trust target references unknown host: %s", target.Host)
		}
		if len(target.Required) == 0 {
			return fmt.Errorf("trust target %d has no required CAs", i)
		}
		seenRequired := map[string]bool{}
		for _, required := range target.Required {
			if !seenCA[required] {
				return fmt.Errorf("trust target references unknown ca: %s", required)
			}
			if seenRequired[required] {
				return fmt.Errorf("trust target contains duplicate ca: %s", required)
			}
			seenRequired[required] = true
		}
	}
	seenService := map[string]bool{}
	for _, service := range cfg.Services {
		if strings.TrimSpace(service.URL) == "" && strings.TrimSpace(service.Host) == "" {
			return fmt.Errorf("service %s requires url or host", service.Name)
		}
		if strings.TrimSpace(service.URL) != "" && strings.TrimSpace(service.Host) != "" {
			return fmt.Errorf("service %s cannot define both url and host", service.Name)
		}
		if service.URL != "" {
			if err := validateHTTPURL(service.URL); err != nil {
				return fmt.Errorf("service %s: %w", service.Name, err)
			}
			parsed, _ := url.Parse(service.URL)
			if parsed.Scheme != "https" {
				return fmt.Errorf("service %s: URL scheme must be https", service.Name)
			}
		}
		identity := servicePlanTarget(service)
		if strings.TrimSpace(identity) == "" {
			return fmt.Errorf("service identity is empty")
		}
		if seenService[identity] {
			return fmt.Errorf("duplicate service identity: %s", identity)
		}
		seenService[identity] = true
		if service.CA != "" && !seenCA[service.CA] {
			return fmt.Errorf("service %s references unknown ca: %s", identity, service.CA)
		}
		if err := validatePort(service.Port); err != nil {
			return fmt.Errorf("service %s: %w", identity, err)
		}
		if service.ServerName != "" {
			if _, err := normalizeServerName(service.ServerName); err != nil {
				return fmt.Errorf("service %s: %w", identity, err)
			}
		}
		if service.MinDaysRemaining < 0 {
			return fmt.Errorf("service %s: min_days_remaining cannot be negative", identity)
		}
		for _, name := range service.CRLs {
			if !seenCRL[name] {
				target := service.Name
				if target == "" {
					target = service.URL
				}
				return fmt.Errorf("service %s references unknown crl: %s", target, name)
			}
		}
	}
	return nil
}

func validateConfigName(kind, name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%s name is required", kind)
	}
	if name != strings.TrimSpace(name) {
		return fmt.Errorf("%s name %q has leading or trailing whitespace", kind, name)
	}
	if strings.ContainsAny(name, "\r\n\x00") {
		return fmt.Errorf("%s name %q contains control characters", kind, name)
	}
	return nil
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	if u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("URL must contain a hostname and no userinfo")
	}
	return nil
}

func validateProviderURL(raw string) error {
	if err := validateHTTPURL(raw); err != nil {
		return err
	}
	u, _ := url.Parse(strings.TrimSpace(raw))
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("provider base URL cannot contain a query or fragment")
	}
	return nil
}

func validateAPIPath(name, value string) error {
	value = strings.Trim(strings.TrimSpace(value), "/")
	if value == "" {
		return nil
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || url.PathEscape(part) != part {
			return fmt.Errorf("%s contains an unsafe path segment", name)
		}
	}
	return nil
}

func validateSSHHost(host configHost) error {
	if strings.HasPrefix(strings.TrimSpace(host.Address), "-") || strings.ContainsAny(host.Address, " \t\r\n\x00") {
		return fmt.Errorf("address is unsafe")
	}
	if strings.HasPrefix(strings.TrimSpace(host.User), "-") || strings.ContainsAny(host.User, "@ \t\r\n\x00") {
		return fmt.Errorf("user is unsafe")
	}
	if strings.ContainsAny(host.IdentityFile, "\r\n\x00") {
		return fmt.Errorf("identity_file contains control characters")
	}
	return validatePort(host.Port)
}

func validatePort(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func defaultConfigPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "certops.yaml"
	}
	return path
}
