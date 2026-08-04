package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	engine "github.com/systeampl/certops/pkg/certops"

	"gopkg.in/yaml.v3"
)

type outputFormat string

const (
	outputRaw  outputFormat = "raw"
	outputJSON outputFormat = "json"
	outputYAML outputFormat = "yaml"
	outputProm outputFormat = "prom"
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*f = append(*f, part)
		}
	}
	return nil
}

func resolveOutput(jsonOut, yamlOut, promOut bool) (outputFormat, error) {
	n := 0
	for _, enabled := range []bool{jsonOut, yamlOut, promOut} {
		if enabled {
			n++
		}
	}
	if n > 1 {
		return "", fmt.Errorf("--json, --yaml and --prom are mutually exclusive")
	}
	switch {
	case jsonOut:
		return outputJSON, nil
	case yamlOut:
		return outputYAML, nil
	case promOut:
		return outputProm, nil
	default:
		return outputRaw, nil
	}
}

// normalizeFlagArgs moves recognized flags (and their values, when separate)
// ahead of positional args so stdlib flag.FlagSet accepts a human CLI:
// `certops check example.com --json` becomes `certops check --json example.com`.
func normalizeFlagArgs(args []string, valueFlags map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			if valueFlags[arg] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, arg)
	}
	return append(flags, pos...)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err.Error())
	}
}

func printYAMLValue(v any) {
	enc := yaml.NewEncoder(os.Stdout)
	defer enc.Close()
	if err := enc.Encode(v); err != nil {
		fatal(err.Error())
	}
}

func normalizeTarget(raw string) (string, string, error) {
	return engine.NormalizeTarget(raw)
}

func normalizeServerName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("server name is required")
	}
	if strings.ContainsAny(name, "/\\@\r\n\x00") {
		return "", fmt.Errorf("server name contains invalid characters")
	}
	if ip := net.ParseIP(strings.Trim(name, "[]")); ip != nil {
		return ip.String(), nil
	}
	if strings.Contains(name, ":") || len(name) > 253 {
		return "", fmt.Errorf("server name must be a DNS name or IP address without a port")
	}
	trimmed := strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("server name is not a valid DNS name")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("server name is not a valid DNS name")
			}
		}
	}
	return strings.ToLower(trimmed), nil
}

func normalizeConnect(raw, defaultPort string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("connect destination is required")
	}
	if strings.ContainsAny(raw, "/\\@\r\n\x00") || strings.HasPrefix(raw, "-") {
		return "", fmt.Errorf("connect destination contains invalid characters")
	}
	if defaultPort == "" {
		defaultPort = "443"
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if strings.Trim(host, "[]") == "" {
			return "", fmt.Errorf("connect destination has no host")
		}
		if err := validateNumericPort(port); err != nil {
			return "", err
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
	}
	host := strings.Trim(raw, "[]")
	if net.ParseIP(host) == nil && strings.Contains(host, ":") {
		return "", fmt.Errorf("connect destination has an invalid host or port")
	}
	if err := validateNumericPort(defaultPort); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, defaultPort), nil
}

func validateNumericPort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func boolInt(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

func validateFailOn(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "warn", "critical":
		return nil
	default:
		return fmt.Errorf("--fail-on must be warn or critical")
	}
}

func validateThresholds(warnDays, criticalDays int) error {
	if warnDays < -1 || criticalDays < -1 {
		return fmt.Errorf("expiry thresholds must be -1 (disabled) or greater")
	}
	if warnDays >= 0 && criticalDays >= 0 && criticalDays > warnDays {
		return fmt.Errorf("--critical-days cannot be greater than --warn-days")
	}
	return nil
}

func validateTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	return nil
}

func validateFingerprint(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	normalized := normalizeFingerprint(value)
	if len(normalized) != sha256HexLength {
		return fmt.Errorf("SHA-256 fingerprint must contain exactly %d hexadecimal characters", sha256HexLength)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return fmt.Errorf("SHA-256 fingerprint is invalid: %w", err)
	}
	return nil
}

const sha256HexLength = 64

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d-byte limit", limit)
	}
	return data, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".certops-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
