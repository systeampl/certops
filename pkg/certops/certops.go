// Package certops exposes the versioned TLS and PKI checking engine used by
// the certops CLI.
package certops

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	checker "github.com/systeampl/certops/internal/check"
	crlcheck "github.com/systeampl/certops/internal/crl"
)

const (
	SchemaVersion    = checker.SchemaVersion
	SeverityInfo     = checker.SeverityInfo
	SeverityWarn     = checker.SeverityWarn
	SeverityCritical = checker.SeverityCritical
	SeverityError    = checker.SeverityError
)

type CheckOptions = checker.Options
type Finding = checker.Finding
type Certificate = checker.Certificate
type ChainCertificate = checker.ChainCertificate
type TLSInfo = checker.TLSInfo
type HTTPSInfo = checker.HTTPSInfo
type RevocationInfo = checker.RevocationInfo
type Report = checker.Report

type CRLOptions = crlcheck.Options
type CRLFinding = crlcheck.Finding
type CRLReport = crlcheck.Report

// CheckEndpoint checks a TLS endpoint using serverName for SNI and hostname
// verification and address as the TCP host:port destination.
func CheckEndpoint(ctx context.Context, serverName, address string, opts CheckOptions) Report {
	return checker.Run(ctx, serverName, address, opts)
}

// CheckTarget normalizes a host, host:port, or HTTPS URL and checks it.
func CheckTarget(ctx context.Context, target string, opts CheckOptions) (Report, error) {
	host, address, err := NormalizeTarget(target)
	if err != nil {
		return Report{}, err
	}
	return CheckEndpoint(ctx, host, address, opts), nil
}

// CheckCRL fetches or reads and validates a PEM or DER CRL.
func CheckCRL(ctx context.Context, opts CRLOptions) CRLReport {
	return crlcheck.Run(ctx, opts)
}

// NormalizeTarget converts host, host:port, and HTTPS URL inputs into a TLS
// server name and TCP host:port address.
func NormalizeTarget(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("target is required")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", "", err
		}
		if u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return "", "", fmt.Errorf("target URL must use https and contain a hostname without userinfo")
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		if err := validatePort(port); err != nil {
			return "", "", err
		}
		return u.Hostname(), net.JoinHostPort(u.Hostname(), port), nil
	}
	host := raw
	port := "443"
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host, port = h, p
	} else if strings.Count(raw, ":") == 1 {
		parts := strings.Split(raw, ":")
		if _, err := strconv.Atoi(parts[1]); err == nil {
			host, port = parts[0], parts[1]
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" || strings.ContainsAny(host, " /\\@\t\r\n\x00") || strings.HasPrefix(host, "-") {
		return "", "", fmt.Errorf("target has an invalid hostname or port")
	}
	if err := validatePort(port); err != nil {
		return "", "", err
	}
	return host, net.JoinHostPort(host, port), nil
}

func validatePort(value string) error {
	portNumber, err := strconv.Atoi(value)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("target has an invalid hostname or port")
	}
	return nil
}
