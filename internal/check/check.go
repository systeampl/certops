package check

import (
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	crlcheck "github.com/pawel-cygal/certops/internal/crl"
	"golang.org/x/crypto/ocsp"
)

const SchemaVersion = "certops.report.v1"

type Options struct {
	WarnDays           int
	CriticalDays       int
	Timeout            time.Duration
	CABundle           string
	CRLSources         []string
	CRLCABundle        string
	CRLWarnDays        int
	CRLCriticalDays    int
	CRLMaxAgeDays      int
	AutoCRL            bool
	CRLInsecureSources map[string]bool
}

type Finding struct {
	Severity string `json:"severity" yaml:"severity"`
	Scope    string `json:"scope" yaml:"scope"`
	Message  string `json:"message" yaml:"message"`
}

type Certificate struct {
	Subject            string   `json:"subject,omitempty" yaml:"subject,omitempty"`
	Issuer             string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty" yaml:"serial_number,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	NotBefore          string   `json:"not_before,omitempty" yaml:"not_before,omitempty"`
	NotAfter           string   `json:"not_after,omitempty" yaml:"not_after,omitempty"`
	DaysRemaining      int      `json:"days_remaining" yaml:"days_remaining"`
	Trusted            bool     `json:"trusted" yaml:"trusted"`
	MatchesHost        bool     `json:"matches_host" yaml:"matches_host"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm,omitempty" yaml:"public_key_algorithm,omitempty"`
	PublicKeyBits      int      `json:"public_key_bits,omitempty" yaml:"public_key_bits,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty" yaml:"signature_algorithm,omitempty"`
}

type ChainCertificate struct {
	Subject            string `json:"subject" yaml:"subject"`
	Issuer             string `json:"issuer" yaml:"issuer"`
	SerialNumber       string `json:"serial_number" yaml:"serial_number"`
	NotAfter           string `json:"not_after" yaml:"not_after"`
	IsCA               bool   `json:"is_ca" yaml:"is_ca"`
	PublicKeyAlgorithm string `json:"public_key_algorithm" yaml:"public_key_algorithm"`
	PublicKeyBits      int    `json:"public_key_bits,omitempty" yaml:"public_key_bits,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm" yaml:"signature_algorithm"`
}

type TLSInfo struct {
	NegotiatedVersion string   `json:"negotiated_version,omitempty" yaml:"negotiated_version,omitempty"`
	CipherSuite       string   `json:"cipher_suite,omitempty" yaml:"cipher_suite,omitempty"`
	ALPN              string   `json:"alpn,omitempty" yaml:"alpn,omitempty"`
	OCSPStapling      bool     `json:"ocsp_stapling" yaml:"ocsp_stapling"`
	OCSPStatus        string   `json:"ocsp_status,omitempty" yaml:"ocsp_status,omitempty"`
	OCSPThisUpdate    string   `json:"ocsp_this_update,omitempty" yaml:"ocsp_this_update,omitempty"`
	OCSPNextUpdate    string   `json:"ocsp_next_update,omitempty" yaml:"ocsp_next_update,omitempty"`
	SupportedVersions []string `json:"supported_versions,omitempty" yaml:"supported_versions,omitempty"`
	HandshakeMS       int64    `json:"handshake_ms" yaml:"handshake_ms"`
}

type HTTPSInfo struct {
	HTTPRedirectChecked bool   `json:"http_redirect_checked" yaml:"http_redirect_checked"`
	HTTPRedirectOK      bool   `json:"http_redirect_ok" yaml:"http_redirect_ok"`
	HSTS                string `json:"hsts,omitempty" yaml:"hsts,omitempty"`
	HSTSEnabled         bool   `json:"hsts_enabled" yaml:"hsts_enabled"`
}

type RevocationInfo struct {
	Checked          bool     `json:"checked" yaml:"checked"`
	Sources          []string `json:"sources,omitempty" yaml:"sources,omitempty"`
	ValidatedSources []string `json:"validated_sources,omitempty" yaml:"validated_sources,omitempty"`
	Revoked          bool     `json:"revoked" yaml:"revoked"`
	Errors           []string `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type Report struct {
	SchemaVersion string             `json:"schema_version" yaml:"schema_version"`
	Target        string             `json:"target" yaml:"target"`
	Host          string             `json:"host" yaml:"host"`
	Address       string             `json:"address" yaml:"address"`
	Status        string             `json:"status" yaml:"status"`
	Certificate   Certificate        `json:"certificate" yaml:"certificate"`
	Chain         []ChainCertificate `json:"chain,omitempty" yaml:"chain,omitempty"`
	TLS           TLSInfo            `json:"tls" yaml:"tls"`
	HTTPS         HTTPSInfo          `json:"https" yaml:"https"`
	Revocation    RevocationInfo     `json:"revocation" yaml:"revocation"`
	Findings      []Finding          `json:"findings,omitempty" yaml:"findings,omitempty"`
	Error         string             `json:"error,omitempty" yaml:"error,omitempty"`
}

func Run(ctx context.Context, host, address string, opts Options) Report {
	if opts.WarnDays == 0 {
		opts.WarnDays = 30
	}
	if opts.CriticalDays == 0 {
		opts.CriticalDays = 14
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.CRLWarnDays == 0 {
		opts.CRLWarnDays = 3
	}
	if opts.CRLCriticalDays == 0 {
		opts.CRLCriticalDays = 1
	}

	report := Report{
		SchemaVersion: SchemaVersion,
		Target:        address,
		Host:          host,
		Address:       address,
		Status:        "ok",
	}

	start := time.Now()
	conn, err := dialTLS(ctx, host, address, opts.Timeout)
	if err != nil {
		report.Status = "error"
		report.Error = err.Error()
		add(&report, "critical", "tls", err.Error())
		return report
	}
	defer conn.Close()

	report.TLS.HandshakeMS = time.Since(start).Milliseconds()
	state := conn.ConnectionState()
	report.TLS.NegotiatedVersion = tlsVersionName(state.Version)
	report.TLS.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	report.TLS.ALPN = state.NegotiatedProtocol
	report.TLS.OCSPStapling = len(state.OCSPResponse) > 0
	report.TLS.SupportedVersions = probeVersions(ctx, host, address, opts.Timeout)

	if len(state.PeerCertificates) == 0 {
		add(&report, "critical", "certificate", "server did not present a certificate")
		report.Status = aggregateStatus(report.Findings)
		return report
	}

	leaf := state.PeerCertificates[0]
	keyAlgorithm, keyBits := certificateKeyInfo(leaf)
	report.Certificate = Certificate{
		Subject:            leaf.Subject.String(),
		Issuer:             leaf.Issuer.String(),
		SerialNumber:       leaf.SerialNumber.String(),
		DNSNames:           append([]string(nil), leaf.DNSNames...),
		NotBefore:          leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining:      int(time.Until(leaf.NotAfter).Hours() / 24),
		Trusted:            true,
		MatchesHost:        true,
		PublicKeyAlgorithm: keyAlgorithm,
		PublicKeyBits:      keyBits,
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
	}
	report.Chain = chainSummary(state.PeerCertificates)

	if report.Certificate.DaysRemaining <= opts.CriticalDays {
		add(&report, "critical", "certificate", fmt.Sprintf("certificate expires in %d days", report.Certificate.DaysRemaining))
	} else if report.Certificate.DaysRemaining <= opts.WarnDays {
		add(&report, "warn", "certificate", fmt.Sprintf("certificate expires in %d days", report.Certificate.DaysRemaining))
	}
	if err := leaf.VerifyHostname(host); err != nil {
		report.Certificate.MatchesHost = false
		add(&report, "critical", "certificate", "certificate does not match hostname: "+err.Error())
	}
	checkCertificateCrypto(&report, leaf, keyBits)
	_, systemTrustErr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates(state.PeerCertificates)})
	if opts.CABundle != "" {
		if err := verifyWithCABundle(leaf, state.PeerCertificates, host, opts.CABundle); err != nil {
			report.Certificate.Trusted = false
			add(&report, "critical", "certificate", "certificate is not trusted by configured CA bundle: "+err.Error())
		}
	} else if systemTrustErr != nil {
		report.Certificate.Trusted = false
		add(&report, "critical", "certificate", "certificate chain is not trusted: "+systemTrustErr.Error())
	}
	checkOCSPStaple(&report, state.OCSPResponse, state.PeerCertificates)
	checkRevocation(ctx, &report, state.PeerCertificates, opts)

	if supports(report.TLS.SupportedVersions, "TLS1.0") {
		add(&report, "warn", "tls", "TLS 1.0 is accepted")
	}
	if supports(report.TLS.SupportedVersions, "TLS1.1") {
		add(&report, "warn", "tls", "TLS 1.1 is accepted")
	}
	if !supports(report.TLS.SupportedVersions, "TLS1.2") && !supports(report.TLS.SupportedVersions, "TLS1.3") {
		add(&report, "critical", "tls", "TLS 1.2 and TLS 1.3 are not available")
	}
	if !report.TLS.OCSPStapling {
		add(&report, "warn", "tls", "OCSP stapling is not enabled")
	}
	if weakNegotiatedCipher(report.TLS.CipherSuite) {
		add(&report, "critical", "tls", "negotiated cipher suite is considered weak: "+report.TLS.CipherSuite)
	}

	report.HTTPS = checkHTTPS(ctx, host, address, opts.Timeout)
	if shouldCheckHTTPRedirect(address) && !report.HTTPS.HTTPRedirectOK {
		add(&report, "warn", "https", "HTTP to HTTPS redirect was not confirmed")
	}
	if !report.HTTPS.HSTSEnabled {
		if strings.TrimSpace(report.HTTPS.HSTS) == "" {
			add(&report, "warn", "https", "HSTS header is missing")
		} else {
			add(&report, "warn", "https", "HSTS header is disabled or invalid")
		}
	}

	report.Status = aggregateStatus(report.Findings)
	return report
}

func shouldCheckHTTPRedirect(address string) bool {
	_, port, err := net.SplitHostPort(address)
	return err != nil || port == "443"
}

func dialTLS(ctx context.Context, host, address string, timeout time.Duration) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	})
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func probeVersions(ctx context.Context, host, address string, timeout time.Duration) []string {
	candidates := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
	}
	var out []string
	for _, candidate := range candidates {
		if probeVersion(ctx, host, address, candidate.version, timeout) {
			out = append(out, candidate.name)
		}
	}
	return out
}

func probeVersion(ctx context.Context, host, address string, version uint16, timeout time.Duration) bool {
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	err = conn.HandshakeContext(ctx)
	_ = conn.Close()
	return err == nil
}

func checkHTTPS(ctx context.Context, host, address string, timeout time.Duration) HTTPSInfo {
	dialer := &net.Dialer{Timeout: timeout}
	httpsTransport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
	defer httpsTransport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   timeout,
		Transport: httpsTransport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	info := HTTPSInfo{}
	httpsURL := "https://" + net.JoinHostPort(host, portFromAddress(address, "443"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpsURL, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			info.HSTS = resp.Header.Get("Strict-Transport-Security")
			info.HSTSEnabled = hstsEnabled(info.HSTS)
			_ = resp.Body.Close()
		}
	}
	_, port, err := net.SplitHostPort(address)
	if err == nil && port != "443" {
		return info
	}
	info.HTTPRedirectChecked = true
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host, nil)
	if err != nil {
		return info
	}
	redirectTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer redirectTransport.CloseIdleConnections()
	redirectClient := &http.Client{
		Timeout:   timeout,
		Transport: redirectTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := redirectClient.Do(req)
	if err != nil {
		return info
	}
	defer resp.Body.Close()
	info.HTTPRedirectOK = resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme == "https"
	return info
}

func hstsEnabled(value string) bool {
	for _, directive := range strings.Split(value, ";") {
		name, raw, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "max-age") {
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		return err == nil && seconds > 0
	}
	return false
}

func portFromAddress(address, fallback string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fallback
	}
	return port
}

func intermediates(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		pool.AddCert(cert)
	}
	return pool
}

func verifyWithCABundle(leaf *x509.Certificate, certs []*x509.Certificate, host, path string) error {
	roots, err := loadCertPool(path)
	if err != nil {
		return err
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates(certs),
	})
	return err
}

func checkRevocation(ctx context.Context, report *Report, certs []*x509.Certificate, opts Options) {
	sources := append([]string(nil), opts.CRLSources...)
	if opts.AutoCRL && len(certs) > 0 {
		sources = append(sources, certs[0].CRLDistributionPoints...)
	}
	sources = uniqueStrings(sources)
	if len(sources) == 0 {
		return
	}
	report.Revocation.Checked = true
	report.Revocation.Sources = uniqueStrings(append(report.Revocation.Sources, sources...))
	lists := make([]*x509.RevocationList, 0, len(sources))
	issuerCerts := []*x509.Certificate(nil)
	if len(certs) > 1 {
		issuerCerts = certs[1:]
	}
	for _, source := range sources {
		crlReport, list, err := crlcheck.Check(ctx, crlcheck.Options{
			Source:             source,
			CABundle:           opts.CRLCABundle,
			WarnDays:           opts.CRLWarnDays,
			CriticalDays:       opts.CRLCriticalDays,
			MaxAgeDays:         opts.CRLMaxAgeDays,
			Timeout:            opts.Timeout,
			IssuerCertificates: issuerCerts,
			RequireSignature:   true,
			Insecure:           opts.CRLInsecureSources[source],
		})
		for _, finding := range crlReport.Findings {
			add(report, finding.Severity, "revocation", fmt.Sprintf("CRL %s: %s", source, finding.Message))
		}
		if err != nil {
			report.Revocation.Errors = append(report.Revocation.Errors, err.Error())
			continue
		}
		if list != nil && crlReport.SignatureValid {
			lists = append(lists, list)
			report.Revocation.ValidatedSources = append(report.Revocation.ValidatedSources, source)
		}
	}
	for _, cert := range certs {
		revoked, issuer := crlcheck.CertificateRevoked(cert, lists)
		if !revoked {
			continue
		}
		report.Revocation.Revoked = true
		add(report, "critical", "revocation", fmt.Sprintf("certificate serial %s is revoked by CRL issuer %s", cert.SerialNumber.String(), issuer))
	}
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("configured CA bundle contains a non-CA certificate: %s", cert.Subject.String())
		}
		pool.AddCert(cert)
	}
	if len(pool.Subjects()) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

func checkCertificateCrypto(report *Report, cert *x509.Certificate, keyBits int) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if keyBits > 0 && keyBits < 2048 {
			add(report, "critical", "certificate", fmt.Sprintf("RSA public key is too small: %d bits", keyBits))
		}
	case x509.DSA:
		add(report, "critical", "certificate", "DSA public keys are not accepted for modern TLS certificates")
	case x509.ECDSA:
		if keyBits > 0 && keyBits < 256 {
			add(report, "critical", "certificate", fmt.Sprintf("ECDSA public key is too small: %d bits", keyBits))
		}
	}
	if weakSignatureAlgorithm(cert.SignatureAlgorithm) {
		add(report, "critical", "certificate", "certificate uses a weak signature algorithm: "+cert.SignatureAlgorithm.String())
	}
}

func certificateKeyInfo(cert *x509.Certificate) (string, int) {
	algorithm := cert.PublicKeyAlgorithm.String()
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return algorithm, key.N.BitLen()
	case *ecdsa.PublicKey:
		return algorithm, key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return algorithm, len(key) * 8
	case *dsa.PublicKey:
		return algorithm, key.P.BitLen()
	default:
		return algorithm, 0
	}
}

func chainSummary(certs []*x509.Certificate) []ChainCertificate {
	out := make([]ChainCertificate, 0, len(certs))
	for _, cert := range certs {
		algorithm, bits := certificateKeyInfo(cert)
		out = append(out, ChainCertificate{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			SerialNumber:       cert.SerialNumber.String(),
			NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
			IsCA:               cert.IsCA,
			PublicKeyAlgorithm: algorithm,
			PublicKeyBits:      bits,
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		})
	}
	return out
}

func checkOCSPStaple(report *Report, staple []byte, certs []*x509.Certificate) {
	if len(staple) == 0 {
		return
	}
	report.TLS.OCSPStapling = true
	report.Revocation.Checked = true
	report.Revocation.Sources = append(report.Revocation.Sources, "ocsp-staple")
	if len(certs) < 2 {
		report.TLS.OCSPStatus = "unverified"
		add(report, "warn", "revocation", "OCSP staple could not be verified because the issuer certificate was not presented")
		return
	}
	response, err := ocsp.ParseResponseForCert(staple, certs[0], certs[1])
	if err != nil {
		report.TLS.OCSPStatus = "invalid"
		add(report, "critical", "revocation", "OCSP staple is invalid: "+err.Error())
		return
	}
	report.TLS.OCSPThisUpdate = formatTime(response.ThisUpdate)
	report.TLS.OCSPNextUpdate = formatTime(response.NextUpdate)
	switch response.Status {
	case ocsp.Good:
		report.TLS.OCSPStatus = "good"
		report.Revocation.ValidatedSources = append(report.Revocation.ValidatedSources, "ocsp-staple")
	case ocsp.Revoked:
		report.TLS.OCSPStatus = "revoked"
		report.Revocation.Revoked = true
		add(report, "critical", "revocation", "OCSP staple reports the leaf certificate as revoked")
	case ocsp.Unknown:
		report.TLS.OCSPStatus = "unknown"
		add(report, "warn", "revocation", "OCSP responder reports an unknown certificate status")
	default:
		report.TLS.OCSPStatus = "invalid"
		add(report, "critical", "revocation", fmt.Sprintf("OCSP staple returned unsupported status %d", response.Status))
	}
	now := time.Now()
	if response.ThisUpdate.After(now.Add(5 * time.Minute)) {
		add(report, "critical", "revocation", "OCSP thisUpdate is in the future")
	}
	if !response.NextUpdate.IsZero() && !response.NextUpdate.After(now) {
		add(report, "critical", "revocation", "OCSP staple has expired")
	}
}

func weakSignatureAlgorithm(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

func weakNegotiatedCipher(name string) bool {
	return strings.Contains(name, "_CBC_") || strings.Contains(name, "_RC4_") || strings.Contains(name, "_3DES_") || strings.Contains(name, "TLS_RSA_WITH_")
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func add(report *Report, severity, scope, message string) {
	report.Findings = append(report.Findings, Finding{
		Severity: severity,
		Scope:    scope,
		Message:  message,
	})
}

func aggregateStatus(findings []Finding) string {
	status := "ok"
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			return "critical"
		case "warn":
			status = "warn"
		}
	}
	return status
}

func supports(versions []string, want string) bool {
	for _, version := range versions {
		if version == want {
			return true
		}
	}
	return false
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}
