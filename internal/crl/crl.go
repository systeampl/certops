package crl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/systeampl/certops/internal/reportcontract"
)

type Options struct {
	Name         string
	Source       string
	CABundle     string
	WarnDays     int
	CriticalDays int
	MaxAgeDays   int
	Timeout      time.Duration
	Insecure     bool
	// IssuerCertificates are trusted candidates used to verify a CRL signature.
	IssuerCertificates []*x509.Certificate
	// RequireSignature fails the check when no trusted issuer validates the CRL.
	RequireSignature bool
}

type Finding struct {
	Severity string `json:"severity" yaml:"severity"`
	Message  string `json:"message" yaml:"message"`
}

type Report struct {
	SchemaVersion       string    `json:"schema_version" yaml:"schema_version"`
	Name                string    `json:"name,omitempty" yaml:"name,omitempty"`
	Source              string    `json:"source" yaml:"source"`
	Status              string    `json:"status" yaml:"status"`
	HTTPStatus          int       `json:"http_status,omitempty" yaml:"http_status,omitempty"`
	Issuer              string    `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	ThisUpdate          string    `json:"this_update,omitempty" yaml:"this_update,omitempty"`
	NextUpdate          string    `json:"next_update,omitempty" yaml:"next_update,omitempty"`
	DaysRemaining       int       `json:"days_remaining" yaml:"days_remaining"`
	AgeSeconds          int64     `json:"age_seconds" yaml:"age_seconds"`
	Number              string    `json:"number,omitempty" yaml:"number,omitempty"`
	RevokedCertificates int       `json:"revoked_certificates" yaml:"revoked_certificates"`
	SHA256              string    `json:"sha256,omitempty" yaml:"sha256,omitempty"`
	SignatureChecked    bool      `json:"signature_checked" yaml:"signature_checked"`
	SignatureValid      bool      `json:"signature_valid" yaml:"signature_valid"`
	Findings            []Finding `json:"findings,omitempty" yaml:"findings,omitempty"`
	Error               string    `json:"error,omitempty" yaml:"error,omitempty"`
}

func Run(ctx context.Context, opts Options) Report {
	report, _, _ := Check(ctx, opts)
	return report
}

func Check(ctx context.Context, opts Options) (Report, *x509.RevocationList, error) {
	normalizeOptions(&opts)
	report := Report{SchemaVersion: reportcontract.SchemaVersion, Name: opts.Name, Source: opts.Source, Status: "ok"}
	if strings.TrimSpace(opts.Source) == "" {
		err := fmt.Errorf("CRL source is required")
		report.Status = "critical"
		report.Error = err.Error()
		add(&report, "critical", err.Error())
		return report, nil, err
	}

	data, httpStatus, err := Fetch(ctx, opts.Source, opts.Timeout, opts.Insecure)
	report.HTTPStatus = httpStatus
	if err != nil {
		report.Status = "critical"
		report.Error = err.Error()
		add(&report, "critical", "CRL fetch failed: "+err.Error())
		return report, nil, err
	}

	list, der, err := Parse(data)
	if err != nil {
		report.Status = "critical"
		report.Error = err.Error()
		add(&report, "critical", "CRL parse failed: "+err.Error())
		return report, nil, err
	}
	populateReport(&report, list, der)
	validateFreshness(&report, list, opts)
	if strings.TrimSpace(opts.CABundle) != "" || opts.RequireSignature || len(opts.IssuerCertificates) > 0 {
		validateSignature(&report, list, opts.CABundle, opts.IssuerCertificates)
	}
	report.Status = aggregate(report.Findings)
	return report, list, nil
}

func normalizeOptions(opts *Options) {
	if opts.WarnDays == 0 {
		opts.WarnDays = 3
	}
	if opts.CriticalDays == 0 {
		opts.CriticalDays = 1
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
}

func Fetch(ctx context.Context, source string, timeout time.Duration, insecure bool) ([]byte, int, error) {
	source = strings.TrimSpace(source)
	u, err := url.Parse(source)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		client := &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		if insecure {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			client.Transport = transport
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		body, err := readLimited(resp.Body, 32<<20)
		if err != nil {
			return nil, resp.StatusCode, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return body, resp.StatusCode, nil
	}
	data, err := os.ReadFile(source)
	return data, 0, err
}

func Parse(data []byte) (*x509.RevocationList, []byte, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("empty CRL")
	}
	if block, _ := pem.Decode(data); block != nil {
		if !strings.Contains(strings.ToUpper(block.Type), "CRL") {
			return nil, nil, fmt.Errorf("PEM block is %q, not a CRL", block.Type)
		}
		list, err := x509.ParseRevocationList(block.Bytes)
		return list, block.Bytes, err
	}
	list, err := x509.ParseRevocationList(data)
	return list, data, err
}

func populateReport(report *Report, list *x509.RevocationList, der []byte) {
	sum := sha256.Sum256(der)
	report.SHA256 = "SHA256:" + strings.ToUpper(hex.EncodeToString(sum[:]))
	report.Issuer = list.Issuer.String()
	report.ThisUpdate = formatTime(list.ThisUpdate)
	report.NextUpdate = formatTime(list.NextUpdate)
	report.DaysRemaining = int(time.Until(list.NextUpdate).Hours() / 24)
	report.AgeSeconds = int64(time.Since(list.ThisUpdate).Seconds())
	report.RevokedCertificates = len(list.RevokedCertificateEntries)
	if list.Number != nil {
		report.Number = list.Number.String()
	}
}

func validateFreshness(report *Report, list *x509.RevocationList, opts Options) {
	now := time.Now()
	if list.ThisUpdate.IsZero() {
		add(report, "critical", "CRL thisUpdate is missing")
	} else if list.ThisUpdate.After(now.Add(5 * time.Minute)) {
		add(report, "critical", "CRL thisUpdate is in the future")
	}
	if list.NextUpdate.IsZero() {
		add(report, "critical", "CRL nextUpdate is missing")
	} else if !list.NextUpdate.After(now) {
		add(report, "critical", fmt.Sprintf("CRL expired at %s", formatTime(list.NextUpdate)))
	} else if report.DaysRemaining <= opts.CriticalDays {
		add(report, "critical", fmt.Sprintf("CRL expires in %d days", report.DaysRemaining))
	} else if report.DaysRemaining <= opts.WarnDays {
		add(report, "warn", fmt.Sprintf("CRL expires in %d days", report.DaysRemaining))
	}
	if opts.MaxAgeDays > 0 && !list.ThisUpdate.IsZero() {
		ageDays := int(now.Sub(list.ThisUpdate).Hours() / 24)
		if ageDays > opts.MaxAgeDays {
			add(report, "warn", fmt.Sprintf("CRL was last updated %d days ago", ageDays))
		}
	}
}

func validateSignature(report *Report, list *x509.RevocationList, caBundle string, issuerCertificates []*x509.Certificate) {
	report.SignatureChecked = true
	certs := append([]*x509.Certificate(nil), issuerCertificates...)
	if strings.TrimSpace(caBundle) != "" {
		bundleCerts, err := loadCerts(caBundle)
		if err != nil {
			add(report, "critical", "CRL signature could not be checked: "+err.Error())
			return
		}
		certs = append(certs, bundleCerts...)
	}
	var signatureErrs []string
	for _, cert := range certs {
		if !issuerMatches(list, cert) {
			continue
		}
		if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
			signatureErrs = append(signatureErrs, "issuer certificate is missing keyUsage cRLSign: "+cert.Subject.String())
			continue
		}
		if err := list.CheckSignatureFrom(cert); err != nil {
			signatureErrs = append(signatureErrs, err.Error())
			continue
		}
		report.SignatureValid = true
		return
	}
	if len(signatureErrs) == 0 {
		add(report, "critical", "CRL signature issuer was not found in CA bundle")
		return
	}
	add(report, "critical", "CRL signature is invalid: "+strings.Join(signatureErrs, "; "))
}

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

func loadCerts(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
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
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return certs, nil
}

func issuerMatches(list *x509.RevocationList, cert *x509.Certificate) bool {
	if len(list.AuthorityKeyId) > 0 && len(cert.SubjectKeyId) > 0 && bytes.Equal(list.AuthorityKeyId, cert.SubjectKeyId) {
		return true
	}
	return list.Issuer.String() == cert.Subject.String()
}

func CertificateRevoked(cert *x509.Certificate, lists []*x509.RevocationList) (bool, string) {
	for _, list := range lists {
		if !crlAppliesToCertificate(list, cert) {
			continue
		}
		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber != nil && entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return true, list.Issuer.String()
			}
		}
	}
	return false, ""
}

func crlAppliesToCertificate(list *x509.RevocationList, cert *x509.Certificate) bool {
	if len(list.AuthorityKeyId) > 0 && len(cert.AuthorityKeyId) > 0 {
		return bytes.Equal(list.AuthorityKeyId, cert.AuthorityKeyId)
	}
	return cert.Issuer.String() == list.Issuer.String()
}

func add(report *Report, severity, message string) {
	report.Findings = append(report.Findings, Finding{Severity: severity, Message: message})
}

func aggregate(findings []Finding) string {
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

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
