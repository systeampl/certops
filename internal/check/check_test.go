package check

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestCheckRevocationMarksRevokedCertificateCritical(t *testing.T) {
	ca, key, caPEM := testCheckCA(t)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Issuer:       ca.Subject,
	}
	crlDER := testCheckCRL(t, ca, key, []*big.Int{leaf.SerialNumber})
	dir := t.TempDir()
	crlPath := filepath.Join(dir, "ca.crl")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		t.Fatal(err)
	}

	report := Report{Status: "ok"}
	checkRevocation(context.Background(), &report, []*x509.Certificate{leaf}, Options{
		CRLSources:  []string{crlPath},
		CRLCABundle: caPath,
	})

	if !report.Revocation.Checked || !report.Revocation.Revoked {
		t.Fatalf("revocation checked/revoked = %t/%t", report.Revocation.Checked, report.Revocation.Revoked)
	}
	if aggregateStatus(report.Findings) != "critical" {
		t.Fatalf("findings did not aggregate critical: %+v", report.Findings)
	}
}

func TestRunUsesSeparateServerNameAndConnectAddress(t *testing.T) {
	ca, caKey, caPEM := testCheckCA(t)
	serverName := "api.example.test"
	leafDER, leafKey := testCheckLeaf(t, ca, caKey, serverName)
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, ca.Raw}, PrivateKey: leafKey}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.WriteHeader(http.StatusNoContent)
		}),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() { _ = server.Close() })

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), serverName, listener.Addr().String(), Options{
		CABundle:     caPath,
		Timeout:      2 * time.Second,
		WarnDays:     30,
		CriticalDays: 14,
	})
	if !report.Certificate.Trusted || !report.Certificate.MatchesHost {
		t.Fatalf("certificate trust/hostname = %t/%t, findings=%+v", report.Certificate.Trusted, report.Certificate.MatchesHost, report.Findings)
	}
	if !report.HTTPS.HSTSEnabled {
		t.Fatalf("HSTS was not detected: %+v", report.HTTPS)
	}
	if report.Host != serverName || report.Address != listener.Addr().String() || report.SchemaVersion != SchemaVersion {
		t.Fatalf("endpoint identity = %+v", report)
	}
}

func TestCheckRevocationRejectsCRLSignedByUntrustedKey(t *testing.T) {
	issuer, _, _ := testCheckCA(t)
	attacker, attackerKey, _ := testCheckCA(t)
	leaf := &x509.Certificate{
		SerialNumber:   big.NewInt(42),
		Issuer:         issuer.Subject,
		AuthorityKeyId: issuer.SubjectKeyId,
	}
	crlDER := testCheckCRL(t, attacker, attackerKey, []*big.Int{leaf.SerialNumber})
	crlPath := filepath.Join(t.TempDir(), "malicious.crl")
	if err := os.WriteFile(crlPath, crlDER, 0600); err != nil {
		t.Fatal(err)
	}

	report := Report{Status: "ok"}
	checkRevocation(context.Background(), &report, []*x509.Certificate{leaf, issuer}, Options{CRLSources: []string{crlPath}})
	if report.Revocation.Revoked {
		t.Fatal("an untrusted CRL marked the certificate revoked")
	}
	if len(report.Revocation.ValidatedSources) != 0 {
		t.Fatalf("validated sources = %v", report.Revocation.ValidatedSources)
	}
	if aggregateStatus(report.Findings) != "critical" {
		t.Fatalf("signature failure was not critical: %+v", report.Findings)
	}
}

func TestAutoCRLUsesDistributionPointAndValidatesSignature(t *testing.T) {
	ca, key, _ := testCheckCA(t)
	leaf := &x509.Certificate{
		SerialNumber:   big.NewInt(43),
		Issuer:         ca.Subject,
		AuthorityKeyId: ca.SubjectKeyId,
	}
	crlDER := testCheckCRL(t, ca, key, []*big.Int{leaf.SerialNumber})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(crlDER)
	}))
	defer server.Close()
	leaf.CRLDistributionPoints = []string{server.URL + "/ca.crl"}

	report := Report{Status: "ok"}
	checkRevocation(context.Background(), &report, []*x509.Certificate{leaf, ca}, Options{AutoCRL: true, Timeout: time.Second})
	if !report.Revocation.Revoked || len(report.Revocation.ValidatedSources) != 1 {
		t.Fatalf("unexpected revocation result: %+v, findings=%+v", report.Revocation, report.Findings)
	}
}

func TestCheckOCSPStapleValidatesStatusAndFreshness(t *testing.T) {
	ca, key, _ := testCheckCA(t)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(44), Issuer: ca.Subject}
	for _, tc := range []struct {
		name       string
		status     int
		wantStatus string
		wantSev    string
	}{
		{name: "good", status: ocsp.Good, wantStatus: "good", wantSev: "ok"},
		{name: "revoked", status: ocsp.Revoked, wantStatus: "revoked", wantSev: "critical"},
		{name: "unknown", status: ocsp.Unknown, wantStatus: "unknown", wantSev: "warn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			staple, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
				Status:       tc.status,
				SerialNumber: leaf.SerialNumber,
				ThisUpdate:   time.Now().Add(-time.Hour),
				NextUpdate:   time.Now().Add(time.Hour),
				RevokedAt:    time.Now().Add(-time.Minute),
			}, key)
			if err != nil {
				t.Fatal(err)
			}
			report := Report{Status: "ok"}
			checkOCSPStaple(&report, staple, []*x509.Certificate{leaf, ca})
			if report.TLS.OCSPStatus != tc.wantStatus {
				t.Fatalf("OCSP status = %q, want %q", report.TLS.OCSPStatus, tc.wantStatus)
			}
			if got := aggregateStatus(report.Findings); got != tc.wantSev {
				t.Fatalf("findings status = %q, want %q: %+v", got, tc.wantSev, report.Findings)
			}
		})
	}

	report := Report{Status: "ok"}
	checkOCSPStaple(&report, []byte("not DER"), []*x509.Certificate{leaf, ca})
	if report.TLS.OCSPStatus != "invalid" || aggregateStatus(report.Findings) != "critical" {
		t.Fatalf("malformed staple result: %+v, findings=%+v", report.TLS, report.Findings)
	}
}

func TestHSTSEnabled(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{value: "max-age=31536000; includeSubDomains", want: true},
		{value: "MAX-AGE=1", want: true},
		{value: "max-age=0", want: false},
		{value: "max-age=abc", want: false},
		{value: "includeSubDomains", want: false},
	} {
		if got := hstsEnabled(tc.value); got != tc.want {
			t.Fatalf("hstsEnabled(%q) = %t, want %t", tc.value, got, tc.want)
		}
	}
}

func TestCertificateCryptoFindings(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{PublicKeyAlgorithm: x509.RSA, PublicKey: &key.PublicKey, SignatureAlgorithm: x509.SHA1WithRSA}
	_, bits := certificateKeyInfo(cert)
	report := Report{Status: "ok"}
	checkCertificateCrypto(&report, cert, bits)
	if bits != 1024 || aggregateStatus(report.Findings) != "critical" || len(report.Findings) != 2 {
		t.Fatalf("crypto findings = %+v, bits=%d", report.Findings, bits)
	}
}

func testCheckCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Check Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{5, 6, 7, 8},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testCheckCRL(t *testing.T, ca *x509.Certificate, key *rsa.PrivateKey, serials []*big.Int) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, serial := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(9),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
		SignatureAlgorithm:        x509.SHA256WithRSA,
	}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func testCheckLeaf(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, name string) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: name},
		DNSNames:       []string{name},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}
