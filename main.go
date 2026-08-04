package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "ca":
		cmdCA(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "crl":
		cmdCRL(os.Args[2:])
	case "drift":
		cmdDrift(os.Args[2:])
	case "fleet":
		cmdFleet(os.Args[2:])
	case "init":
		cmdInit(os.Args[2:])
	case "inventory":
		cmdInventory(os.Args[2:])
	case "plan":
		cmdPlan(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "trust":
		cmdTrust(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "version":
		cmdVersion(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fatal("unknown command: " + os.Args[1])
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `certops - TLS and HTTPS operations CLI

Usage:
  certops version [--json|--yaml]
  certops init [-f certops.yaml] [--force]
  certops inventory list -f certops.yaml [--json|--yaml]
  certops inventory show <host|group> -f certops.yaml [--json|--yaml]
  certops ca list -f certops.yaml [--json|--yaml]
  certops ca fetch -f certops.yaml --out roots/
  certops fleet trust plan -f certops.yaml [--limit host|group] [--json|--yaml]
  certops fleet trust verify -f certops.yaml [--limit host|group] [--json|--yaml] [--fail-on warn|critical]
  certops fleet trust install -f certops.yaml --yes [--limit host|group] [--json|--yaml] [--html report.html]
  certops fleet trust apply -f certops.yaml --yes [--limit host|group] [--json|--yaml] [--html report.html]
  certops fleet trust remove -f certops.yaml --yes [--limit host|group] [--json|--yaml] [--html report.html]
  certops plan -f certops.yaml [--live] [--json|--yaml] [--html report.html] [--fail-on warn|critical]
  certops drift -f certops.yaml [--json|--yaml] [--html report.html] [--fail-on warn|critical]
  certops ca cfssl health --url http://127.0.0.1:8888 [--json|--yaml|--prom]
  certops ca cfssl info --url http://127.0.0.1:8888 [--label root] [--profile server] [--fingerprint SHA256:...] [--out cfssl-ca.pem]
  certops ca generic info --ca-bundle root.pem|--url https://pki.example.com/root.pem [--fingerprint SHA256:...] [--out root.pem]
  certops ca smallstep health --url https://ca.internal.example.com [--insecure] [--json|--yaml|--prom]
  certops ca smallstep roots --url https://ca.internal.example.com [--fingerprint SHA256:...] [--insecure] [--out roots.pem]
  certops ca smallstep info --url https://ca.internal.example.com [--fingerprint SHA256:...] [--insecure] [--json|--yaml|--prom]
  certops ca vault health --url http://127.0.0.1:8200 [--standby-ok] [--json|--yaml|--prom]
  certops ca vault ca --url http://127.0.0.1:8200 [--mount pki] [--fingerprint SHA256:...] [--out vault-ca.pem]
  certops ca vault info --url http://127.0.0.1:8200 [--mount pki] [--fingerprint SHA256:...] [--json|--yaml|--prom]
  certops crl check --file ca.crl|--url https://pki.example.com/ca.crl --ca-bundle issuer.pem [--warn-days 3] [--critical-days 1] [--max-age-days 7] [--insecure] [--json|--yaml|--prom]
  certops check <host|url> [--server-name name] [--connect host:port] [--json|--yaml|--prom] [--html report.html] [--otel-endpoint URL] [--warn-days 30] [--critical-days 14] [--ca-bundle path] [--crl path-or-url] [--auto-crl] [--crl-insecure] [--crl-ca-bundle path] [--crl-warn-days 3] [--crl-critical-days 1] [--crl-max-age-days 7] [--fail-on warn|critical]
  certops scan --input domains.txt [--concurrency 4] [--json|--yaml|--prom] [--html report.html] [--otel-endpoint URL] [--warn-days 30] [--critical-days 14] [--ca-bundle path] [--crl path-or-url] [--auto-crl] [--crl-insecure] [--crl-ca-bundle path] [--crl-warn-days 3] [--crl-critical-days 1] [--crl-max-age-days 7] [--fail-on warn|critical]
  certops trust plan --ca-bundle root.pem [--json|--yaml|--prom] [--fail-on warn|critical]
  certops trust verify --ca-bundle root.pem [--json|--yaml|--prom] [--fail-on warn|critical]
  certops trust install --ca-bundle root.pem --yes [--name company-root]
  certops verify -f certs.yaml [--json|--yaml|--prom] [--html report.html] [--otel-endpoint URL] [--fail-on warn|critical]

`)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "certops:", msg)
	os.Exit(2)
}
