package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const starterConfig = `policy:
  fail_on: warn
  min_ca_days_remaining: 180
  min_leaf_days_remaining: 30
  min_crl_days_remaining: 3
  max_crl_age_days: 7
  allow_unmanaged_roots: false

cas:
  - name: lan-step
    provider: smallstep
    url: https://ca.lan.example.com
    fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

  - name: vault-prod
    provider: vault
    url: https://vault.example.com
    mount: pki
    fingerprint: SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

  - name: vendor-root
    provider: generic
    ca_bundle: vendor-root.pem
    fingerprint: SHA256:1111111111111111111111111111111111111111111111111111111111111111

crls:
  - name: lan-step-crl
    ca: lan-step
    url: https://ca.lan.example.com/crl
    warn_days: 3
    critical_days: 1

inventory:
  groups:
    runners:
      hosts:
        runner-01:
          address: 10.10.1.21
          user: ops
          os: linux

trust:
  targets:
    - group: runners
      required:
        - lan-step

services:
  - name: internal-api
    url: https://api.lan.example.com
    ca: lan-step
    crls:
      - lan-step-crl
    expected_names:
      - api.lan.example.com
    require_tls13: true
    require_hsts: true
`

func cmdInit(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true})
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	file := fs.String("f", "certops.yaml", "config file to create")
	force := fs.Bool("force", false, "overwrite existing config")
	fs.Parse(args)

	path := defaultConfigPath(*file)
	if !*force {
		if _, err := os.Stat(path); err == nil {
			fatal(path + " already exists; use --force to overwrite")
		}
	}
	if err := writeFileAtomic(path, []byte(starterConfig), 0644); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("created %s\n", strings.TrimSpace(path))
}
