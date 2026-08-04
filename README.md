# certops

[![CI](https://github.com/systeampl/certops/actions/workflows/ci.yml/badge.svg)](https://github.com/systeampl/certops/actions/workflows/ci.yml)

`certops` is a PKI and TLS operations CLI. It checks CA providers, endpoint
certificates, local trust stores, and remote Linux trust stores from one
terminal tool.

Part of [SysTeam Ops Tools](https://github.com/systeampl):
[dnsops](https://github.com/systeampl/dnsops) ·
[certops](https://github.com/systeampl/certops) ·
[mailops](https://github.com/systeampl/mailops). The open-source tools are
built by [SysTeam](https://systeam.pl), run standalone, and provide structured
results designed for deep checks in [SysChecks](https://syschecks.com).

The main workflow is config-driven:

```bash
certops init
certops plan -f certops.yaml
certops plan -f certops.yaml --live
certops drift -f certops.yaml --fail-on warn
certops fleet trust plan -f certops.yaml --limit runners
certops fleet trust apply -f certops.yaml --limit runner-01 --yes
certops fleet trust verify -f certops.yaml --limit runner-01
```

`plan`, `drift`, `check`, `scan`, `verify`, and provider inspection commands
only report state. Commands that change trust stores require explicit `--yes`.

## Features

- Declarative `certops.yaml` with CA providers, inventory, trust targets, and services.
- CA provider checks for Smallstep, Vault PKI, CFSSL-compatible APIs, and generic PEM bundles or URLs.
- TLS endpoint checks for expiry, SAN/hostname match, chain trust, public-key and signature strength, TLS versions/cipher, ALPN, cryptographically validated OCSP stapling, redirects, and effective HSTS.
- Signed CRL validation for explicit sources and opt-in certificate distribution points, including `thisUpdate`, `nextUpdate`, CRL number, freshness, and revoked serials.
- Drift reports that compare configured PKI state with live CA and service checks.
- Local trust-store plan, verify, and install for CA bundles.
- Remote Linux trust-store plan, apply, verify, and remove over SSH.
- JSON, YAML, Prometheus text, HTML reports, and OTLP/HTTP metric export where supported.
- Watch mode for `check` and `verify`.
- Separate TLS identity (`--server-name`) and TCP destination (`--connect`) for load balancers, inventories, and pre-DNS checks.
- Bounded concurrent scans with stable input ordering.
- Strict YAML parsing and validation, versioned endpoint reports, and a public Go API at `pkg/certops`.

## Install

```bash
git clone https://github.com/systeampl/certops.git
cd certops
go build -o certops .
sudo install -m 0755 certops /usr/local/bin/certops
```

Check the installed build with `certops version`, `certops version --json`, or
`certops --version --yaml`.

For a local build without VCS metadata:

```bash
go build -buildvcs=false -o certops .
```

## Configuration

Create a starter config:

```bash
certops init
```

Example `certops.yaml`:

```yaml
policy:
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
          port: "22"
          identity_file: ~/.ssh/id_ed25519
          os: linux

trust:
  targets:
    - group: runners
      required:
        - lan-step

services:
  - name: internal-api
    host: runner-01
    port: "443"
    server_name: api.lan.example.com
    ca: lan-step
    crls:
      - lan-step-crl
    auto_crl: true
    expected_names:
      - api.lan.example.com
    require_tls13: true
    require_hsts: true
```

## Core Commands

### Inventory

```bash
certops inventory list -f certops.yaml
certops inventory show runners -f certops.yaml
certops inventory show runner-01 -f certops.yaml --json
```

### CA Providers

List and fetch CAs from config:

```bash
certops ca list -f certops.yaml
certops ca fetch -f certops.yaml --out roots/
```

Check providers directly:

```bash
certops ca smallstep health --url https://ca.lan.example.com
certops ca smallstep roots --url https://ca.lan.example.com --fingerprint SHA256:AA:BB:... --out smallstep-roots.pem
certops ca smallstep info --url https://127.0.0.1:9000 --fingerprint SHA256:AA:BB:... --insecure

certops ca vault health --url http://127.0.0.1:8200
certops ca vault ca --url http://127.0.0.1:8200 --mount pki --out vault-ca.pem
certops ca vault info --url http://127.0.0.1:8200 --mount pki --fingerprint SHA256:AA:BB:...

certops ca cfssl health --url http://127.0.0.1:8888
certops ca cfssl info --url http://127.0.0.1:8888 --fingerprint SHA256:AA:BB:... --out cfssl-ca.pem

certops ca generic info --ca-bundle vendor-root.pem
certops ca generic info --url https://pki.example.com/root.pem --fingerprint SHA256:AA:BB:... --out vendor-root.pem
```

CA material fetched from a URL is only written after provider validation and
fingerprint verification. `--insecure` exists for bootstrap cases where the CA
HTTPS endpoint is not trusted yet and requires a SHA-256 fingerprint in the
same command. Provider clients refuse redirects; this also prevents Vault
tokens from being forwarded to another origin. Prefer `VAULT_TOKEN` over a
token on the command line.

### CRL Checks

```bash
certops crl check --file ca.crl --ca-bundle issuer.pem
certops crl check --url https://pki.example.com/ca.crl --ca-bundle issuer.pem --prom
certops check api.example.com --ca-bundle roots.pem --crl ca.crl --crl-ca-bundle issuer.pem
certops check api.example.com --ca-bundle roots.pem --auto-crl
```

`crl check` requires `--ca-bundle`, accepts PEM or DER CRLs, and reports `thisUpdate`, `nextUpdate`,
days remaining, CRL number, revoked-entry count, SHA-256 fingerprint, and CRL
signature status. `check`, `scan`, and `verify` accept explicit CRLs; `check`
and `scan` also support `--auto-crl`. A CRL participates in revocation decisions
only after its signature is verified against the presented issuer chain or a
configured CRL CA bundle. `--crl-insecure` disables HTTPS verification only for
fetching an explicit CRL; it never disables CRL signature validation.

### Plan And Drift

```bash
certops plan -f certops.yaml
certops plan -f certops.yaml --live
certops plan -f certops.yaml --html certops-plan.html
certops drift -f certops.yaml
certops drift -f certops.yaml --fail-on warn
certops drift -f certops.yaml --no-live
certops drift -f certops.yaml --html certops-drift.html
```

`plan` validates the configured CA providers, CRLs, inventory, trust policies,
and services. With `--live`, it also fetches configured CA roots, checks CA
expiry against `policy.min_ca_days_remaining`, checks CRL freshness, and runs
live TLS checks plus service policy checks for configured services.

`plan` and `drift` use `policy.fail_on` when `--fail-on` is not provided.
`drift` uses the same model and reports non-OK or manual items. Use `--no-live`
for static config drift only.

### Local Trust Store

```bash
certops trust plan --ca-bundle company-root.pem
certops trust verify --ca-bundle company-root.pem
certops trust plan --url https://pki.example.com/roots.pem --fingerprint SHA256:AA:BB:...
certops trust plan --smallstep-url https://ca.lan.example.com --fingerprint SHA256:AA:BB:...
sudo certops trust install --ca-bundle company-root.pem --name company-root --yes
```

`trust install` modifies the local trust store and requires `--yes`.

### Remote Fleet Trust

```bash
certops fleet trust plan -f certops.yaml
certops fleet trust plan -f certops.yaml --limit runners --html fleet-plan.html
certops fleet trust apply -f certops.yaml --limit runner-01 --yes
certops fleet trust verify -f certops.yaml --limit runner-01
certops fleet trust remove -f certops.yaml --limit runner-01 --yes
```

Remote trust operations currently target Linux hosts over SSH. `apply`,
`install`, and `remove` change the remote trust store and require `--yes`.
SSH uses the user's persistent `known_hosts` file with
`StrictHostKeyChecking=accept-new`, batch mode, and bounded connect/command
timeouts. Existing host-key changes are still rejected.
Managed roots are written under:

```text
/usr/local/share/ca-certificates/certops-<ca-name>.crt
```

When `policy.allow_unmanaged_roots` is `false`, fleet verification reports
additional `certops-*.crt` files that are not declared for the target. It does
not flag operating-system or vendor roots outside the Certops namespace.

### Endpoint Checks

```bash
certops check example.com
certops check https://api.example.com
certops check example.com:8443 --json
certops check internal.example.com --ca-bundle smallstep-root.pem
certops check internal.example.com --ca-bundle smallstep-root.pem --crl ca.crl --crl-ca-bundle smallstep-root.pem
certops check api.example.com --server-name api.example.com --connect 192.0.2.10:443
certops check api.example.com --ca-bundle smallstep-root.pem --auto-crl
certops check api.example.com --watch --until-ok --interval 5s
certops check api.example.com --html certops-report.html
```

`check` accepts `host`, `host:port`, or `https://host`. It supports
`--json`, `--yaml`, `--prom`, `--html`, `--otel-endpoint`, `--warn-days`,
`--critical-days`, `--ca-bundle`, repeatable `--crl`, `--crl-ca-bundle`,
`--crl-warn-days`, `--crl-critical-days`, `--crl-max-age-days`, `--fail-on`,
`--auto-crl`, `--server-name`, `--connect`, and watch flags. Expiry thresholds
accept `-1` to disable that threshold. Timeouts must be positive.

Scan multiple targets:

```bash
certops scan --input domains.txt
certops scan example.com api.example.com --json
certops scan --input domains.txt --concurrency 16 --prom
certops scan --input domains.txt --html certops-report.html
```

Scan concurrency defaults to 4 and accepts values from 1 through 128. Results
retain the same order as their input even when checks finish out of order.

### Expected-State Verification

```bash
certops verify -f certs.yaml
certops verify -f certs.yaml --json
certops verify -f certs.yaml --prom
certops verify -f certs.yaml --html certops-report.html
certops verify -f certs.yaml --watch --until-ok
```

Example `certs.yaml`:

```yaml
defaults:
  warn_days: 30
  critical_days: 14
  timeout: 10s
  ca_bundle: smallstep-root.pem
  crl_ca_bundle: smallstep-root.pem
  crl_warn_days: 3
  crl_critical_days: 1
  crl_max_age_days: 7

targets:
  - name: internal-api
    host: api.lan.example.com
    server_name: api.lan.example.com
    connect: 10.10.1.21:443
    crls:
      - smallstep.crl
    auto_crl: true
    min_days_remaining: 30
    require_tls13: true
    require_hsts: true
    forbid_tls10: true
    forbid_tls11: true
    expected_names:
      - api.lan.example.com
    allowed_issuers:
      - Smallstep
```

Verification specs use strict YAML: unknown fields, duplicate YAML documents,
invalid thresholds, and invalid durations are rejected before network work.

## Output And Exit Codes

Supported outputs vary by command, but the common formats are:

- human-readable table or report output
- `--json`
- `--yaml`
- `--prom`
- `--html report.html`
- `--otel-endpoint http://collector:4318`

Exit codes:

- `0`: no findings at or above the selected threshold
- `1`: findings at or above `--fail-on`
- `2`: usage, config, or runtime error

## Local Lab

The repository includes a Docker-based lab for Smallstep, Vault PKI,
CFSSL-compatible APIs, generic PEM roots, a Linux SSH target, and an HTTPS test
service.

```bash
bash docs/lab/bootstrap.sh
bash docs/lab/smoke.sh
bash docs/lab/cleanup.sh
```

See [`docs/LAB.md`](docs/LAB.md).

## Development

```bash
go test ./...
go test -race -shuffle=on ./...
go vet ./...
go build -buildvcs=false -o /tmp/certops .
```

The reusable engine is available at `github.com/systeampl/certops/pkg/certops`:

```go
report, err := certops.CheckTarget(ctx, "api.example.com", certops.CheckOptions{
    Timeout: 10 * time.Second,
    AutoCRL: true,
})
```

Machine-readable endpoint reports include `schema_version`; consumers should
validate it against `certops.SchemaVersion`, currently `certops.report.v1`.
New fields may be added within that version; breaking changes increment its
major component. Common finding severity constants are `info`, `warn`,
`critical`, and `error`. Integration adapters belong in the consuming product,
so the standalone tool and its public engine remain reusable.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
