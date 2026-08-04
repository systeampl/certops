# Changelog

All notable changes to `certops` are documented here. The project follows
Semantic Versioning.

## [Unreleased]

### Changed

- moved the public Go module namespace to `github.com/systeampl/certops`
- aligned CI, releases, dependency updates, contribution guidance, and build
  metadata with the SysTeam Ops Tools contract
- added `--version` as an alias for the existing text, JSON, and YAML version
  output
- exposed the common `info`, `warn`, `critical`, and `error` severities from
  the supported Go package
- added `schema_version` to standalone CRL reports

### Fixed

- replaced deprecated X.509 CRL and certificate-pool APIs and removed dead
  formatting helpers found by Staticcheck

## [0.2.0] - 2026-08-04

### Added

- Cryptographic OCSP staple validation and signed CRL revocation checks,
  including opt-in CRL distribution-point discovery.
- Certificate chain, public-key, signature-algorithm, cipher, and effective
  HSTS reporting in human, JSON, YAML, Prometheus, HTML, and OTLP outputs.
- Separate TLS server identity and TCP destination for endpoint, service, and
  verification checks.
- Bounded concurrent scans with deterministic result ordering.
- Strict YAML configuration/spec validation, stable endpoint report schema,
  a public Go API, and a `version` command.
- GitHub CI, scheduled live integration, Dependabot, and GoReleaser workflows.

### Fixed

- CA material is no longer written or installed after provider validation or
  fingerprint failures.
- Smallstep insecure bootstrap requires a pinned SHA-256 fingerprint, and
  provider/CRL/OTLP clients refuse redirects.
- Vault tokens cannot be forwarded across HTTP redirects.
- Unverified or forged CRLs cannot mark certificates as revoked; standalone
  and declarative CRL checks require an issuer CA.
- Non-CA and expired certificates are rejected before trust-store install.
- SSH fleet operations use persistent host-key verification, bounded timeouts,
  deterministic expansion, and managed-root drift detection.
- HSTS `max-age=0`, malformed HSTS, weak certificate crypto, and weak
  negotiated ciphers are no longer reported as healthy.
- Configured leaf-expiry and failure policies are enforced consistently.
- Go was updated to a patched toolchain and vulnerable standard-library paths
  reported by `govulncheck` were removed.

## [0.1.0] - 2026-07-05

- Initial PKI provider, endpoint, trust-store, fleet, plan, drift, and reporting
  implementation.

[Unreleased]: https://github.com/systeampl/certops/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/systeampl/certops/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/systeampl/certops/releases/tag/v0.1.0
