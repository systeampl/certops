# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's security
advisory form for this repository. Do not open a public issue containing
secrets, exploit details, private PKI material, or affected infrastructure.

Include the affected Certops version or commit, operating system, reproduction
steps, impact, and any suggested mitigation. Reports will be acknowledged and
triaged as soon as practical.

## Operational guidance

- Pin SHA-256 fingerprints whenever CA material is fetched from a URL.
- Use `--insecure` only for bootstrap, together with the required fingerprint.
- Treat CA bundles, Vault tokens, SSH identities, and generated reports as
  sensitive operational data.
- Review `plan`, `drift`, and trust-store changes before using `--yes`.
- Keep Certops and its Go toolchain updated; CI runs `govulncheck` on every
  change.

