# certops local lab

The local lab tests real provider and host-trust workflows without external
infrastructure.

## Goals

- run a local Smallstep CA
- run a local Vault dev server with PKI enabled
- run a CFSSL-compatible mock API
- run a generic PEM HTTP endpoint
- run a target Linux container reachable over SSH
- run an HTTPS service with a Vault-issued certificate
- fetch CA roots with `certops`
- verify provider readiness with pinned fingerprints
- install and verify CA trust on the target Linux container
- tear down all lab state cleanly

## Topology

```text
host
  certops
  docker compose

containers
  step-ca
  vault
  cfssl-mock
  generic-roots
  target-linux
  https-vault
```

## Quick Start

```bash
cd /home/destine/GIT/wlasne/certops
bash docs/lab/bootstrap.sh
```

The bootstrap script:

- generates a disposable SSH key for `target-linux`
- starts Smallstep CA, Vault dev server, and the SSH target container
- enables Vault PKI
- issues a short-lived HTTPS certificate from Vault PKI
- starts an Nginx HTTPS service with that certificate
- starts a CFSSL-compatible API mock
- starts an HTTP endpoint serving a generic root PEM
- writes `docs/lab/certops.lab.yaml` with pinned fingerprints
- fetches provider roots through `certops`
- prints follow-up commands for manual checks

## Test Flow

```bash
certops ca smallstep info \
  --url https://127.0.0.1:9000 \
  --fingerprint SHA256:... \
  --insecure

certops ca vault info \
  --url http://127.0.0.1:8200 \
  --mount pki \
  --fingerprint SHA256:...

certops ca cfssl info \
  --url http://127.0.0.1:8888 \
  --fingerprint SHA256:...

certops ca generic info \
  --url http://127.0.0.1:8088/generic-root.pem \
  --fingerprint SHA256:...

certops ca fetch -f docs/lab/certops.lab.yaml --out /tmp/certops-lab-roots
certops inventory list -f docs/lab/certops.lab.yaml
certops plan -f docs/lab/certops.lab.yaml
certops plan -f docs/lab/certops.lab.yaml --live
certops drift -f docs/lab/certops.lab.yaml --fail-on warn
certops check https://127.0.0.1:9443 --ca-bundle /tmp/certops-lab-roots/lab-vault.pem --fail-on critical
certops fleet trust plan -f docs/lab/certops.lab.yaml --limit target-linux
certops fleet trust apply -f docs/lab/certops.lab.yaml --limit target-linux --yes
certops fleet trust verify -f docs/lab/certops.lab.yaml --limit target-linux
certops fleet trust remove -f docs/lab/certops.lab.yaml --limit target-linux --yes
```

The Smallstep command uses `--insecure` because a fresh lab CA serves HTTPS
with a certificate that is not trusted by the host yet. The root fingerprint is
still pinned and verified.

## Full Smoke

```bash
bash docs/lab/smoke.sh
```

The smoke test covers Smallstep, Vault, CFSSL-compatible, and generic PEM
provider checks, CA fetch, inventory, plan, drift, HTML reports, version output,
concurrent scan, expected-state verification, separate SNI/connect handling, a
Vault-issued HTTPS endpoint, and remote Linux trust apply/verify/remove.

## SSH Target

```bash
ssh -i docs/lab/.state/id_ed25519 -p 2222 ops@127.0.0.1
```

## Cleanup

```bash
bash docs/lab/cleanup.sh
```

## Notes

- The lab does not depend on production secrets.
- Fingerprints are pinned in `certops.lab.yaml`.
- The target container is disposable.
- Generated state is kept in `docs/lab/.state`.
