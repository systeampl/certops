#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../.." && pwd)"
CONFIG="$LAB_DIR/certops.lab.yaml"
ROOTS_DIR="/tmp/certops-lab-smoke-roots"

cd "$REPO_DIR"

certops version >/dev/null
certops version --json >/dev/null

smallstep_fp="$(grep -A4 'name: lab-smallstep' "$CONFIG" | awk '/fingerprint:/ {print $2}')"
vault_fp="$(grep -A5 'name: lab-vault' "$CONFIG" | awk '/fingerprint:/ {print $2}')"
cfssl_fp="$(grep -A4 'name: lab-cfssl' "$CONFIG" | awk '/fingerprint:/ {print $2}')"
generic_fp="$(grep -A4 'name: lab-generic-url' "$CONFIG" | awk '/fingerprint:/ {print $2}')"
generic_bundle="$(awk '/name: lab-generic-file/{found=1} found && /ca_bundle:/ {print $2; exit}' "$CONFIG")"

certops ca list -f "$CONFIG" >/dev/null
certops ca list -f "$CONFIG" --json >/dev/null
certops ca list -f "$CONFIG" --yaml >/dev/null

certops ca smallstep health --url https://127.0.0.1:9000 --insecure >/dev/null
certops ca smallstep roots --url https://127.0.0.1:9000 --fingerprint "$smallstep_fp" --insecure --out /tmp/certops-smoke-smallstep.pem >/dev/null
certops ca smallstep info --url https://127.0.0.1:9000 --fingerprint "$smallstep_fp" --insecure >/dev/null
certops ca smallstep info --url https://127.0.0.1:9000 --fingerprint "$smallstep_fp" --insecure --json >/dev/null
certops ca smallstep info --url https://127.0.0.1:9000 --fingerprint "$smallstep_fp" --insecure --yaml >/dev/null
certops ca smallstep info --url https://127.0.0.1:9000 --fingerprint "$smallstep_fp" --insecure --prom >/dev/null

certops ca vault health --url http://127.0.0.1:8200 >/dev/null
certops ca vault ca --url http://127.0.0.1:8200 --mount pki --fingerprint "$vault_fp" --out /tmp/certops-smoke-vault.pem >/dev/null
certops ca vault info --url http://127.0.0.1:8200 --mount pki --fingerprint "$vault_fp" >/dev/null
certops ca vault info --url http://127.0.0.1:8200 --mount pki --fingerprint "$vault_fp" --json >/dev/null
certops ca vault info --url http://127.0.0.1:8200 --mount pki --fingerprint "$vault_fp" --yaml >/dev/null
certops ca vault info --url http://127.0.0.1:8200 --mount pki --fingerprint "$vault_fp" --prom >/dev/null

certops ca cfssl health --url http://127.0.0.1:8888 >/dev/null
certops ca cfssl info --url http://127.0.0.1:8888 --fingerprint "$cfssl_fp" --out /tmp/certops-smoke-cfssl.pem >/dev/null
certops ca cfssl info --url http://127.0.0.1:8888 --fingerprint "$cfssl_fp" --json >/dev/null
certops ca cfssl info --url http://127.0.0.1:8888 --fingerprint "$cfssl_fp" --yaml >/dev/null
certops ca cfssl info --url http://127.0.0.1:8888 --fingerprint "$cfssl_fp" --prom >/dev/null

certops ca generic info --ca-bundle "$generic_bundle" --fingerprint "$generic_fp" --out /tmp/certops-smoke-generic-file.pem >/dev/null
certops ca generic info --ca-bundle "$generic_bundle" --fingerprint "$generic_fp" --json >/dev/null
certops ca generic info --ca-bundle "$generic_bundle" --fingerprint "$generic_fp" --yaml >/dev/null
certops ca generic info --ca-bundle "$generic_bundle" --fingerprint "$generic_fp" --prom >/dev/null
certops ca generic info --url http://127.0.0.1:8088/generic-root.pem --fingerprint "$generic_fp" --out /tmp/certops-smoke-generic-url.pem >/dev/null
certops ca generic info --url http://127.0.0.1:8088/generic-root.pem --fingerprint "$generic_fp" --json >/dev/null
certops ca generic info --url http://127.0.0.1:8088/generic-root.pem --fingerprint "$generic_fp" --yaml >/dev/null
certops ca generic info --url http://127.0.0.1:8088/generic-root.pem --fingerprint "$generic_fp" --prom >/dev/null

certops ca fetch -f "$CONFIG" --out "$ROOTS_DIR" >/dev/null
test -s "$ROOTS_DIR/lab-smallstep.pem"
test -s "$ROOTS_DIR/lab-vault.pem"
test -s "$ROOTS_DIR/lab-cfssl.pem"
test -s "$ROOTS_DIR/lab-generic-file.pem"
test -s "$ROOTS_DIR/lab-generic-url.pem"
certops inventory list -f "$CONFIG" >/dev/null
certops inventory show target-linux -f "$CONFIG" >/dev/null
certops inventory show lab -f "$CONFIG" --json >/dev/null

certops plan -f "$CONFIG" >/dev/null
certops plan -f "$CONFIG" --live >/dev/null
certops plan -f "$CONFIG" --live --json >/dev/null
certops plan -f "$CONFIG" --live --yaml >/dev/null
certops plan -f "$CONFIG" --live --html /tmp/certops-smoke-plan.html >/dev/null
certops drift -f "$CONFIG" --no-live >/dev/null
certops drift -f "$CONFIG" --no-live --json >/dev/null
certops drift -f "$CONFIG" --no-live --yaml >/dev/null
certops drift -f "$CONFIG" --no-live --html /tmp/certops-smoke-drift.html >/dev/null

certops trust plan --ca-bundle "$ROOTS_DIR/lab-smallstep.pem" >/dev/null
certops trust verify --ca-bundle "$ROOTS_DIR/lab-smallstep.pem" >/dev/null || true
if certops check https://127.0.0.1:9000 --ca-bundle "$ROOTS_DIR/lab-smallstep.pem" --json >/dev/null; then
  printf 'expected step-ca service check to report certificate findings\n' >&2
  exit 1
fi
certops check https://127.0.0.1:9443 --ca-bundle "$ROOTS_DIR/lab-vault.pem" --critical-days -1 --warn-days -1 >/dev/null
certops check https://127.0.0.1:9443 --ca-bundle "$ROOTS_DIR/lab-vault.pem" --critical-days -1 --warn-days -1 --json >/dev/null
certops check https://127.0.0.1:9443 --ca-bundle "$ROOTS_DIR/lab-vault.pem" --critical-days -1 --warn-days -1 --yaml >/dev/null
certops check https://127.0.0.1:9443 --ca-bundle "$ROOTS_DIR/lab-vault.pem" --critical-days -1 --warn-days -1 --prom >/dev/null
certops check https://127.0.0.1:9443 --ca-bundle "$ROOTS_DIR/lab-vault.pem" --critical-days -1 --warn-days -1 --html /tmp/certops-smoke-check.html >/dev/null
certops check localhost --server-name localhost --connect 127.0.0.1:9443 --ca-bundle "$ROOTS_DIR/lab-vault.pem" --critical-days -1 --warn-days -1 >/dev/null
certops scan 127.0.0.1:9443 --concurrency 2 --ca-bundle "$ROOTS_DIR/lab-vault.pem" --critical-days -1 --warn-days -1 --json >/dev/null

printf 'defaults:\n  warn_days: -1\n  critical_days: -1\n  ca_bundle: %s\ntargets:\n  - name: vault-lab\n    host: localhost\n    connect: 127.0.0.1:9443\n' "$ROOTS_DIR/lab-vault.pem" > /tmp/certops-smoke-verify.yaml
certops verify -f /tmp/certops-smoke-verify.yaml --json >/dev/null

certops fleet trust plan -f "$CONFIG" --limit target-linux >/dev/null
certops fleet trust plan -f "$CONFIG" --limit target-linux --html /tmp/certops-smoke-fleet-plan.html >/dev/null
certops fleet trust apply -f "$CONFIG" --limit target-linux --yes >/dev/null
certops fleet trust apply -f "$CONFIG" --limit target-linux --yes --html /tmp/certops-smoke-fleet-apply.html >/dev/null
certops fleet trust verify -f "$CONFIG" --limit target-linux >/dev/null
certops fleet trust verify -f "$CONFIG" --limit target-linux --json >/dev/null
certops fleet trust verify -f "$CONFIG" --limit target-linux --yaml >/dev/null
certops fleet trust verify -f "$CONFIG" --limit target-linux --html /tmp/certops-smoke-fleet-verify.html >/dev/null
certops fleet trust remove -f "$CONFIG" --limit target-linux --yes >/dev/null
if certops fleet trust verify -f "$CONFIG" --limit target-linux >/dev/null; then
  printf 'expected fleet trust verify to fail after remove\n' >&2
  exit 1
fi
certops fleet trust apply -f "$CONFIG" --limit target-linux --yes >/dev/null
certops fleet trust verify -f "$CONFIG" --limit target-linux >/dev/null

printf 'certops lab smoke: ok\n'
