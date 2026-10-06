#!/usr/bin/env bash
set -euo pipefail

# Wiz CLI v1 Local Scan Runner for NATS Custom Secret Detection Lab
# Usage: ./scripts/run-wiz-scan.sh [--help] [--no-publish]

POLICY_NAME="${WIZ_POLICY_NAME:-sr-nats-custom-secrets-policy}"
SCAN_NAME="${WIZ_SCAN_NAME:-nats-custom-secrets-cli-scan}"
PUBLISH_FLAG=""

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      echo "Usage: ./scripts/run-wiz-scan.sh [--no-publish]"
      echo ""
      echo "Options:"
      echo "  --no-publish   Run the Wiz CLI scan locally without publishing results to Wiz Platform"
      echo "  -h, --help     Show this help message"
      exit 0
      ;;
    --no-publish)
      PUBLISH_FLAG="--no-publish"
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Load credentials from local .env or workspace Wiz .env if not already in environment
if [[ -z "${WIZ_CLIENT_ID:-}" || -z "${WIZ_CLIENT_SECRET:-}" ]]; then
  if [[ -f "${REPO_ROOT}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.env"
    set +a
  elif [[ -f "${HOME}/projects/repos/iac-recipes/wiz/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${HOME}/projects/repos/iac-recipes/wiz/.env"
    set +a
  fi
fi

if [[ -z "${WIZ_CLIENT_ID:-}" || -z "${WIZ_CLIENT_SECRET:-}" ]]; then
  echo "ERROR: WIZ_CLIENT_ID and WIZ_CLIENT_SECRET must be set in environment or .env"
  exit 1
fi

WIZCLI_BIN="${REPO_ROOT}/bin/wizcli"
if [[ ! -x "${WIZCLI_BIN}" ]]; then
  echo "[*] Downloading Wiz CLI v1 to ${WIZCLI_BIN}..."
  mkdir -p "${REPO_ROOT}/bin"
  curl -sSL -o "${WIZCLI_BIN}" https://downloads.wiz.io/v1/wizcli/latest/wizcli-linux-amd64
  chmod +x "${WIZCLI_BIN}"
fi

mkdir -p "${REPO_ROOT}/reports"

echo "[*] Running Wiz CLI v1 Directory Scan with policy: ${POLICY_NAME}..."
set +e
"${WIZCLI_BIN}" scan dir "${REPO_ROOT}" \
  --name "${SCAN_NAME}" \
  --policies "${POLICY_NAME}" \
  --disabled-scanners Vulnerability,SensitiveData,Misconfiguration,SoftwareSupplyChain,AIModels,SAST,Malware \
  --json-output-file "${REPO_ROOT}/reports/wiz-scan.json" \
  --sarif-output-file "${REPO_ROOT}/reports/wiz-scan.sarif" \
  ${PUBLISH_FLAG}
SCAN_EXIT_CODE=$?
set -e

echo ""
echo "[*] Wiz CLI scan finished with exit code: ${SCAN_EXIT_CODE} (non-zero is expected when policy blocks detected secrets)"
exit 0
