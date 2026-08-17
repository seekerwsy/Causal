#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/ubuntu/secaware-deployments/gate-c-model-scale-live-20260816-03"
readonly PYTHON_PREFIX="/home/ubuntu/secaware-python/cpython-3.12.13-system-20260816-01"
readonly PYTHON="${PYTHON_PREFIX}/bin/python3.12"
readonly COMPAT_DIR="/home/ubuntu/secaware-oracle-compat/cpython-3.12.13-semgrep-1.168.0-bandit-1.9.4-20260816-02"
readonly BIN_DIR="${COMPAT_DIR}/bin"
readonly RECORD_DIR="/home/ubuntu/secaware-experiments/readiness/gate-c-oracle-compat-20260816-02"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
for required in "${PYTHON}" "${PYTHON_PREFIX}/bin/semgrep" \
  "${PYTHON_PREFIX}/bin/bandit" /usr/bin/uname; do
  if [[ ! -x "${required}" ]]; then
    echo "fixed Oracle input is unavailable: ${required}" >&2
    exit 2
  fi
done
if [[ -e "${COMPAT_DIR}" || -e "${RECORD_DIR}" ]]; then
  echo "refusing to overwrite an existing compatibility environment" >&2
  exit 2
fi

mkdir -p "${BIN_DIR}" "${RECORD_DIR}"

# Preserve the exact pip-generated entry points. Reimplementing their argv[0]
# handling changes analyzer behavior after the runner seals a shebang script.
install -m 0755 "${PYTHON_PREFIX}/bin/semgrep" "${BIN_DIR}/semgrep"
install -m 0755 "${PYTHON_PREFIX}/bin/bandit" "${BIN_DIR}/bandit"
install -m 0755 /usr/bin/uname "${BIN_DIR}/uname"

PATH="${BIN_DIR}" "${BIN_DIR}/semgrep" --version \
  >"${RECORD_DIR}/semgrep-version.txt" 2>&1
PATH="${BIN_DIR}" "${BIN_DIR}/bandit" --version \
  >"${RECORD_DIR}/bandit-version.txt" 2>&1
PATH="${BIN_DIR}" "${BIN_DIR}/uname" -s \
  >"${RECORD_DIR}/uname-system.txt" 2>&1

"${PYTHON}" - "${RECORD_DIR}/environment.json" "${COMPAT_DIR}" <<'PY'
import json
import pathlib
import platform
import socket
import sys
from datetime import UTC, datetime

destination = pathlib.Path(sys.argv[1])
compat_dir = pathlib.Path(sys.argv[2])
payload = {
    "schema_version": "1.0",
    "status": "READY_FOR_BATCH_VALIDATION",
    "captured_at_utc": datetime.now(UTC).isoformat(),
    "hostname": socket.gethostname(),
    "platform": platform.platform(),
    "python": platform.python_version(),
    "python_executable": sys.executable,
    "compatibility_directory": str(compat_dir),
    "purpose": "co-locate exact locked analyzer entry points with their uname helper",
    "batch_validation_required": True,
    "required_consecutive_batch_passes": 2,
}
destination.write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

sha256sum \
  "${BIN_DIR}/semgrep" \
  "${BIN_DIR}/bandit" \
  "${BIN_DIR}/uname" \
  >"${RECORD_DIR}/compatibility-files.sha256"
sha256sum \
  "${PYTHON_PREFIX}/bin/semgrep" \
  "${PYTHON_PREFIX}/bin/bandit" \
  /usr/bin/uname \
  >"${RECORD_DIR}/source-files.sha256"
sha256sum \
  "${DEPLOY_DIR}/scripts/setup_gate_c_oracle_compat_v2.sh" \
  >"${RECORD_DIR}/setup-script.sha256"
printf '%s\n' "${COMPAT_DIR}" >"${RECORD_DIR}/compatibility-directory.txt"
printf '%s\n' READY_FOR_BATCH_VALIDATION >"${RECORD_DIR}/status.txt"

chmod -R a-w "${COMPAT_DIR}"

echo "READY_FOR_BATCH_VALIDATION ${COMPAT_DIR}"
