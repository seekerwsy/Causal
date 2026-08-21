#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/ubuntu/secaware-deployments/gate-c-model-scale-live-20260816-03"
readonly PYTHON_PREFIX="/home/ubuntu/secaware-python/cpython-3.12.13-system-20260816-01"
readonly PYTHON="${PYTHON_PREFIX}/bin/python3.12"
readonly COMPAT_DIR="/home/ubuntu/secaware-oracle-compat/cpython-3.12.13-semgrep-1.168.0-bandit-1.9.4-20260816-01"
readonly BIN_DIR="${COMPAT_DIR}/bin"
readonly RECORD_DIR="/home/ubuntu/secaware-experiments/readiness/gate-c-oracle-compat-20260816-01"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" || ! -x /usr/bin/uname ]]; then
  echo "fixed source Python or system uname is unavailable" >&2
  exit 2
fi
if [[ -e "${COMPAT_DIR}" || -e "${RECORD_DIR}" ]]; then
  echo "refusing to overwrite an existing compatibility environment" >&2
  exit 2
fi

mkdir -p "${BIN_DIR}" "${RECORD_DIR}"

cat >"${BIN_DIR}/semgrep" <<EOF
#!${PYTHON}
import sys

from semgrep.console_scripts.entrypoint import main


if __name__ == "__main__":
    sys.argv[0] = "semgrep"
    raise SystemExit(main())
EOF

cat >"${BIN_DIR}/bandit" <<EOF
#!${PYTHON}
import platform
import sys
from importlib.metadata import version

from bandit.cli.main import main


if __name__ == "__main__":
    if sys.argv[1:] == ["--version"]:
        print(f"bandit {version('bandit')}")
        print(
            f"  python version = {platform.python_version()} "
            f"({platform.python_implementation()}) [{platform.python_compiler()}]"
        )
        raise SystemExit(0)
    sys.argv[0] = "bandit"
    raise SystemExit(main())
EOF

install -m 0755 /usr/bin/uname "${BIN_DIR}/uname"
chmod 0755 "${BIN_DIR}/semgrep" "${BIN_DIR}/bandit"

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
    "status": "READY",
    "captured_at_utc": datetime.now(UTC).isoformat(),
    "hostname": socket.gethostname(),
    "platform": platform.platform(),
    "python": platform.python_version(),
    "python_executable": sys.executable,
    "compatibility_directory": str(compat_dir),
    "purpose": "keep locked analyzers and their required uname helper in one minimal PATH",
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
  "${DEPLOY_DIR}/scripts/setup_gate_c_oracle_compat_v1.sh" \
  >"${RECORD_DIR}/setup-script.sha256"
printf '%s\n' "${COMPAT_DIR}" >"${RECORD_DIR}/compatibility-directory.txt"
printf '%s\n' READY >"${RECORD_DIR}/status.txt"

chmod -R a-w "${COMPAT_DIR}"

echo "READY ${COMPAT_DIR}"
