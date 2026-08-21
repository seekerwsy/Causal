#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/wsy/secaware-deployments/server-smoke-20260812-02"
readonly SOURCE_ENV="/home/wsy/secaware-environments/server-smoke-py312-20260812-01"
readonly ENV_DIR="/home/wsy/secaware-environments/server-smoke-py312-20260812-02"
readonly RECORD_DIR="${DEPLOY_DIR}/.deployment/environment-setup-20260812-02"
readonly CONDA="/home/wsy/miniconda3/bin/conda"
readonly PYTHON="${ENV_DIR}/bin/python"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${CONDA}" || ! -x "${SOURCE_ENV}/bin/python" ]]; then
  echo "fixed conda or source environment is unavailable" >&2
  exit 2
fi
if [[ -e "${ENV_DIR}" || -e "${RECORD_DIR}" ]]; then
  echo "refusing to overwrite an existing environment or setup record" >&2
  exit 2
fi

mkdir -p "${RECORD_DIR}" "$(dirname "${ENV_DIR}")"

finalize() {
  local code="$?"
  set +e
  if [[ -x "${PYTHON}" ]]; then
    "${PYTHON}" - "${RECORD_DIR}/summary.json" "${code}" <<'PY'
import datetime
import json
import pathlib
import platform
import sys

payload = {
    "schema_version": "1.0",
    "status": "PASS" if int(sys.argv[2]) == 0 else "ERROR",
    "exit_code": int(sys.argv[2]),
    "completed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "python_executable": sys.executable,
    "python_version": platform.python_version(),
}
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
  fi
}
trap finalize EXIT

/usr/bin/cat >"${RECORD_DIR}/commands.txt" <<EOF
${CONDA} create --yes --clone ${SOURCE_ENV} --prefix ${ENV_DIR}
${PYTHON} -m pip install --report ${RECORD_DIR}/pip-install-report.json --editable .[api,dev,oracle]
${PYTHON} -m pytest -q tests/test_openai_compatible_provider.py tests/test_observed_generation_pipeline.py tests/test_bailian_functional_judge_canary.py
EOF

"${CONDA}" create --yes --clone "${SOURCE_ENV}" --prefix "${ENV_DIR}" \
  >"${RECORD_DIR}/conda-clone.stdout.log" \
  2>"${RECORD_DIR}/conda-clone.stderr.log"

"${PYTHON}" -m pip install \
  --report "${RECORD_DIR}/pip-install-report.json" \
  --editable ".[api,dev,oracle]" \
  >"${RECORD_DIR}/pip-install.stdout.log" \
  2>"${RECORD_DIR}/pip-install.stderr.log"

"${PYTHON}" -m pip freeze --all >"${RECORD_DIR}/pip-freeze.txt"
"${PYTHON}" --version >"${RECORD_DIR}/python-version.txt" 2>&1
"${PYTHON}" -m pytest -q \
  tests/test_openai_compatible_provider.py \
  tests/test_observed_generation_pipeline.py \
  tests/test_bailian_functional_judge_canary.py \
  >"${RECORD_DIR}/pytest.stdout.log" \
  2>"${RECORD_DIR}/pytest.stderr.log"
