#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/ubuntu/secaware-deployments/gate-c-model-scale-live-20260816-03"
readonly ENV_DIR="/home/ubuntu/secaware-envs/secaware-gate-c-py312-20260816-02"
readonly RECORD_DIR="/home/ubuntu/secaware-experiments/readiness/gate-c-runner-env-20260816-02"
readonly UV="/home/ubuntu/.local/bin/uv"
readonly PYTHON_VERSION="3.12.12"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${UV}" || ! -f "${DEPLOY_DIR}/pyproject.toml" ]]; then
  echo "fixed uv executable or project metadata is unavailable" >&2
  exit 2
fi
if [[ -e "${ENV_DIR}" || -e "${RECORD_DIR}" ]]; then
  echo "refusing to overwrite an existing environment or readiness record" >&2
  exit 2
fi

mkdir -p "${RECORD_DIR}"

finish() {
  local code="$?"
  if [[ "${code}" -eq 0 ]]; then
    printf '%s\n' "READY" >"${RECORD_DIR}/status.txt"
  else
    printf '%s\n' "ERROR" >"${RECORD_DIR}/status.txt"
    printf '%s\n' "${code}" >"${RECORD_DIR}/exit-code.txt"
  fi
}
trap finish EXIT

cat >"${RECORD_DIR}/install-command.txt" <<EOF
${UV} python install ${PYTHON_VERSION}
${UV} venv --python ${PYTHON_VERSION} --seed ${ENV_DIR}
${UV} pip install --python ${ENV_DIR}/bin/python --editable .[api,oracle]
EOF

date --utc --iso-8601=seconds >"${RECORD_DIR}/started-at-utc.txt"
"${UV}" --version >"${RECORD_DIR}/uv-version.txt" 2>&1
df -h /home/ubuntu >"${RECORD_DIR}/disk-before.txt"
nvidia-smi --query-gpu=index,uuid,name,driver_version,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${RECORD_DIR}/gpu-before.csv"

"${UV}" python install "${PYTHON_VERSION}" \
  >"${RECORD_DIR}/python-install.stdout.log" \
  2>"${RECORD_DIR}/python-install.stderr.log"
"${UV}" venv --python "${PYTHON_VERSION}" --seed "${ENV_DIR}" \
  >"${RECORD_DIR}/venv.stdout.log" 2>"${RECORD_DIR}/venv.stderr.log"
"${UV}" pip install --python "${ENV_DIR}/bin/python" --editable ".[api,oracle]" \
  >"${RECORD_DIR}/install.stdout.log" 2>"${RECORD_DIR}/install.stderr.log"

"${ENV_DIR}/bin/python" --version >"${RECORD_DIR}/python-version.txt" 2>&1
"${ENV_DIR}/bin/python" -c \
  "import bandit,causallearn,numpy,openai,pandas,pydantic,semgrep,secaware; print('imports-ready')" \
  >"${RECORD_DIR}/import-check.txt" 2>"${RECORD_DIR}/import-check.stderr.log"
"${ENV_DIR}/bin/semgrep" --version >"${RECORD_DIR}/semgrep-version.txt" 2>&1
"${ENV_DIR}/bin/bandit" --version >"${RECORD_DIR}/bandit-version.txt" 2>&1
"${ENV_DIR}/bin/python" -m pip freeze --all >"${RECORD_DIR}/pip-freeze.txt"
df -h /home/ubuntu >"${RECORD_DIR}/disk-after.txt"
date --utc --iso-8601=seconds >"${RECORD_DIR}/completed-at-utc.txt"
