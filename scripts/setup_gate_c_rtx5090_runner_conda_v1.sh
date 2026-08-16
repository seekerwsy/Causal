#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/ubuntu/secaware-deployments/gate-c-model-scale-live-20260816-03"
readonly ENV_DIR="/home/ubuntu/secaware-envs/secaware-gate-c-conda-py312-20260816-03"
readonly RECORD_DIR="/home/ubuntu/secaware-experiments/readiness/gate-c-runner-conda-env-20260816-03"
readonly CONDA="/home/ubuntu/miniconda3/bin/conda"
readonly PYTHON_VERSION="3.12.12"
readonly PIP_VERSION="25.0.1"
readonly SETUPTOOLS_VERSION="83.0.0"
readonly WHEEL_VERSION="0.47.0"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${CONDA}" || ! -f "${DEPLOY_DIR}/pyproject.toml" ]]; then
  echo "fixed Conda executable or project metadata is unavailable" >&2
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
${CONDA} create --yes --prefix ${ENV_DIR} python=${PYTHON_VERSION} pip=${PIP_VERSION} setuptools=${SETUPTOOLS_VERSION} wheel=${WHEEL_VERSION}
${ENV_DIR}/bin/python -m pip install --editable .[api,oracle]
EOF

date --utc --iso-8601=seconds >"${RECORD_DIR}/started-at-utc.txt"
"${CONDA}" --version >"${RECORD_DIR}/conda-version.txt" 2>&1
"${CONDA}" info --json >"${RECORD_DIR}/conda-info.json" 2>"${RECORD_DIR}/conda-info.stderr.log"
df -h /home/ubuntu >"${RECORD_DIR}/disk-before.txt"
nvidia-smi --query-gpu=index,uuid,name,driver_version,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${RECORD_DIR}/gpu-before.csv"

"${CONDA}" create --yes --prefix "${ENV_DIR}" \
  "python=${PYTHON_VERSION}" \
  "pip=${PIP_VERSION}" \
  "setuptools=${SETUPTOOLS_VERSION}" \
  "wheel=${WHEEL_VERSION}" \
  >"${RECORD_DIR}/conda-create.stdout.log" \
  2>"${RECORD_DIR}/conda-create.stderr.log"

"${ENV_DIR}/bin/python" -c \
  "import os,sys; assert hasattr(os,'memfd_create'); assert hasattr(os,'pidfd_open'); print(sys.version); print('linux-isolation-primitives-ready')" \
  >"${RECORD_DIR}/isolation-primitives.txt" \
  2>"${RECORD_DIR}/isolation-primitives.stderr.log"
"${ENV_DIR}/bin/python" -m pip install --editable ".[api,oracle]" \
  >"${RECORD_DIR}/install.stdout.log" 2>"${RECORD_DIR}/install.stderr.log"

"${ENV_DIR}/bin/python" -c \
  "import bandit,causallearn,numpy,openai,pandas,pydantic,semgrep,secaware; print('imports-ready')" \
  >"${RECORD_DIR}/import-check.txt" 2>"${RECORD_DIR}/import-check.stderr.log"
"${ENV_DIR}/bin/semgrep" --version >"${RECORD_DIR}/semgrep-version.txt" 2>&1
"${ENV_DIR}/bin/bandit" --version >"${RECORD_DIR}/bandit-version.txt" 2>&1
"${CONDA}" list --prefix "${ENV_DIR}" --explicit >"${RECORD_DIR}/conda-explicit.txt"
"${CONDA}" env export --prefix "${ENV_DIR}" >"${RECORD_DIR}/conda-environment.yaml"
"${ENV_DIR}/bin/python" -m pip freeze --all >"${RECORD_DIR}/pip-freeze.txt"
df -h /home/ubuntu >"${RECORD_DIR}/disk-after.txt"
date --utc --iso-8601=seconds >"${RECORD_DIR}/completed-at-utc.txt"
