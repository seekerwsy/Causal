#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/ubuntu/secaware-deployments/gate-c-model-scale-20260816-01"
readonly ENV_DIR="/home/ubuntu/secaware-envs/gate-c-vllm-0.16.0-py310-20260816-01"
readonly RECORD_DIR="/home/ubuntu/secaware-experiments/readiness/gate-c-vllm-env-20260816-01"
readonly PYTHON="/usr/bin/python3.10"
readonly UV="/home/ubuntu/.local/bin/uv"
readonly VLLM_VERSION="0.16.0"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" || ! -x "${UV}" ]]; then
  echo "fixed Python or uv executable is unavailable" >&2
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
${UV} venv --python ${PYTHON} --seed ${ENV_DIR}
${UV} pip install --python ${ENV_DIR}/bin/python vllm==${VLLM_VERSION}
EOF

date --utc --iso-8601=seconds >"${RECORD_DIR}/started-at-utc.txt"
"${PYTHON}" --version >"${RECORD_DIR}/host-python-version.txt" 2>&1
"${UV}" --version >"${RECORD_DIR}/uv-version.txt" 2>&1
df -h /home/ubuntu >"${RECORD_DIR}/disk-before.txt"
nvidia-smi --query-gpu=index,uuid,name,driver_version,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${RECORD_DIR}/gpu-before.csv"

"${UV}" venv --python "${PYTHON}" --seed "${ENV_DIR}" \
  >"${RECORD_DIR}/venv.stdout.log" 2>"${RECORD_DIR}/venv.stderr.log"
"${UV}" pip install --python "${ENV_DIR}/bin/python" "vllm==${VLLM_VERSION}" \
  >"${RECORD_DIR}/install.stdout.log" 2>"${RECORD_DIR}/install.stderr.log"

"${ENV_DIR}/bin/python" -c \
  "import idna,numpy,torch,transformers,vllm; print('idna',idna.__version__); print('numpy',numpy.__version__); print('torch',torch.__version__); print('transformers',transformers.__version__); print('vllm',vllm.__version__)" \
  >"${RECORD_DIR}/import-check.txt" 2>"${RECORD_DIR}/import-check.stderr.log"
"${ENV_DIR}/bin/python" -m pip freeze --all >"${RECORD_DIR}/pip-freeze.txt"
df -h /home/ubuntu >"${RECORD_DIR}/disk-after.txt"
date --utc --iso-8601=seconds >"${RECORD_DIR}/completed-at-utc.txt"
