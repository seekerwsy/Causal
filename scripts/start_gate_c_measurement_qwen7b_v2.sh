#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/ubuntu/secaware-deployments/oracle-v2-measurement-canary-20260818-06"
readonly ENV_FILE="${DEPLOY_DIR}/.env"
readonly ENV_DIR="/home/ubuntu/secaware-envs/gate-c-vllm-0.16.0-py310-20260816-01"
readonly VLLM="${ENV_DIR}/bin/vllm"
readonly MODEL_DIR="/home/ubuntu/model-zoo/Qwen2.5-Coder-7B-Instruct"
readonly SERVED_MODEL="qwen2.5-coder-7b-instruct"
readonly SERVICE_DIR="/home/ubuntu/secaware-model-services/qwen25-coder-7b-measurement-v2-20260818-01"
readonly GPU_INDEX="0"
readonly MIN_FREE_MIB="31500"
readonly MAX_UTILIZATION="10"
readonly PORT="18101"
readonly MAX_MODEL_LEN="4096"

if [[ "$#" -ne 0 || "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "measurement service invocation failed validation" >&2
  exit 2
fi
if [[ ! -x "${VLLM}" || ! -f "${MODEL_DIR}/config.json" || ! -f "${ENV_FILE}" ]]; then
  echo "fixed serving environment, model, or protected environment file is unavailable" >&2
  exit 2
fi
if [[ -e "${SERVICE_DIR}" ]]; then
  echo "refusing to overwrite an existing model-service record" >&2
  exit 2
fi
if ss -ltn | grep -qE ":${PORT}[[:space:]]"; then
  echo "frozen model-service port is already in use" >&2
  exit 2
fi

read -r gpu_free gpu_utilization < <(
  nvidia-smi --id="${GPU_INDEX}" \
    --query-gpu=memory.free,utilization.gpu \
    --format=csv,noheader,nounits \
    | tr -d ' ' | tr ',' ' '
)
if [[ ! "${gpu_free}" =~ ^[0-9]+$ || ! "${gpu_utilization}" =~ ^[0-9]+$ \
  || "${gpu_free}" -lt "${MIN_FREE_MIB}" \
  || "${gpu_utilization}" -gt "${MAX_UTILIZATION}" ]]; then
  echo "GPU readiness gate failed" >&2
  exit 6
fi

mkdir -p "${SERVICE_DIR}"
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a
: "${OLLAMA_API_KEY:?local model-service API key is unavailable}"

finish_failure() {
  local code="$?"
  set +e
  if [[ "${code}" -ne 0 ]]; then
    printf '%s\n' "ERROR" >"${SERVICE_DIR}/status.txt"
    printf '%s\n' "${code}" >"${SERVICE_DIR}/exit-code.txt"
    if [[ -f "${SERVICE_DIR}/server.pid" ]]; then
      kill "$(<"${SERVICE_DIR}/server.pid")" 2>/dev/null || true
    fi
  fi
}
trap finish_failure EXIT

cat >"${SERVICE_DIR}/launch-command.txt" <<EOF
CUDA_VISIBLE_DEVICES=${GPU_INDEX} ${VLLM} serve ${MODEL_DIR} \\
  --served-model-name ${SERVED_MODEL} --host 127.0.0.1 --port ${PORT} \\
  --api-key \${OLLAMA_API_KEY} --dtype bfloat16 --max-model-len ${MAX_MODEL_LEN} \\
  --gpu-memory-utilization 0.95 --max-num-seqs 1 --seed 20260818 --enforce-eager
EOF

date --utc --iso-8601=seconds >"${SERVICE_DIR}/started-at-utc.txt"
"${ENV_DIR}/bin/python" --version >"${SERVICE_DIR}/python-version.txt" 2>&1
"${ENV_DIR}/bin/python" -m pip freeze --all >"${SERVICE_DIR}/pip-freeze.txt"
nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${SERVICE_DIR}/gpu-before.csv"
find "${MODEL_DIR}" -maxdepth 1 -type f -printf '%f\t%s\t%T@\n' \
  | sort >"${SERVICE_DIR}/model-files.tsv"
sha256sum \
  "${MODEL_DIR}/config.json" \
  "${MODEL_DIR}/generation_config.json" \
  "${MODEL_DIR}/tokenizer_config.json" \
  "${MODEL_DIR}/model.safetensors.index.json" \
  >"${SERVICE_DIR}/model-metadata.sha256"

nohup env CUDA_VISIBLE_DEVICES="${GPU_INDEX}" \
  "${VLLM}" serve "${MODEL_DIR}" \
  --served-model-name "${SERVED_MODEL}" \
  --host 127.0.0.1 \
  --port "${PORT}" \
  --api-key "${OLLAMA_API_KEY}" \
  --dtype bfloat16 \
  --max-model-len "${MAX_MODEL_LEN}" \
  --gpu-memory-utilization 0.95 \
  --max-num-seqs 1 \
  --seed 20260818 \
  --enforce-eager \
  >"${SERVICE_DIR}/server.stdout.log" \
  2>"${SERVICE_DIR}/server.stderr.log" &
printf '%s\n' "$!" >"${SERVICE_DIR}/server.pid"

http_ready=false
for _attempt in $(seq 1 180); do
  if ! kill -0 "$(<"${SERVICE_DIR}/server.pid")" 2>/dev/null; then
    echo "model-service process exited during startup" >&2
    exit 3
  fi
  if curl -fsS --max-time 5 \
    -H "Authorization: Bearer ${OLLAMA_API_KEY}" \
    "http://127.0.0.1:${PORT}/v1/models" \
    >"${SERVICE_DIR}/models.json"; then
    http_ready=true
    break
  fi
  sleep 5
done
if [[ "${http_ready}" != "true" ]]; then
  echo "model-service HTTP readiness deadline exceeded" >&2
  exit 4
fi

printf '%s\n' "READY" >"${SERVICE_DIR}/status.txt"
date --utc --iso-8601=seconds >"${SERVICE_DIR}/ready-at-utc.txt"
nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${SERVICE_DIR}/gpu-ready.csv"
