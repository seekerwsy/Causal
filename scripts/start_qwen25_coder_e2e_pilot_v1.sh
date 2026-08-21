#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/wsy/secaware-deployments/e2e-pilot-20260814-03"
readonly ENV_FILE="${DEPLOY_DIR}/.env"
readonly SGLANG_ENV="/home/wsy/miniconda3/envs/sgl"
readonly PYTHON="${SGLANG_ENV}/bin/python"
readonly CUDA_HOME="/usr/local/cuda-12.8"
readonly MODEL_DIR="/home/ubuntu/RAID5/data/model_zoo/CodeLLMs/Qwen2.5-Coder-32B-Instruct"
readonly SERVED_MODEL="qwen2.5-coder-32b-instruct"
readonly SERVICE_DIR="/home/wsy/secaware-model-services/qwen25-coder-32b-e2e-20260814-01"
readonly PORT="18101"

if [[ ! -x "${PYTHON}" || ! -x "${CUDA_HOME}/bin/nvcc" \
  || ! -f "${MODEL_DIR}/config.json" || ! -f "${ENV_FILE}" ]]; then
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
    if [[ -f "${SERVICE_DIR}/server.pid" ]]; then
      kill "$(cat "${SERVICE_DIR}/server.pid")" 2>/dev/null || true
    fi
  fi
}
trap finish_failure EXIT

cat >"${SERVICE_DIR}/launch-command.txt" <<EOF
CUDA_HOME=${CUDA_HOME} PATH=${CUDA_HOME}/bin:${SGLANG_ENV}/bin:\${PATH} \\
  CUDA_VISIBLE_DEVICES=1 ${PYTHON} -m sglang.launch_server \\
  --model-path ${MODEL_DIR} --served-model-name ${SERVED_MODEL} \\
  --host 127.0.0.1 --port ${PORT} --context-length 8192 \\
  --mem-fraction-static 0.88 --random-seed 20260814 --disable-cuda-graph
EOF

"${PYTHON}" --version >"${SERVICE_DIR}/python-version.txt" 2>&1
"${CUDA_HOME}/bin/nvcc" --version >"${SERVICE_DIR}/nvcc-version.txt" 2>&1
"${PYTHON}" -m pip freeze --all >"${SERVICE_DIR}/pip-freeze.txt"
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

nohup env CUDA_HOME="${CUDA_HOME}" PATH="${CUDA_HOME}/bin:${SGLANG_ENV}/bin:${PATH}" \
  CUDA_VISIBLE_DEVICES=1 \
  "${PYTHON}" -m sglang.launch_server \
  --model-path "${MODEL_DIR}" \
  --served-model-name "${SERVED_MODEL}" \
  --host 127.0.0.1 \
  --port "${PORT}" \
  --context-length 8192 \
  --mem-fraction-static 0.88 \
  --random-seed 20260814 \
  --disable-cuda-graph \
  >"${SERVICE_DIR}/server.stdout.log" \
  2>"${SERVICE_DIR}/server.stderr.log" &
printf '%s\n' "$!" >"${SERVICE_DIR}/server.pid"

http_ready=false
for _attempt in $(seq 1 180); do
  if ! kill -0 "$(cat "${SERVICE_DIR}/server.pid")" 2>/dev/null; then
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

curl -fsS --max-time 180 \
  -H "Authorization: Bearer ${OLLAMA_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{"model":"qwen2.5-coder-32b-instruct","messages":[{"role":"user","content":"Return only the Python expression 1 + 1."}],"temperature":0.0,"max_tokens":32,"seed":20260814}' \
  "http://127.0.0.1:${PORT}/v1/chat/completions" \
  >"${SERVICE_DIR}/warmup-response.json.tmp"

"${PYTHON}" - "${SERVICE_DIR}/warmup-response.json.tmp" \
  "${SERVICE_DIR}/warmup-response.json" <<'PY'
import json
import os
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
payload = json.loads(source.read_text(encoding="utf-8"))
choices = payload.get("choices")
if not isinstance(choices, list) or len(choices) != 1:
    raise SystemExit("warmup response choices failed validation")
message = choices[0].get("message")
content = message.get("content") if isinstance(message, dict) else None
if not isinstance(content, str) or not content.strip():
    raise SystemExit("warmup response content failed validation")
os.replace(source, target)
PY

sleep 2
if ! kill -0 "$(cat "${SERVICE_DIR}/server.pid")" 2>/dev/null; then
  echo "model-service process exited after warmup" >&2
  exit 5
fi
printf '%s\n' "READY" >"${SERVICE_DIR}/status.txt"
date --utc --iso-8601=seconds >"${SERVICE_DIR}/ready-at-utc.txt"
nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${SERVICE_DIR}/gpu-ready.csv"
