#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly SERVICE_DIR="/home/wsy/secaware-model-services/qwen25-coder-32b-e2e-20260814-01"
readonly RECORD_DIR="${SERVICE_DIR}/shutdown-20260814-01"
readonly PID_FILE="${SERVICE_DIR}/server.pid"
readonly EXPECTED_MODEL="/home/ubuntu/RAID5/data/model_zoo/CodeLLMs/Qwen2.5-Coder-32B-Instruct"
readonly EXPECTED_PORT="18101"

if [[ ! -f "${PID_FILE}" || ! -f "${SERVICE_DIR}/status.txt" \
  || "$(cat "${SERVICE_DIR}/status.txt")" != "READY" ]]; then
  echo "frozen ready service record is unavailable" >&2
  exit 2
fi
if [[ -e "${RECORD_DIR}" ]]; then
  echo "refusing to overwrite an existing shutdown record" >&2
  exit 2
fi

readonly PID="$(cat "${PID_FILE}")"
if [[ ! "${PID}" =~ ^[1-9][0-9]*$ ]] || ! kill -0 "${PID}" 2>/dev/null; then
  echo "recorded model-service process is unavailable" >&2
  exit 2
fi
readonly COMMAND="$(ps -p "${PID}" -o args=)"
if [[ "${COMMAND}" != *"sglang.launch_server"* \
  || "${COMMAND}" != *"${EXPECTED_MODEL}"* \
  || "${COMMAND}" != *"--port ${EXPECTED_PORT}"* ]]; then
  echo "recorded process identity failed validation" >&2
  exit 2
fi
if ! ss -ltnp | grep -qE "127\.0\.0\.1:${EXPECTED_PORT}[[:space:]].*pid=${PID},"; then
  echo "recorded process does not own the frozen service port" >&2
  exit 2
fi

mkdir -p "${RECORD_DIR}"
printf '%s\n' "kill -TERM ${PID}" >"${RECORD_DIR}/commands.txt"
printf '%s\n' "${COMMAND}" >"${RECORD_DIR}/process-before.txt"
date --utc --iso-8601=seconds >"${RECORD_DIR}/started-at-utc.txt"
nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${RECORD_DIR}/gpu-before.csv"

kill -TERM "${PID}"
for _attempt in $(seq 1 30); do
  if ! kill -0 "${PID}" 2>/dev/null; then
    break
  fi
  sleep 1
done
if kill -0 "${PID}" 2>/dev/null; then
  printf '%s\n' "ERROR" >"${RECORD_DIR}/status.txt"
  echo "model-service process did not stop after SIGTERM" >&2
  exit 3
fi
if ss -ltn | grep -qE ":${EXPECTED_PORT}[[:space:]]"; then
  printf '%s\n' "ERROR" >"${RECORD_DIR}/status.txt"
  echo "model-service port remained occupied after shutdown" >&2
  exit 3
fi

nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${RECORD_DIR}/gpu-after.csv"
date --utc --iso-8601=seconds >"${RECORD_DIR}/finished-at-utc.txt"
printf '%s\n' "STOPPED" >"${RECORD_DIR}/status.txt"
