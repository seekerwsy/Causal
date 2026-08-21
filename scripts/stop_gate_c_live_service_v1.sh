#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly SERVICE_DIR="/home/wsy/secaware-model-services/qwen25-coder-32b-gate-c-20260815-01"
readonly EXPECTED_PORT="18101"

if [[ ! -f "${SERVICE_DIR}/server.pid" || ! -f "${SERVICE_DIR}/launch-command.txt" ]]; then
  echo "model-service record is incomplete" >&2
  exit 2
fi
readonly PID="$(cat "${SERVICE_DIR}/server.pid")"
if [[ ! "${PID}" =~ ^[0-9]+$ ]]; then
  echo "model-service PID is invalid" >&2
  exit 2
fi
if ! kill -0 "${PID}" 2>/dev/null; then
  echo "model-service process is not alive" >&2
  exit 2
fi
readonly COMMAND="$(ps -p "${PID}" -o args=)"
if [[ "${COMMAND}" != *"sglang.launch_server"* \
  || "${COMMAND}" != *"--port ${EXPECTED_PORT}"* \
  || "${COMMAND}" != *"Qwen2.5-Coder-32B-Instruct"* ]]; then
  echo "refusing to stop an unrecognized process" >&2
  exit 2
fi

readonly SHUTDOWN_DIR="${SERVICE_DIR}/shutdown-$(date --utc +%Y%m%dT%H%M%SZ)"
mkdir -p "${SHUTDOWN_DIR}"
ps -p "${PID}" -o pid,ppid,user,lstart,args >"${SHUTDOWN_DIR}/process-before.txt"
nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${SHUTDOWN_DIR}/gpu-before.csv"
kill "${PID}"
for _attempt in $(seq 1 60); do
  if ! kill -0 "${PID}" 2>/dev/null; then
    break
  fi
  sleep 1
done
if kill -0 "${PID}" 2>/dev/null; then
  echo "model-service did not stop within deadline" >&2
  exit 3
fi
date --utc --iso-8601=seconds >"${SHUTDOWN_DIR}/stopped-at-utc.txt"
nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${SHUTDOWN_DIR}/gpu-after.csv"
printf '%s\n' "STOPPED" >"${SERVICE_DIR}/status.txt"
