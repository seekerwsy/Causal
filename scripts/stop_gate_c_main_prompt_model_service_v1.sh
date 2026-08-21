#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly DEPLOY_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

if [[ "$#" -ne 1 || "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "main-Prompt model-service stop invocation failed validation" >&2
  exit 2
fi

case "$1" in
  qwen25-coder-7b)
    readonly SERVICE_DIR="/home/ubuntu/secaware-model-services/qwen25-coder-7b-main-prompt-v1-20260818-01"
    ;;
  phi4-14b)
    readonly SERVICE_DIR="/home/ubuntu/secaware-model-services/phi4-14b-main-prompt-v1-20260818-01"
    ;;
  qwen25-coder-7b-randomized-main)
    readonly SERVICE_DIR="/home/ubuntu/secaware-model-services/qwen25-coder-7b-randomized-discovery-main-v1-20260818-01"
    ;;
  phi4-14b-randomized-main)
    readonly SERVICE_DIR="/home/ubuntu/secaware-model-services/phi4-14b-randomized-discovery-main-v1-20260818-01"
    ;;
  *)
    echo "unregistered main-Prompt model service" >&2
    exit 2
    ;;
esac

if [[ ! -f "${SERVICE_DIR}/server.pid" || ! -f "${SERVICE_DIR}/status.txt" ]]; then
  echo "model-service record is unavailable" >&2
  exit 2
fi
if [[ "$(<"${SERVICE_DIR}/status.txt")" != "READY" ]]; then
  echo "model-service is not in the READY state" >&2
  exit 2
fi

readonly pid="$(<"${SERVICE_DIR}/server.pid")"
if kill -0 "${pid}" 2>/dev/null; then
  kill "${pid}"
  for _attempt in $(seq 1 60); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 1
  done
fi
if kill -0 "${pid}" 2>/dev/null; then
  echo "model-service did not stop before the deadline" >&2
  exit 3
fi

printf '%s\n' "STOPPED" >"${SERVICE_DIR}/status.txt"
date --utc --iso-8601=seconds >"${SERVICE_DIR}/stopped-at-utc.txt"
nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv,noheader >"${SERVICE_DIR}/gpu-after.csv"
