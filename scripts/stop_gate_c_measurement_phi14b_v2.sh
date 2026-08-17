#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly DEPLOY_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly SERVICE_DIR="/home/ubuntu/secaware-model-services/phi4-14b-measurement-v2-20260818-01"

if [[ "$#" -ne 0 || "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "measurement service stop invocation failed validation" >&2
  exit 2
fi
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
