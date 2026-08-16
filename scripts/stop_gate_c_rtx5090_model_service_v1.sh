#!/usr/bin/env bash
set -euo pipefail

umask 077

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 {qwen25-coder-7b|phi4-14b}" >&2
  exit 2
fi
case "$1" in
  qwen25-coder-7b)
    readonly SERVICE_DIR="/home/ubuntu/secaware-model-services/qwen25-coder-7b-gate-c-20260816-01"
    readonly EXPECTED_MODEL="Qwen2.5-Coder-7B-Instruct"
    ;;
  phi4-14b)
    readonly SERVICE_DIR="/home/ubuntu/secaware-model-services/phi4-14b-gate-c-20260816-01"
    readonly EXPECTED_MODEL="phi4-14b"
    ;;
  *)
    echo "unregistered model profile" >&2
    exit 2
    ;;
esac

if [[ ! -f "${SERVICE_DIR}/server.pid" ]]; then
  echo "registered server PID is unavailable" >&2
  exit 2
fi
readonly PID="$(cat "${SERVICE_DIR}/server.pid")"
if [[ ! "${PID}" =~ ^[0-9]+$ ]]; then
  echo "registered server PID is invalid" >&2
  exit 2
fi
if ! kill -0 "${PID}" 2>/dev/null; then
  printf '%s\n' "ALREADY_STOPPED" >"${SERVICE_DIR}/stop-status.txt"
  exit 0
fi
readonly COMMAND="$(tr '\0' ' ' <"/proc/${PID}/cmdline")"
if [[ "${COMMAND}" != *"vllm"* || "${COMMAND}" != *"${EXPECTED_MODEL}"* ]]; then
  echo "refusing to stop an unverified process" >&2
  exit 2
fi

kill "${PID}"
for _attempt in $(seq 1 60); do
  if ! kill -0 "${PID}" 2>/dev/null; then
    printf '%s\n' "STOPPED" >"${SERVICE_DIR}/stop-status.txt"
    date --utc --iso-8601=seconds >"${SERVICE_DIR}/stopped-at-utc.txt"
    exit 0
  fi
  sleep 1
done
echo "registered service did not stop before deadline" >&2
exit 3
