#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/wsy/secaware-deployments/server-smoke-20260812-01"
readonly ENV_DIR="/home/wsy/secaware-environments/server-smoke-py312-20260812-01"
readonly INPUT_DIR="/home/wsy/secaware-experiments/inputs/server-smoke-v1-20260812-02"
readonly EXECUTION_DIR="/home/wsy/secaware-experiments/executions/server-smoke-v1-20260812-02"
readonly RUN_DIR="/home/wsy/secaware-experiments/runs/server-smoke-v1-20260812-02"
readonly CONFIG="${INPUT_DIR}/ollama-qwen3-32b-bailian-v2.yaml"
readonly PYTHON="${ENV_DIR}/bin/python"
readonly CANARY_DIR="${EXECUTION_DIR}/bailian-canary"
readonly EVENTS="${EXECUTION_DIR}/events.jsonl"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" || ! -f "${CONFIG}" ]]; then
  echo "fixed Python environment or immutable input is unavailable" >&2
  exit 2
fi
if [[ -e "${EXECUTION_DIR}" || -e "${RUN_DIR}" ]]; then
  echo "refusing to overwrite an existing smoke execution" >&2
  exit 2
fi

mkdir -p "${EXECUTION_DIR}" "$(dirname "${RUN_DIR}")"

set -a
# shellcheck disable=SC1091
source "${DEPLOY_DIR}/.env"
set +a
: "${ALI_BAILIAN_API_KEY:?ALI_BAILIAN_API_KEY is unavailable}"
: "${OLLAMA_API_KEY:?OLLAMA_API_KEY is unavailable}"

record_event() {
  local event="$1"
  local status="$2"
  "${PYTHON}" - "${EVENTS}" "${event}" "${status}" <<'PY'
import datetime
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = {
    "at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "event": sys.argv[2],
    "status": sys.argv[3],
}
with path.open("a", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
PY
}

finalize() {
  local code="$?"
  set +e
  record_event "execution_finished" "${code}"
  "${PYTHON}" - "${EXECUTION_DIR}" "${RUN_DIR}" "${code}" <<'PY'
import json
import pathlib
import sys

execution_dir = pathlib.Path(sys.argv[1])
run_dir = pathlib.Path(sys.argv[2])
exit_code = int(sys.argv[3])

def count_lines(path: pathlib.Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())

payload = {
    "schema_version": "1.0",
    "status": "PASS" if exit_code == 0 else "ERROR",
    "exit_code": exit_code,
    "counts": {
        "observed_requests": count_lines(run_dir / "generation/observed_requests.jsonl"),
        "observed_attempts": count_lines(run_dir / "generation/observed_attempts.jsonl"),
        "observed_code": count_lines(run_dir / "generation/observed_code.jsonl"),
        "observed_oracle": count_lines(run_dir / "oracle/observed_oracle.jsonl"),
    },
    "bailian_canary_report_present": (execution_dir / "bailian-canary/report.json").is_file(),
}
(execution_dir / "summary.json").write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}
trap finalize EXIT

cat >"${EXECUTION_DIR}/commands.txt" <<EOF
${PYTHON} -m secaware preflight --config ${CONFIG}
${PYTHON} scripts/validate_bailian_functional_judge.py --output-dir ${CANARY_DIR}
${PYTHON} -m secaware generate-observed --config ${CONFIG}
${PYTHON} -m secaware run-oracle --config ${CONFIG} --condition observed
EOF

sha256sum "${CONFIG}" "${INPUT_DIR}/run_server_smoke_v2.sh" \
  >"${EXECUTION_DIR}/input-files.sha256"

"${PYTHON}" - "${EXECUTION_DIR}/environment.json" <<'PY'
import datetime
import importlib.metadata
import json
import os
import pathlib
import platform
import socket
import sys

payload = {
    "schema_version": "1.0",
    "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "hostname": socket.gethostname(),
    "working_directory": str(pathlib.Path.cwd().resolve()),
    "python_executable": sys.executable,
    "python_version": platform.python_version(),
    "platform": platform.platform(),
    "packages": {
        name: importlib.metadata.version(name)
        for name in ("secaware", "openai", "pydantic", "causal-learn")
    },
    "credentials": {
        "ALI_BAILIAN_API_KEY": {"present": bool(os.environ.get("ALI_BAILIAN_API_KEY")), "value_recorded": False},
        "OLLAMA_API_KEY": {"present": bool(os.environ.get("OLLAMA_API_KEY")), "value_recorded": False},
    },
    "base_deployment": "/home/wsy/secaware-deployments/server-smoke-20260812-01",
    "base_snapshot_sha256": "4825ec903110bb3d588f03873631b90395320bab1e040525675f3ab99f438ab9",
}
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu \
  --format=csv,noheader >"${EXECUTION_DIR}/gpu-before.csv"
curl --fail --silent --show-error --max-time 5 \
  http://127.0.0.1:11434/v1/models >"${EXECUTION_DIR}/ollama-models.json"

record_event "preflight" "started"
"${PYTHON}" -m secaware preflight --config "${CONFIG}" \
  >"${EXECUTION_DIR}/preflight.stdout.log" \
  2>"${EXECUTION_DIR}/preflight.stderr.log"
record_event "preflight" "passed"

record_event "bailian_canary" "started"
"${PYTHON}" scripts/validate_bailian_functional_judge.py --output-dir "${CANARY_DIR}" \
  >"${EXECUTION_DIR}/bailian-canary.stdout.log" \
  2>"${EXECUTION_DIR}/bailian-canary.stderr.log"
record_event "bailian_canary" "passed"

record_event "observed_generation" "started"
"${PYTHON}" -m secaware generate-observed --config "${CONFIG}" \
  >"${EXECUTION_DIR}/generate-observed.stdout.log" \
  2>"${EXECUTION_DIR}/generate-observed.stderr.log"
record_event "observed_generation" "passed"

record_event "observed_oracle" "started"
"${PYTHON}" -m secaware run-oracle --config "${CONFIG}" --condition observed \
  >"${EXECUTION_DIR}/observed-oracle.stdout.log" \
  2>"${EXECUTION_DIR}/observed-oracle.stderr.log"
record_event "observed_oracle" "passed"

nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu \
  --format=csv,noheader >"${EXECUTION_DIR}/gpu-after.csv"
