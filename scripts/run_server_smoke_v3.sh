#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/wsy/secaware-deployments/server-smoke-20260812-02"
readonly ENV_DIR="/home/wsy/secaware-environments/server-smoke-py312-20260812-02"
readonly INPUT_DIR="/home/wsy/secaware-experiments/inputs/server-smoke-v1-20260812-07-final"
readonly COMPAT_BIN="${INPUT_DIR}/bin"
readonly EXECUTION_DIR="/home/wsy/secaware-experiments/executions/server-smoke-v1-20260812-03"
readonly RUN_DIR="/home/wsy/secaware-experiments/runs/server-smoke-v1-20260812-03"
readonly CONFIG="configs/server-smoke/ollama-qwen3-32b-bailian-v2.yaml"
readonly PYTHON="${ENV_DIR}/bin/python"
readonly CANARY_DIR="${EXECUTION_DIR}/bailian-canary"
readonly EVENTS="${EXECUTION_DIR}/events.jsonl"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" || ! -f "${CONFIG}" ]]; then
  echo "fixed Python environment or config is unavailable" >&2
  exit 2
fi
for required in semgrep bandit uname; do
  if [[ ! -x "${COMPAT_BIN}/${required}" ]]; then
    echo "frozen Oracle compatibility input is unavailable" >&2
    exit 2
  fi
done
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
  "${PYTHON}" - "${EXECUTION_DIR}/summary.json" "${RUN_DIR}" "${code}" <<'PY'
import ast
from collections import Counter
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
run_dir = pathlib.Path(sys.argv[2])
exit_code = int(sys.argv[3])

def rows(path: pathlib.Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

codes = rows(run_dir / "generation/observed_code.jsonl")
oracle = rows(run_dir / "oracle/observed_oracle.jsonl")

def syntax_ok(code: object) -> bool:
    if not isinstance(code, str):
        return False
    try:
        ast.parse(code)
    except (SyntaxError, ValueError, TypeError):
        return False
    return True

security_labels = Counter(str(item.get("security_label")) for item in oracle)
payload = {
    "schema_version": "1.0",
    "status": "PASS" if exit_code == 0 else "ERROR",
    "exit_code": exit_code,
    "counts": {
        "observed_requests": len(rows(run_dir / "generation/observed_requests.jsonl")),
        "observed_attempts": len(rows(run_dir / "generation/observed_attempts.jsonl")),
        "observed_code": len(codes),
        "observed_oracle": len(oracle),
    },
    "code_diagnostics": {
        "syntax_ok": sum(1 for item in codes if syntax_ok(item.get("code"))),
        "starts_with_markdown_fence": sum(
            1 for item in codes if str(item.get("code", "")).startswith("```")
        ),
    },
    "security_labels": dict(sorted(security_labels.items())),
    "bailian_canary_report_present": (summary_path.parent / "bailian-canary/report.json").is_file(),
}
summary_path.write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}
trap finalize EXIT

/usr/bin/cat >"${EXECUTION_DIR}/commands.txt" <<EOF
${PYTHON} -m secaware preflight --config ${CONFIG} --run-dir ${RUN_DIR}
${PYTHON} scripts/validate_bailian_functional_judge.py --output-dir ${CANARY_DIR}
${PYTHON} -m secaware generate-observed --config ${CONFIG} --run-dir ${RUN_DIR}
PATH=${COMPAT_BIN} ${PYTHON} -m pytest -q tests/test_oracle_real_tools.py
PATH=${COMPAT_BIN} ${PYTHON} -m secaware run-oracle --config ${CONFIG} --run-dir ${RUN_DIR} --condition observed
EOF

/usr/bin/sha256sum \
  "${CONFIG}" \
  "${INPUT_DIR}/run_server_smoke_v3.sh" \
  "${COMPAT_BIN}/semgrep" \
  "${COMPAT_BIN}/bandit" \
  "${COMPAT_BIN}/uname" \
  >"${EXECUTION_DIR}/input-files.sha256"

nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu \
  --format=csv,noheader >"${EXECUTION_DIR}/gpu-before.csv"

record_event "preflight" "started"
"${PYTHON}" -m secaware preflight --config "${CONFIG}" --run-dir "${RUN_DIR}" \
  >"${EXECUTION_DIR}/preflight.stdout.log" \
  2>"${EXECUTION_DIR}/preflight.stderr.log"
record_event "preflight" "passed"

record_event "bailian_canary" "started"
"${PYTHON}" scripts/validate_bailian_functional_judge.py --output-dir "${CANARY_DIR}" \
  >"${EXECUTION_DIR}/bailian-canary.stdout.log" \
  2>"${EXECUTION_DIR}/bailian-canary.stderr.log"
record_event "bailian_canary" "passed"

record_event "observed_generation" "started"
"${PYTHON}" -m secaware generate-observed --config "${CONFIG}" --run-dir "${RUN_DIR}" \
  >"${EXECUTION_DIR}/generate-observed.stdout.log" \
  2>"${EXECUTION_DIR}/generate-observed.stderr.log"
record_event "observed_generation" "passed"

record_event "oracle_real_tools_gate" "started"
PATH="${COMPAT_BIN}" "${PYTHON}" -m pytest -q tests/test_oracle_real_tools.py \
  >"${EXECUTION_DIR}/oracle-real-tools.stdout.log" \
  2>"${EXECUTION_DIR}/oracle-real-tools.stderr.log"
record_event "oracle_real_tools_gate" "passed"

record_event "observed_oracle" "started"
PATH="${COMPAT_BIN}" "${PYTHON}" -m secaware run-oracle \
  --config "${CONFIG}" --run-dir "${RUN_DIR}" --condition observed \
  >"${EXECUTION_DIR}/observed-oracle.stdout.log" \
  2>"${EXECUTION_DIR}/observed-oracle.stderr.log"
record_event "observed_oracle" "passed"

nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu \
  --format=csv,noheader >"${EXECUTION_DIR}/gpu-after.csv"
