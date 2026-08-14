#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/wsy/secaware-deployments/e2e-pilot-20260814-03"
readonly ENV_DIR="/home/wsy/secaware-environments/server-smoke-py312-20260812-02"
readonly PYTHON="${ENV_DIR}/bin/python"
readonly COMPAT_BIN="/home/wsy/secaware-experiments/inputs/server-smoke-v1-20260812-07-final/bin"
readonly SERVICE_DIR="/home/wsy/secaware-model-services/qwen25-coder-32b-e2e-20260814-01"
readonly CONFIG="${DEPLOY_DIR}/configs/e2e-pilot/server-qwen25-coder-32b-observed-v1.yaml"
readonly RUN_DIR="/home/wsy/secaware-experiments/runs/e2e-pilot-qwen25-observed-v1-20260814-01"
readonly EXECUTION_DIR="/home/wsy/secaware-experiments/executions/e2e-pilot-qwen25-observed-v1-20260814-01"
readonly EVENTS="${EXECUTION_DIR}/events.jsonl"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" || ! -f "${CONFIG}" || ! -f "${DEPLOY_DIR}/.env" ]]; then
  echo "fixed Python environment, config, or protected environment file is unavailable" >&2
  exit 2
fi
if [[ ! -f "${SERVICE_DIR}/server.pid" || "$(cat "${SERVICE_DIR}/status.txt")" != "READY" ]] \
  || ! kill -0 "$(cat "${SERVICE_DIR}/server.pid")" 2>/dev/null; then
  echo "frozen model service is not ready" >&2
  exit 2
fi
for required in semgrep bandit uname; do
  if [[ ! -x "${COMPAT_BIN}/${required}" ]]; then
    echo "frozen Oracle compatibility input is unavailable" >&2
    exit 2
  fi
done
if [[ -e "${EXECUTION_DIR}" || -e "${RUN_DIR}" ]]; then
  echo "refusing to overwrite an existing observed execution" >&2
  exit 2
fi

mkdir -p "${EXECUTION_DIR}" "$(dirname "${RUN_DIR}")"
set -a
# shellcheck disable=SC1091
source "${DEPLOY_DIR}/.env"
set +a
: "${ALI_BAILIAN_API_KEY:?ALI_BAILIAN_API_KEY is unavailable}"
: "${OLLAMA_API_KEY:?local model-service API key is unavailable}"
export PYTHONPATH="${DEPLOY_DIR}/src"

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

def rows(relative: str) -> list[dict]:
    path = run_dir / relative
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

codes = rows("generation/observed_code.jsonl")
oracle = rows("oracle/observed_oracle.jsonl")

def syntax_ok(value: object) -> bool:
    try:
        ast.parse(value if isinstance(value, str) else "")
    except (SyntaxError, TypeError, ValueError):
        return False
    return True

payload = {
    "schema_version": "1.0",
    "status": "PASS" if exit_code == 0 else "ERROR",
    "exit_code": exit_code,
    "interpretation": "real_generator_engineering_pilot_only",
    "counts": {
        "observed_requests": len(rows("generation/observed_requests.jsonl")),
        "observed_attempts": len(rows("generation/observed_attempts.jsonl")),
        "observed_code": len(codes),
        "observed_oracle": len(oracle),
        "causal_tables": len(rows("discovery/causal_tables.jsonl")),
        "causal_observations": len(rows("discovery/causal_observations.jsonl")),
        "hypotheses": len(rows("discovery/hypotheses_frozen.jsonl")),
    },
    "code_diagnostics": {
        "syntax_ok": sum(syntax_ok(item.get("code")) for item in codes),
        "markdown_fence": sum(str(item.get("code", "")).startswith("```") for item in codes),
    },
    "security_labels": dict(sorted(Counter(str(x.get("security_label")) for x in oracle).items())),
}
summary_path.write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}
trap finalize EXIT

cat >"${EXECUTION_DIR}/commands.txt" <<EOF
PYTHONPATH=${DEPLOY_DIR}/src ${PYTHON} -m secaware.cli preflight --config ${CONFIG}
PYTHONPATH=${DEPLOY_DIR}/src ${PYTHON} -m secaware.cli extract-prompt-tsg --config ${CONFIG}
PYTHONPATH=${DEPLOY_DIR}/src ${PYTHON} -m secaware.cli generate-observed --config ${CONFIG}
PATH=${COMPAT_BIN}:\${PATH} PYTHONPATH=${DEPLOY_DIR}/src ${PYTHON} -m secaware.cli run-oracle --config ${CONFIG} --condition observed
PYTHONPATH=${DEPLOY_DIR}/src ${PYTHON} -m secaware.cli discover --config ${CONFIG}
EOF

sha256sum \
  "${CONFIG}" \
  "${DEPLOY_DIR}/scripts/start_qwen25_coder_e2e_pilot_v1.sh" \
  "${DEPLOY_DIR}/scripts/run_e2e_pilot_qwen25_observed_v1.sh" \
  "${DEPLOY_DIR}/data/e2e-pilot/cyberseceval-v2-cwe78-cwe89-v1/prompts.jsonl" \
  "${DEPLOY_DIR}/policies/oracle/python/policy.lock.json" \
  "${DEPLOY_DIR}/policies/oracle/python/coverage-contract.json" \
  "${SERVICE_DIR}/model-metadata.sha256" \
  >"${EXECUTION_DIR}/input-files.sha256"
"${PYTHON}" --version >"${EXECUTION_DIR}/python-version.txt" 2>&1
"${PYTHON}" -m pip freeze --all >"${EXECUTION_DIR}/pip-freeze.txt"
nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu \
  --format=csv,noheader >"${EXECUTION_DIR}/gpu-before.csv"

record_event "preflight" "started"
"${PYTHON}" -m secaware.cli preflight --config "${CONFIG}" \
  >"${EXECUTION_DIR}/preflight.stdout.log" 2>"${EXECUTION_DIR}/preflight.stderr.log"
record_event "preflight" "passed"

record_event "prompt_tsg" "started"
"${PYTHON}" -m secaware.cli extract-prompt-tsg --config "${CONFIG}" \
  >"${EXECUTION_DIR}/prompt-tsg.stdout.log" 2>"${EXECUTION_DIR}/prompt-tsg.stderr.log"
record_event "prompt_tsg" "passed"

record_event "observed_generation" "started"
"${PYTHON}" -m secaware.cli generate-observed --config "${CONFIG}" \
  >"${EXECUTION_DIR}/generate-observed.stdout.log" 2>"${EXECUTION_DIR}/generate-observed.stderr.log"
record_event "observed_generation" "passed"

record_event "observed_oracle" "started"
PATH="${COMPAT_BIN}:${PATH}" "${PYTHON}" -m secaware.cli run-oracle \
  --config "${CONFIG}" --condition observed \
  >"${EXECUTION_DIR}/observed-oracle.stdout.log" 2>"${EXECUTION_DIR}/observed-oracle.stderr.log"
record_event "observed_oracle" "passed"

record_event "discovery" "started"
set +e
"${PYTHON}" -m secaware.cli discover --config "${CONFIG}" \
  >"${EXECUTION_DIR}/discover.stdout.log" 2>"${EXECUTION_DIR}/discover.stderr.log"
discovery_code="$?"
set -e
printf '%s\n' "${discovery_code}" >"${EXECUTION_DIR}/discovery-exit-code.txt"
if [[ "${discovery_code}" -eq 0 ]]; then
  record_event "discovery" "passed"
elif [[ "${discovery_code}" -eq 60 ]] \
  && grep -q "reference FCI run failed validation" "${EXECUTION_DIR}/discover.stderr.log"; then
  record_event "discovery" "expected_small_sample_terminal"
else
  record_event "discovery" "failed_${discovery_code}"
  exit "${discovery_code}"
fi

nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu \
  --format=csv,noheader >"${EXECUTION_DIR}/gpu-after.csv"
