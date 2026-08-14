#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/wsy/secaware-deployments/e2e-pilot-20260814-04"
readonly ENV_DIR="/home/wsy/secaware-environments/server-smoke-py312-20260812-02"
readonly PYTHON="${ENV_DIR}/bin/python"
readonly CONFIG="${DEPLOY_DIR}/configs/e2e-pilot/server-qwen25-coder-32b-observed-v1.yaml"
readonly RUN_DIR="/home/wsy/secaware-experiments/runs/e2e-pilot-qwen25-observed-v1-20260814-01"
readonly EXECUTION_DIR="/home/wsy/secaware-experiments/executions/e2e-pilot-qwen25-discovery-recovery-v1-20260814-01"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" || ! -f "${CONFIG}" || ! -d "${RUN_DIR}" ]]; then
  echo "fixed Python environment, config, or source run is unavailable" >&2
  exit 2
fi
if [[ -e "${EXECUTION_DIR}" ]]; then
  echo "refusing to overwrite an existing recovery execution" >&2
  exit 2
fi
for manifest in \
  extract-prompt-tsg.json \
  plan-provider-generation-observed.json \
  generate-provider-observed.json \
  run-oracle-observed.json; do
  if [[ ! -f "${RUN_DIR}/.stages/${manifest}" ]]; then
    echo "required committed source stage is unavailable" >&2
    exit 2
  fi
done
if [[ -f "${RUN_DIR}/.stages/assemble-causal-tables.json" ]]; then
  echo "causal-table stage is already committed" >&2
  exit 2
fi

mkdir -p "${EXECUTION_DIR}"
export PYTHONPATH="${DEPLOY_DIR}/src"

cat >"${EXECUTION_DIR}/commands.txt" <<EOF
PYTHONPATH=${DEPLOY_DIR}/src ${PYTHON} -m secaware.cli discover --config ${CONFIG} --run-dir ${RUN_DIR}
EOF
"${PYTHON}" --version >"${EXECUTION_DIR}/python-version.txt" 2>&1
"${PYTHON}" -m pip freeze --all >"${EXECUTION_DIR}/pip-freeze.txt"
sha256sum \
  "${CONFIG}" \
  "${DEPLOY_DIR}/scripts/recover_e2e_pilot_qwen25_discovery_v1.sh" \
  "${DEPLOY_DIR}/src/secaware/generation/request_planner.py" \
  "${DEPLOY_DIR}/src/secaware/pipeline/stages/causal_tables.py" \
  "${RUN_DIR}/.stages/extract-prompt-tsg.json" \
  "${RUN_DIR}/.stages/generate-provider-observed.json" \
  "${RUN_DIR}/.stages/run-oracle-observed.json" \
  "${RUN_DIR}/generation/observed_code.jsonl" \
  "${RUN_DIR}/oracle/observed_oracle.jsonl" \
  >"${EXECUTION_DIR}/inputs-before.sha256"

set +e
"${PYTHON}" -m secaware.cli discover \
  --config "${CONFIG}" --run-dir "${RUN_DIR}" \
  >"${EXECUTION_DIR}/discover.stdout.log" \
  2>"${EXECUTION_DIR}/discover.stderr.log"
readonly DISCOVERY_CODE="$?"
set -e
printf '%s\n' "${DISCOVERY_CODE}" >"${EXECUTION_DIR}/discovery-exit-code.txt"

if [[ "${DISCOVERY_CODE}" -ne 60 ]] \
  || ! grep -q "reference FCI run failed validation" "${EXECUTION_DIR}/discover.stderr.log"; then
  printf '%s\n' "ERROR" >"${EXECUTION_DIR}/status.txt"
  echo "unexpected discovery recovery terminal status" >&2
  exit "${DISCOVERY_CODE}"
fi
if [[ ! -f "${RUN_DIR}/.stages/assemble-causal-tables.json" ]]; then
  printf '%s\n' "ERROR" >"${EXECUTION_DIR}/status.txt"
  echo "causal-table recovery did not commit" >&2
  exit 3
fi

sha256sum \
  "${RUN_DIR}/.stages/assemble-causal-tables.json" \
  "${RUN_DIR}/discovery/causal_tables.jsonl" \
  "${RUN_DIR}/discovery/causal_observations.jsonl" \
  "${RUN_DIR}/discovery/causal_exclusions.jsonl" \
  >"${EXECUTION_DIR}/outputs-after.sha256"

"${PYTHON}" - "${EXECUTION_DIR}/summary.json" "${RUN_DIR}" "${DISCOVERY_CODE}" <<'PY'
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
run_dir = pathlib.Path(sys.argv[2])
discovery_code = int(sys.argv[3])

def count(relative: str) -> int:
    path = run_dir / relative
    return sum(bool(line) for line in path.read_text(encoding="utf-8").splitlines())

payload = {
    "schema_version": "1.0",
    "status": "PASS_EXPECTED_SMALL_SAMPLE_TERMINAL",
    "discovery_exit_code": discovery_code,
    "reused_frozen_artifacts": {
        "observed_code": count("generation/observed_code.jsonl"),
        "observed_oracle": count("oracle/observed_oracle.jsonl"),
    },
    "recovered_artifacts": {
        "causal_tables": count("discovery/causal_tables.jsonl"),
        "causal_observations": count("discovery/causal_observations.jsonl"),
        "causal_exclusions": count("discovery/causal_exclusions.jsonl"),
    },
    "hypotheses_frozen": 0,
}
summary_path.write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
printf '%s\n' "PASS_EXPECTED_SMALL_SAMPLE_TERMINAL" >"${EXECUTION_DIR}/status.txt"
