#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/wsy/secaware-deployments/server-smoke-20260812-01"
readonly ENV_DIR="/home/wsy/secaware-environments/server-smoke-py312-20260812-01"
readonly INPUT_DIR="/home/wsy/secaware-experiments/inputs/server-smoke-v1-20260812-06-oracle-compat"
readonly COMPAT_BIN="${INPUT_DIR}/bin"
readonly EXECUTION_DIR="/home/wsy/secaware-experiments/executions/server-smoke-v1-20260812-06-oracle-compat"
readonly RUN_DIR="/home/wsy/secaware-experiments/runs/server-smoke-v1-20260812-02"
readonly CONFIG="/home/wsy/secaware-experiments/inputs/server-smoke-v1-20260812-02/ollama-qwen3-32b-bailian-v2.yaml"
readonly PYTHON="${ENV_DIR}/bin/python"
readonly EVENTS="${EXECUTION_DIR}/events.jsonl"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" || ! -f "${CONFIG}" ]]; then
  echo "fixed Python environment or immutable config is unavailable" >&2
  exit 2
fi
for required in semgrep bandit uname; do
  if [[ ! -x "${COMPAT_BIN}/${required}" ]]; then
    echo "frozen Oracle compatibility input is unavailable" >&2
    exit 2
  fi
done
if [[ -e "${EXECUTION_DIR}" ]]; then
  echo "refusing to overwrite an existing recovery execution" >&2
  exit 2
fi
if [[ ! -f "${RUN_DIR}/generation/observed_code.jsonl" ]]; then
  echo "sealed observed code is unavailable" >&2
  exit 2
fi
if [[ -e "${RUN_DIR}/oracle/observed_oracle.jsonl" ]]; then
  echo "refusing to overwrite an existing Oracle result" >&2
  exit 2
fi

mkdir -p "${EXECUTION_DIR}"

set -a
# shellcheck disable=SC1091
source "${DEPLOY_DIR}/.env"
set +a
export PATH="${COMPAT_BIN}"

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
import json
import pathlib
import sys

summary = pathlib.Path(sys.argv[1])
run_dir = pathlib.Path(sys.argv[2])
exit_code = int(sys.argv[3])

def count_lines(path: pathlib.Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())

summary.write_text(
    json.dumps(
        {
            "schema_version": "1.0",
            "status": "PASS" if exit_code == 0 else "ERROR",
            "exit_code": exit_code,
            "counts": {
                "observed_requests": count_lines(run_dir / "generation/observed_requests.jsonl"),
                "observed_attempts": count_lines(run_dir / "generation/observed_attempts.jsonl"),
                "observed_code": count_lines(run_dir / "generation/observed_code.jsonl"),
                "observed_oracle": count_lines(run_dir / "oracle/observed_oracle.jsonl"),
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n",
    encoding="utf-8",
)
PY
}
trap finalize EXIT

/usr/bin/cat >"${EXECUTION_DIR}/commands.txt" <<EOF
export PATH=${COMPAT_BIN}
semgrep --version
bandit --version
${PYTHON} -m secaware run-oracle --config ${CONFIG} --condition observed
EOF

/usr/bin/sha256sum \
  "${CONFIG}" \
  "${INPUT_DIR}/recover_server_smoke_oracle_v2.sh" \
  "${COMPAT_BIN}/semgrep" \
  "${COMPAT_BIN}/bandit" \
  "${COMPAT_BIN}/uname" \
  >"${EXECUTION_DIR}/input-files.sha256"
/usr/bin/sha256sum \
  "${RUN_DIR}/generation/observed_requests.jsonl" \
  "${RUN_DIR}/generation/observed_attempts.jsonl" \
  "${RUN_DIR}/generation/observed_code.jsonl" \
  >"${EXECUTION_DIR}/generation-before.sha256"

semgrep --version >"${EXECUTION_DIR}/semgrep-version.txt" 2>&1
bandit --version >"${EXECUTION_DIR}/bandit-version.txt" 2>&1

record_event "observed_oracle_compat_recovery" "started"
"${PYTHON}" -m secaware run-oracle --config "${CONFIG}" --condition observed \
  >"${EXECUTION_DIR}/observed-oracle.stdout.log" \
  2>"${EXECUTION_DIR}/observed-oracle.stderr.log"
record_event "observed_oracle_compat_recovery" "passed"

/usr/bin/sha256sum \
  "${RUN_DIR}/generation/observed_requests.jsonl" \
  "${RUN_DIR}/generation/observed_attempts.jsonl" \
  "${RUN_DIR}/generation/observed_code.jsonl" \
  >"${EXECUTION_DIR}/generation-after.sha256"
/usr/bin/diff -u "${EXECUTION_DIR}/generation-before.sha256" \
  "${EXECUTION_DIR}/generation-after.sha256" \
  >"${EXECUTION_DIR}/generation-integrity.diff"
