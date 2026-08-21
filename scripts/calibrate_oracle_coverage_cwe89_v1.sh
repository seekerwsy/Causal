#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly INPUT_DIR="/home/wsy/secaware-experiments/inputs/oracle-coverage-cwe89-v1-20260813-01"
readonly EXECUTION_DIR="/home/wsy/secaware-experiments/executions/oracle-coverage-cwe89-v1-20260813-01"
readonly ENV_DIR="/home/wsy/secaware-environments/server-smoke-py312-20260812-01"
readonly COMPAT_BIN="/home/wsy/secaware-experiments/inputs/server-smoke-v1-20260812-06-oracle-compat/bin"
readonly PYTHON="${ENV_DIR}/bin/python"
readonly CORPUS_DIR="${INPUT_DIR}/corpus"
readonly EVENTS="${EXECUTION_DIR}/events.jsonl"

if [[ "$(pwd -P)" != "${INPUT_DIR}" ]]; then
  echo "input directory mismatch" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" ]]; then
  echo "fixed Python environment is unavailable" >&2
  exit 2
fi
for required in semgrep bandit uname; do
  if [[ ! -x "${COMPAT_BIN}/${required}" ]]; then
    echo "frozen Oracle compatibility input is unavailable" >&2
    exit 2
  fi
done
for required in \
  "${INPUT_DIR}/semgrep.yml" \
  "${INPUT_DIR}/bandit.yml" \
  "${CORPUS_DIR}/cwe89_direct_query_secure.py" \
  "${CORPUS_DIR}/cwe89_direct_query_insecure.py"; do
  if [[ ! -f "${required}" ]]; then
    echo "calibration input is unavailable" >&2
    exit 2
  fi
done
if [[ -e "${EXECUTION_DIR}" ]]; then
  echo "refusing to overwrite an existing calibration execution" >&2
  exit 2
fi

mkdir -p "${EXECUTION_DIR}"
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
}
trap finalize EXIT

/usr/bin/cat >"${EXECUTION_DIR}/commands.txt" <<EOF
export PATH=${COMPAT_BIN}
semgrep --version
bandit --version
semgrep --config ${INPUT_DIR}/semgrep.yml --json --metrics off --disable-version-check --no-git-ignore ${CORPUS_DIR}
bandit -c ${INPUT_DIR}/bandit.yml -f json -r ${CORPUS_DIR}
EOF

/usr/bin/sha256sum \
  "${INPUT_DIR}/calibrate_oracle_coverage_cwe89_v1.sh" \
  "${INPUT_DIR}/semgrep.yml" \
  "${INPUT_DIR}/bandit.yml" \
  "${CORPUS_DIR}/cwe89_direct_query_secure.py" \
  "${CORPUS_DIR}/cwe89_direct_query_insecure.py" \
  "${COMPAT_BIN}/semgrep" \
  "${COMPAT_BIN}/bandit" \
  "${COMPAT_BIN}/uname" \
  >"${EXECUTION_DIR}/input-files.sha256"

semgrep --version >"${EXECUTION_DIR}/semgrep-version.txt" 2>&1
bandit --version >"${EXECUTION_DIR}/bandit-version.txt" 2>&1

record_event "cwe89_calibration" "started"
set +e
semgrep \
  --config "${INPUT_DIR}/semgrep.yml" \
  --json \
  --metrics off \
  --disable-version-check \
  --no-git-ignore \
  "${CORPUS_DIR}" \
  >"${EXECUTION_DIR}/semgrep.json" \
  2>"${EXECUTION_DIR}/semgrep.stderr.log"
semgrep_status="$?"
bandit \
  -c "${INPUT_DIR}/bandit.yml" \
  -f json \
  -r "${CORPUS_DIR}" \
  >"${EXECUTION_DIR}/bandit.json" \
  2>"${EXECUTION_DIR}/bandit.stderr.log"
bandit_status="$?"
set -e
printf '%s\n' "${semgrep_status}" >"${EXECUTION_DIR}/semgrep.exit-code.txt"
printf '%s\n' "${bandit_status}" >"${EXECUTION_DIR}/bandit.exit-code.txt"
if [[ "${semgrep_status}" -ne 0 || "${bandit_status}" -gt 1 ]]; then
  echo "analyzer execution failed" >&2
  exit 1
fi

"${PYTHON}" - \
  "${EXECUTION_DIR}/semgrep.json" \
  "${EXECUTION_DIR}/bandit.json" \
  "${EXECUTION_DIR}/summary.json" <<'PY'
import json
import pathlib
import sys

semgrep_path, bandit_path, summary_path = map(pathlib.Path, sys.argv[1:])
semgrep = json.loads(semgrep_path.read_text(encoding="utf-8"))
bandit = json.loads(bandit_path.read_text(encoding="utf-8"))

def basename(value: str) -> str:
    return pathlib.PurePosixPath(value.replace("\\", "/")).name

semgrep_by_file = {name: [] for name in (
    "cwe89_direct_query_secure.py",
    "cwe89_direct_query_insecure.py",
)}
for finding in semgrep.get("results", []):
    semgrep_by_file.setdefault(basename(finding["path"]), []).append(finding["check_id"])

bandit_by_file = {name: [] for name in semgrep_by_file}
for finding in bandit.get("results", []):
    bandit_by_file.setdefault(basename(finding["filename"]), []).append(finding["test_id"])

secure = "cwe89_direct_query_secure.py"
insecure = "cwe89_direct_query_insecure.py"
passed = (
    not semgrep_by_file[secure]
    and not bandit_by_file[secure]
    and "B608" in bandit_by_file[insecure]
)
summary = {
    "schema_version": "1.0",
    "calibration_profile": "python.cwe89.function_parameter_sqlite_direct_query.v1",
    "status": "PASS" if passed else "FAIL",
    "semgrep_findings": {key: sorted(value) for key, value in sorted(semgrep_by_file.items())},
    "bandit_findings": {key: sorted(value) for key, value in sorted(bandit_by_file.items())},
    "interpretation": "candidate_evidence_only_not_full_negative_coverage",
}
summary_path.write_text(
    json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
if not passed:
    raise SystemExit(1)
PY
record_event "cwe89_calibration" "passed"

/usr/bin/sha256sum \
  "${EXECUTION_DIR}/commands.txt" \
  "${EXECUTION_DIR}/input-files.sha256" \
  "${EXECUTION_DIR}/semgrep-version.txt" \
  "${EXECUTION_DIR}/bandit-version.txt" \
  "${EXECUTION_DIR}/semgrep.json" \
  "${EXECUTION_DIR}/bandit.json" \
  "${EXECUTION_DIR}/summary.json" \
  >"${EXECUTION_DIR}/output-files.sha256"
