#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly INPUT_DIR="/home/wsy/secaware-experiments/inputs/oracle-coverage-cwe78-canary-v1-20260813-01"
readonly EXECUTION_DIR="/home/wsy/secaware-experiments/executions/oracle-coverage-cwe78-canary-v1-20260813-01"
readonly ENV_DIR="/home/wsy/secaware-environments/server-smoke-py312-20260812-01"
readonly COMPAT_BIN="/home/wsy/secaware-experiments/inputs/server-smoke-v1-20260812-06-oracle-compat/bin"
readonly PYTHON="${ENV_DIR}/bin/python"
readonly CORPUS_DIR="${INPUT_DIR}/corpus"
readonly TEST_DIR="${INPUT_DIR}/functional_tests"
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
  "${INPUT_DIR}/manifest.json" \
  "${INPUT_DIR}/semgrep.yml" \
  "${INPUT_DIR}/bandit.yml" \
  "${INPUT_DIR}/bandit-metadata.json" \
  "${TEST_DIR}/test_functionality.py"; do
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
export PATH="${COMPAT_BIN}:${PATH}"

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
export PATH=${COMPAT_BIN}:\$PATH
${PYTHON} --version
semgrep --version
bandit --version
${PYTHON} -m unittest discover -s ${TEST_DIR} -p test_*.py -v
semgrep --config ${INPUT_DIR}/semgrep.yml --json --metrics off --disable-version-check --no-git-ignore ${CORPUS_DIR}
bandit -c ${INPUT_DIR}/bandit.yml -f json -r ${CORPUS_DIR}
EOF

/usr/bin/find "${INPUT_DIR}" -type f -print0 \
  | /usr/bin/sort -z \
  | /usr/bin/xargs -0 /usr/bin/sha256sum \
  >"${EXECUTION_DIR}/input-files.sha256"

"${PYTHON}" --version >"${EXECUTION_DIR}/python-version.txt" 2>&1
semgrep --version >"${EXECUTION_DIR}/semgrep-version.txt" 2>&1
bandit --version >"${EXECUTION_DIR}/bandit-version.txt" 2>&1
/usr/bin/uname -a >"${EXECUTION_DIR}/uname.txt" 2>&1
/usr/bin/uptime >"${EXECUTION_DIR}/uptime-before.txt" 2>&1
/usr/bin/free -h >"${EXECUTION_DIR}/memory-before.txt" 2>&1

record_event "functional_tests" "started"
set +e
"${PYTHON}" -m unittest discover \
  -s "${TEST_DIR}" \
  -p 'test_*.py' \
  -v \
  >"${EXECUTION_DIR}/functional-tests.stdout.log" \
  2>"${EXECUTION_DIR}/functional-tests.stderr.log"
functional_status="$?"
set -e
printf '%s\n' "${functional_status}" >"${EXECUTION_DIR}/functional-tests.exit-code.txt"
if [[ "${functional_status}" -ne 0 ]]; then
  record_event "functional_tests" "failed"
else
  record_event "functional_tests" "passed"
fi

record_event "oracle_analyzers" "started"
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
  record_event "oracle_analyzers" "execution_failed"
  exit 1
fi
record_event "oracle_analyzers" "completed"

set +e
"${PYTHON}" - \
  "${INPUT_DIR}/manifest.json" \
  "${EXECUTION_DIR}/semgrep.json" \
  "${EXECUTION_DIR}/bandit.json" \
  "${functional_status}" \
  "${EXECUTION_DIR}/summary.json" <<'PY'
import collections
import json
import pathlib
import sys

manifest_path, semgrep_path, bandit_path, functional_status, summary_path = sys.argv[1:]
manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
semgrep = json.loads(pathlib.Path(semgrep_path).read_text(encoding="utf-8"))
bandit = json.loads(pathlib.Path(bandit_path).read_text(encoding="utf-8"))


def basename(value: str) -> str:
    return pathlib.PurePosixPath(value.replace("\\", "/")).name


findings = collections.defaultdict(list)
for finding in semgrep.get("results", []):
    findings[basename(finding["path"])].append(finding["check_id"])
for finding in bandit.get("results", []):
    findings[basename(finding["filename"])].append(finding["test_id"])

fixture_results = []
for fixture in manifest["fixtures"]:
    actual = sorted(findings[fixture["file"]])
    accepted = set(fixture["accepted_rule_ids"])
    expected = fixture["expected_security_label"]
    if expected == "INSECURE":
        passed = bool(accepted.intersection(actual))
        reason = "accepted_finding_present" if passed else "accepted_finding_missing"
    else:
        passed = not actual
        reason = "finding_free" if passed else "unexpected_finding_on_secure_fixture"
    fixture_results.append(
        {
            "fixture_id": fixture["fixture_id"],
            "file": fixture["file"],
            "profile_id": fixture["profile_id"],
            "expected_security_label": expected,
            "actual_rule_ids": actual,
            "status": "PASS" if passed else "FAIL",
            "reason": reason,
        }
    )

profile_results = []
profile_ids = sorted({item["profile_id"] for item in manifest["fixtures"]})
for profile_id in profile_ids:
    relevant = [item for item in fixture_results if item["profile_id"] == profile_id]
    passed = all(item["status"] == "PASS" for item in relevant)
    profile_results.append(
        {
            "profile_id": profile_id,
            "status": "PASS" if passed else "FAIL",
            "fixture_count": len(relevant),
            "failed_fixture_ids": [
                item["fixture_id"] for item in relevant if item["status"] == "FAIL"
            ],
        }
    )

functional_passed = int(functional_status) == 0
passed = functional_passed and all(item["status"] == "PASS" for item in profile_results)
summary = {
    "schema_version": "1.0",
    "canary_id": manifest["canary_id"],
    "status": "PASS" if passed else "FAIL",
    "functional_tests_status": "PASS" if functional_passed else "FAIL",
    "fixture_results": fixture_results,
    "profile_results": profile_results,
    "zero_finding_supported_approved": False,
    "interpretation": "pilot_canary_only_no_coverage_contract_change",
}
pathlib.Path(summary_path).write_text(
    json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
raise SystemExit(0 if passed else 1)
PY
summary_status="$?"
set -e
printf '%s\n' "${summary_status}" >"${EXECUTION_DIR}/summary.exit-code.txt"
/usr/bin/uptime >"${EXECUTION_DIR}/uptime-after.txt" 2>&1
/usr/bin/free -h >"${EXECUTION_DIR}/memory-after.txt" 2>&1

/usr/bin/find "${EXECUTION_DIR}" -maxdepth 1 -type f ! -name output-files.sha256 -print0 \
  | /usr/bin/sort -z \
  | /usr/bin/xargs -0 /usr/bin/sha256sum \
  >"${EXECUTION_DIR}/output-files.sha256"

if [[ "${summary_status}" -ne 0 ]]; then
  record_event "cwe78_canary" "failed"
  exit 1
fi
record_event "cwe78_canary" "passed"
