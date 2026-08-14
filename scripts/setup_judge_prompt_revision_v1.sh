#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly SOURCE_DEPLOY_DIR="/home/wsy/secaware-deployments/server-smoke-20260812-02"
readonly DEPLOY_DIR="/home/wsy/secaware-deployments/server-smoke-20260813-04"
readonly ENV_DIR="/home/wsy/secaware-environments/server-smoke-py312-20260812-02"
readonly INPUT_DIR="/home/wsy/secaware-experiments/inputs/qwen25-coder-smoke-v1-20260813-07"
readonly PROMPT_INPUT="${INPUT_DIR}/functional_judge_v1.txt"
readonly SCRIPT_INPUT="${INPUT_DIR}/setup_judge_prompt_revision_v1.sh"
readonly PROMPT_RELATIVE="src/secaware/functional_judge/prompts/functional_judge_v1.txt"
readonly RECORD_DIR="${DEPLOY_DIR}/.deployment/judge-prompt-revision-20260813-01"
readonly PYTHON="${ENV_DIR}/bin/python"

if [[ ! -d "${SOURCE_DEPLOY_DIR}" || ! -x "${PYTHON}" \
  || ! -f "${PROMPT_INPUT}" || ! -f "${SCRIPT_INPUT}" ]]; then
  echo "source deployment, fixed environment, or frozen input is unavailable" >&2
  exit 2
fi
if [[ -e "${DEPLOY_DIR}" ]]; then
  echo "refusing to overwrite an existing deployment" >&2
  exit 2
fi

cp -a "${SOURCE_DEPLOY_DIR}" "${DEPLOY_DIR}"
mkdir -p "${RECORD_DIR}"

finalize() {
  local code="$?"
  set +e
  if [[ -d "${RECORD_DIR}" ]]; then
    if [[ "${code}" -eq 0 ]]; then
      printf '%s\n' "PASS" >"${RECORD_DIR}/status.txt"
    else
      printf '%s\n' "ERROR" >"${RECORD_DIR}/status.txt"
    fi
    printf '%s\n' "${code}" >"${RECORD_DIR}/exit-code.txt"
    date --utc --iso-8601=seconds >"${RECORD_DIR}/finished-at-utc.txt"
  fi
}
trap finalize EXIT

cat >"${RECORD_DIR}/commands.txt" <<EOF
cp -a ${SOURCE_DEPLOY_DIR} ${DEPLOY_DIR}
install -m 644 ${PROMPT_INPUT} ${DEPLOY_DIR}/${PROMPT_RELATIVE}
diff -qr --exclude=.deployment --exclude=functional_judge_v1.txt ${SOURCE_DEPLOY_DIR} ${DEPLOY_DIR}
cd ${DEPLOY_DIR}
PYTHONPATH=${DEPLOY_DIR}/src ${PYTHON} -m pytest -q tests/test_functional_judge.py tests/test_bailian_functional_judge_canary.py tests/test_packaging.py
EOF

sha256sum \
  "${SOURCE_DEPLOY_DIR}/${PROMPT_RELATIVE}" \
  "${PROMPT_INPUT}" \
  "${SCRIPT_INPUT}" \
  >"${RECORD_DIR}/inputs.sha256"
install -m 644 "${PROMPT_INPUT}" "${DEPLOY_DIR}/${PROMPT_RELATIVE}"
chmod 600 "${DEPLOY_DIR}/.env"

diff -qr \
  --exclude=.deployment \
  --exclude=functional_judge_v1.txt \
  "${SOURCE_DEPLOY_DIR}" "${DEPLOY_DIR}" \
  >"${RECORD_DIR}/non-prompt-diff.stdout.log" \
  2>"${RECORD_DIR}/non-prompt-diff.stderr.log"

sha256sum \
  "${SOURCE_DEPLOY_DIR}/${PROMPT_RELATIVE}" \
  "${DEPLOY_DIR}/${PROMPT_RELATIVE}" \
  >"${RECORD_DIR}/prompt-before-after.sha256"
if cmp -s \
  "${SOURCE_DEPLOY_DIR}/${PROMPT_RELATIVE}" \
  "${DEPLOY_DIR}/${PROMPT_RELATIVE}"; then
  echo "judge prompt revision did not change the frozen resource" >&2
  exit 3
fi

cd "${DEPLOY_DIR}"
PYTHONPATH="${DEPLOY_DIR}/src" "${PYTHON}" -m pytest -q \
  tests/test_functional_judge.py \
  tests/test_bailian_functional_judge_canary.py \
  tests/test_packaging.py \
  >"${RECORD_DIR}/pytest.stdout.log" \
  2>"${RECORD_DIR}/pytest.stderr.log"

PYTHONPATH="${DEPLOY_DIR}/src" "${PYTHON}" - \
  "${RECORD_DIR}/policy-resource.json" <<'PY'
import hashlib
import json
import pathlib
import sys

from secaware.functional_judge import FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256

path = pathlib.Path(sys.argv[1])
resource = pathlib.Path(
    "/home/wsy/secaware-deployments/server-smoke-20260813-04/"
    "src/secaware/functional_judge/prompts/functional_judge_v1.txt"
)
payload = {
    "schema_version": "1.0",
    "resource_sha256": hashlib.sha256(resource.read_bytes()).hexdigest(),
    "runtime_template_sha256": FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256,
}
if payload["resource_sha256"] != payload["runtime_template_sha256"]:
    raise SystemExit("runtime prompt resource hash failed validation")
path.write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
