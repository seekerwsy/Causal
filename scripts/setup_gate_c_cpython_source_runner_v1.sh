#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly DEPLOY_DIR="/home/ubuntu/secaware-deployments/gate-c-model-scale-live-20260816-03"
readonly PYTHON_VERSION="3.12.13"
readonly SOURCE_URL="https://www.python.org/ftp/python/3.12.13/Python-3.12.13.tar.xz"
readonly SOURCE_SHA256="c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684"
readonly SOURCE_ARCHIVE="/home/ubuntu/secaware-sources/Python-3.12.13.tar.xz"
readonly BUILD_DIR="/home/ubuntu/secaware-builds/cpython-3.12.13-20260816-01"
readonly PREFIX="/home/ubuntu/secaware-python/cpython-3.12.13-system-20260816-01"
readonly RECORD_DIR="/home/ubuntu/secaware-experiments/readiness/gate-c-cpython-source-runner-20260816-01"
readonly BUILD_JOBS="4"
readonly PIP_VERSION="25.0.1"
readonly SETUPTOOLS_VERSION="83.0.0"
readonly WHEEL_VERSION="0.47.0"

if [[ "$(pwd -P)" != "${DEPLOY_DIR}" ]]; then
  echo "deployment directory mismatch" >&2
  exit 2
fi
if [[ -e "${SOURCE_ARCHIVE}" || -e "${BUILD_DIR}" || -e "${PREFIX}" || -e "${RECORD_DIR}" ]]; then
  echo "refusing to overwrite an existing source, build, prefix, or readiness record" >&2
  exit 2
fi
for executable in curl gcc make sha256sum tar; do
  if ! command -v "${executable}" >/dev/null 2>&1; then
    echo "required build executable is unavailable" >&2
    exit 2
  fi
done

mkdir -p "${RECORD_DIR}" "$(dirname "${SOURCE_ARCHIVE}")" "${BUILD_DIR}" "$(dirname "${PREFIX}")"

finish() {
  local code="$?"
  if [[ "${code}" -eq 0 ]]; then
    printf '%s\n' "READY" >"${RECORD_DIR}/status.txt"
  else
    printf '%s\n' "ERROR" >"${RECORD_DIR}/status.txt"
    printf '%s\n' "${code}" >"${RECORD_DIR}/exit-code.txt"
  fi
}
trap finish EXIT

cat >"${RECORD_DIR}/build-command.txt" <<EOF
curl --proto =https --tlsv1.2 --fail --location ${SOURCE_URL} --output ${SOURCE_ARCHIVE}
sha256sum --check Python-3.12.13.sha256
./configure --prefix=${PREFIX} --with-ensurepip=install
make -j${BUILD_JOBS}
make install
${PREFIX}/bin/python3.12 -m pip install pip==${PIP_VERSION} setuptools==${SETUPTOOLS_VERSION} wheel==${WHEEL_VERSION}
${PREFIX}/bin/python3.12 -m pip install --editable .[api,oracle]
EOF

date --utc --iso-8601=seconds >"${RECORD_DIR}/started-at-utc.txt"
printf '%s\n' "${SOURCE_SHA256}  ${SOURCE_ARCHIVE}" >"${RECORD_DIR}/Python-3.12.13.sha256"
dpkg-query -W >"${RECORD_DIR}/dpkg-build-inputs.txt"
gcc --version >"${RECORD_DIR}/gcc-version.txt" 2>&1
make --version >"${RECORD_DIR}/make-version.txt" 2>&1
nproc >"${RECORD_DIR}/nproc.txt"
uptime >"${RECORD_DIR}/uptime-before.txt"
free -h >"${RECORD_DIR}/memory-before.txt"

curl --proto '=https' --tlsv1.2 --fail --location "${SOURCE_URL}" \
  --output "${SOURCE_ARCHIVE}" \
  >"${RECORD_DIR}/download.stdout.log" 2>"${RECORD_DIR}/download.stderr.log"
sha256sum --check "${RECORD_DIR}/Python-3.12.13.sha256" \
  >"${RECORD_DIR}/sha256-check.txt" 2>"${RECORD_DIR}/sha256-check.stderr.log"
tar -xf "${SOURCE_ARCHIVE}" --strip-components=1 --directory "${BUILD_DIR}"

(
  cd "${BUILD_DIR}"
  ./configure --prefix="${PREFIX}" --with-ensurepip=install \
    >"${RECORD_DIR}/configure.stdout.log" 2>"${RECORD_DIR}/configure.stderr.log"
  make -j"${BUILD_JOBS}" \
    >"${RECORD_DIR}/make.stdout.log" 2>"${RECORD_DIR}/make.stderr.log"
  make install \
    >"${RECORD_DIR}/make-install.stdout.log" 2>"${RECORD_DIR}/make-install.stderr.log"
  cp config.log "${RECORD_DIR}/config.log"
)

"${PREFIX}/bin/python3.12" -c \
  "import os,ssl,sqlite3,sys; assert hasattr(os,'memfd_create'); assert hasattr(os,'pidfd_open'); print(sys.version); print(ssl.OPENSSL_VERSION); print(sqlite3.sqlite_version); print('linux-isolation-primitives-ready')" \
  >"${RECORD_DIR}/runtime-primitives.txt" 2>"${RECORD_DIR}/runtime-primitives.stderr.log"
"${PREFIX}/bin/python3.12" -m pip install \
  "pip==${PIP_VERSION}" \
  "setuptools==${SETUPTOOLS_VERSION}" \
  "wheel==${WHEEL_VERSION}" \
  >"${RECORD_DIR}/packaging-install.stdout.log" \
  2>"${RECORD_DIR}/packaging-install.stderr.log"
"${PREFIX}/bin/python3.12" -m pip install --editable ".[api,oracle]" \
  >"${RECORD_DIR}/project-install.stdout.log" \
  2>"${RECORD_DIR}/project-install.stderr.log"

"${PREFIX}/bin/python3.12" -c \
  "import bandit,causallearn,numpy,openai,pandas,pydantic,semgrep,secaware; print('imports-ready')" \
  >"${RECORD_DIR}/import-check.txt" 2>"${RECORD_DIR}/import-check.stderr.log"
"${PREFIX}/bin/semgrep" --version >"${RECORD_DIR}/semgrep-version.txt" 2>&1
"${PREFIX}/bin/bandit" --version >"${RECORD_DIR}/bandit-version.txt" 2>&1
"${PREFIX}/bin/python3.12" -m pip freeze --all >"${RECORD_DIR}/pip-freeze.txt"
uptime >"${RECORD_DIR}/uptime-after.txt"
free -h >"${RECORD_DIR}/memory-after.txt"
date --utc --iso-8601=seconds >"${RECORD_DIR}/completed-at-utc.txt"
