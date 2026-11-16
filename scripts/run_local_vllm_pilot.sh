#!/usr/bin/env bash
set -euo pipefail

# Run the live local_vllm multi-operation paired counterfactual pilot and verify outputs.
# Expects $STUDY_ROOT (or defaults to current repository root) and a running vLLM endpoint.

STUDY_ROOT="${STUDY_ROOT:-$(pwd)}"
OUT_DIR="${1:-${STUDY_ROOT}/results/local-vllm-multiop-pilot-$(date -u +%Y%m%dT%H%M%SZ)}"

export OPENBLAS_NUM_THREADS=1
export OMP_NUM_THREADS=1
export LOCAL_VLLM_BASE_URL="${LOCAL_VLLM_BASE_URL:-http://127.0.0.1:8000/v1}"
export LOCAL_VLLM_MODEL_ID="${LOCAL_VLLM_MODEL_ID:-Qwen2.5-Coder-7B-Instruct}"

cd "${STUDY_ROOT}"
python -m prompt_mechanism_study study run "${OUT_DIR}" --plan configs/jci-local-vllm-pilot.json
python -m prompt_mechanism_study study verify "${OUT_DIR}"
