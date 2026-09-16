#!/bin/sh
set -eu
ROOT=/home/wsy/work/prompt-mechanism-study
BASE=$ROOT/inputs/tsg-reliable-inventory-pilot-v1
OUT=$ROOT/results/tsg-reliable-inventory-pilot-v1
[ ! -e "$BASE" ]
[ ! -e "$OUT" ]
[ "$(stat -c %a "$ROOT/.deepseek-development.env")" = 600 ]
mkdir -p "$BASE" "$OUT"
tar -xzf "$ROOT/inputs/tsg-reliable-inventory-pilot-source.tar.gz" -C "$BASE"
docker run --rm --env-file "$ROOT/.deepseek-development.env" -e PYTHONPATH=/work/src -v "$BASE:/work:ro" -v "$OUT:/result" -w /work sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python run_tsg_development.py /work/experiment /result/run
tar -czf "$ROOT/results/tsg-reliable-inventory-pilot-results.tar.gz" -C "$OUT" run
