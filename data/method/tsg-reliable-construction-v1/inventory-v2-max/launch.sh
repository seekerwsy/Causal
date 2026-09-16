#!/bin/sh
set -eu
ROOT=/home/wsy/work/prompt-mechanism-study
BASE=$ROOT/inputs/tsg-reliable-construction-v1/inventory-v2-max
OUT=$ROOT/results/tsg-reliable-construction-v1/inventory-v2-max
[ ! -e "$BASE/source" ]
[ ! -e "$OUT" ]
[ "$(stat -c %a "$ROOT/.env")" = 600 ]
echo "ff4754e1693822af533142e6875a5bf4cb540d51855291c73f57b5eb147f7871  $BASE/execution-source.tar.gz" | sha256sum -c -
mkdir -p "$BASE/source" "$OUT"
tar -xzf "$BASE/execution-source.tar.gz" -C "$BASE/source"
docker run --rm --user "$(id -u):$(id -g)" --env-file "$ROOT/.env" -e PYTHONPATH=/work/src -e PYTHONDONTWRITEBYTECODE=1 -v "$BASE/source:/work:ro" -v "$OUT:/result" -w /work sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python run_tsg_development.py /work/experiment /result/run
tar -czf "$BASE/results.tar.gz" -C "$OUT" run
