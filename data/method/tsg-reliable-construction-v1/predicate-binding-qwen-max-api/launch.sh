#!/bin/sh
set -eu
ROOT=/home/wsy/work/prompt-mechanism-study
BASE=$ROOT/inputs/tsg-reliable-construction-v1/predicate-binding-qwen-max-api
OUT=$ROOT/results/tsg-reliable-construction-v1/predicate-binding-qwen-max-api
[ ! -e "$BASE/source" ]
[ ! -e "$OUT" ]
[ "$(stat -c %a "$ROOT/.env")" = 600 ]
echo "088ce5c87d912bb866843c5cf573716aa47f1cf5b9378aa8e5563b0124988c80  $BASE/execution-source.tar.gz" | sha256sum -c -
mkdir -p "$BASE/source" "$OUT"
tar -xzf "$BASE/execution-source.tar.gz" -C "$BASE/source"
docker run --rm --user "$(id -u):$(id -g)" --env-file "$ROOT/.env" -e PYTHONPATH=/work/src -e PYTHONDONTWRITEBYTECODE=1 -v "$BASE/source:/work:ro" -v "$OUT:/result" -w /work sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python run_tsg_development.py /work/experiment /result/run
tar -czf "$BASE/results.tar.gz" -C "$OUT" run
