#!/bin/sh
set -eu
ROOT=/home/wsy/work/prompt-mechanism-study
BASE=$ROOT/inputs/tsg-reliable-construction-v1/predicate-binding-api
OUT=$ROOT/results/tsg-reliable-construction-v1/predicate-binding-api
[ ! -e "$BASE/source" ]
[ ! -e "$OUT" ]
[ "$(stat -c %a "$ROOT/.deepseek-development.env")" = 600 ]
echo "9971d94939f03e8092d0b1273a8b8132d2a51de27de617dfb119a820c8f3d4e7  $BASE/execution-source.tar.gz" | sha256sum -c -
mkdir -p "$BASE/source" "$OUT"
tar -xzf "$BASE/execution-source.tar.gz" -C "$BASE/source"
docker run --rm --user "$(id -u):$(id -g)" --env-file "$ROOT/.deepseek-development.env" -e PYTHONPATH=/work/src -e PYTHONDONTWRITEBYTECODE=1 -v "$BASE/source:/work:ro" -v "$OUT:/result" -w /work sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python run_tsg_development.py /work/experiment /result/run
tar -czf "$BASE/results.tar.gz" -C "$OUT" run
