set -eu
study=/home/wsy/work/prompt-mechanism-study
input=$study/inputs/tsg-extraction-comparison-v1
output=$study/results/tsg-extraction-comparison-v1
test "$(sha256sum "$input/execution-source.tar.gz" | cut -d ' ' -f 1)" = c4e1b4b798c3c70f5f3ec0d8abade0fdd8fda68741a0017bc06b256647eb924b
test "$(stat -c %a "$study/.env")" = 600
test ! -e "$input/source"
test ! -e "$output"
mkdir -p "$input/source" "$output"
tar -xzf "$input/execution-source.tar.gz" -C "$input/source"
set +e
docker run --rm --name pms-tsg-extraction-comparison --user "$(id -u):$(id -g)" --env-file "$study/.env" -e PYTHONPATH=/input/src -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUTF8=1 -v "$input/source:/input:ro" -v "$output:/output" -w /input sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python data/method/tsg-extraction-comparison-v1/compare.py data/method/tsg-extraction-comparison-v1 /output/run > "$output/run.log" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$output/exit-code.txt"
tar -czf "$input/results.tar.gz" -C "$output" .
sha256sum "$input/results.tar.gz"
printf 'comparison_exit_code=%s\n' "$status"
