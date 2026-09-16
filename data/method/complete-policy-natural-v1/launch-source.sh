set -eu
study=/home/wsy/work/prompt-mechanism-study
package=$study/inputs/complete-policy-natural-v1/source
output=$study/results/complete-policy-natural-v1/source
test "$(stat -c %a "$study/.env")" = 600
test ! -e "$package/source"
test ! -e "$output"
echo "a63b79fdca9bb716757b0c6e4b2637ca0a25f5243c816cfe730f507b35436b0a  $package/execution-source.tar.gz" | sha256sum -c -
mkdir -p "$package/source" "$output"
tar -xzf "$package/execution-source.tar.gz" -C "$package/source"
set +e
docker run --rm --name pms-complete-policy-natural-source --user "$(id -u):$(id -g)" --env-file "$study/.env" -e PYTHONPATH=/input/src -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUTF8=1 -v "$package/source:/input:ro" -v "$output:/output" -w /input sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python scripts/run_tsg_development.py data/method/complete-policy-natural-v1/source /output/run > "$output/run.log" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$output/exit-code.txt"
tar -czf "$package/results.tar.gz" -C "$output" .
sha256sum "$package/results.tar.gz"
printf 'source_exit_code=%s\n' "$status"
