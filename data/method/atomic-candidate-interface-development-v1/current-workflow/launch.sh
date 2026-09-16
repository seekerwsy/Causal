set -eu
study=/home/wsy/work/prompt-mechanism-study
input=$study/inputs/atomic-candidate-interface-development-v1/current-workflow
output=$study/results/atomic-candidate-interface-development-v1/current-workflow
test "$(sha256sum "$input/execution-source.tar.gz" | cut -d ' ' -f 1)" = dd90ae0c272c7d8b867502be08cace7a2b85eb2f93c49203147dc1403cb0e1bf
test "$(stat -c %a "$study/.env")" = 600
test ! -e "$input/source"
test ! -e "$output"
mkdir -p "$input/source" "$output"
tar -xzf "$input/execution-source.tar.gz" -C "$input/source"
set +e
docker run --rm --name pms-atomic-current-workflow --user "$(id -u):$(id -g)" --env-file "$study/.env" -e PYTHONPATH=/input/src -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUTF8=1 -v "$input/source:/input:ro" -v "$output:/output" -w /input sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python scripts/run_tsg_development.py data/method/atomic-candidate-interface-development-v1/current-workflow /output/run > "$output/run.log" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$output/exit-code.txt"
tar -czf "$input/results.tar.gz" -C "$output" .
sha256sum "$input/results.tar.gz"
printf 'workflow_exit_code=%s\n' "$status"
