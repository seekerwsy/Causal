set -eu
study=/home/wsy/work/prompt-mechanism-study
package=$study/inputs/tsg-reliable-construction-v1/compact-candidate-v2
output=$study/results/tsg-reliable-construction-v1/compact-candidate-v2
test "$(stat -c %a "$study/.env")" = 600
test ! -e "$package/source"
test ! -e "$output"
echo "77b64de3b1ae6593fe7ecd498fcd046cf6496f2a50a2c13ab0fc830418993d1b  $package/execution-source.tar.gz" | sha256sum -c -
mkdir -p "$package/source" "$output"
tar -xzf "$package/execution-source.tar.gz" -C "$package/source"
set +e
docker run --rm --name pms-tsg-compact-candidate-v2 --user "$(id -u):$(id -g)" --env-file "$study/.env" -e PYTHONPATH=/input/src -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUTF8=1 -v "$package/source:/input:ro" -v "$output:/output" -w /input sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python data/method/tsg-reliable-construction-v1/compact-candidate-v2/propose.py data/method/tsg-reliable-construction-v1/compact-candidate-v2 /output/run > "$output/run.log" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$output/exit-code.txt"
tar -czf "$package/results.tar.gz" -C "$output" .
sha256sum "$package/results.tar.gz"
printf 'proposal_exit_code=%s\n' "$status"
