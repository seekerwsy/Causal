set -eu
study=/home/wsy/work/prompt-mechanism-study
package=$study/inputs/tsg-reliable-construction-v1/compact-candidate
output=$study/results/tsg-reliable-construction-v1/compact-candidate
test "$(stat -c %a "$study/.env")" = 600
test ! -e "$package/source"
test ! -e "$output"
echo "0ef4c8c4ccc3decd022d061c1247684e1f6d4a4078b577ef228a553d6efeaf18  $package/execution-source.tar.gz" | sha256sum -c -
mkdir -p "$package/source" "$output"
tar -xzf "$package/execution-source.tar.gz" -C "$package/source"
set +e
docker run --rm --name pms-tsg-compact-candidate --user "$(id -u):$(id -g)" --env-file "$study/.env" -e PYTHONPATH=/input/src -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUTF8=1 -v "$package/source:/input:ro" -v "$output:/output" -w /input sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python data/method/tsg-reliable-construction-v1/compact-candidate/propose.py data/method/tsg-reliable-construction-v1/compact-candidate /output/run > "$output/run.log" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$output/exit-code.txt"
tar -czf "$package/results.tar.gz" -C "$output" .
sha256sum "$package/results.tar.gz"
printf 'proposal_exit_code=%s\n' "$status"
