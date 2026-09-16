set -eu
study=/home/wsy/work/prompt-mechanism-study
package=$study/inputs/complete-policy-natural-v1/proposal-canonical
output=$study/results/complete-policy-natural-v1/proposal-canonical
test ! -e "$package/source"
test ! -e "$output"
echo "5a0f89f8295cf6c5a7e603be2d01d01c8fbca924811e36153f3b49cabd928377  $package/proposal-canonical-inputs.tar.gz" | sha256sum -c -
mkdir -p "$package/source" "$output"
tar -xzf "$package/proposal-canonical-inputs.tar.gz" -C "$package/source"
set +e
docker run --rm --name pms-complete-policy-natural-proposal --user "$(id -u):$(id -g)" --env-file "$study/.env" -e PYTHONPATH=/code/src -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUTF8=1 -v "$study/inputs/complete-policy-natural-v1/source/source:/code:ro" -v "$package/source:/input:ro" -v "$output:/output" -w /input sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python data/method/complete-policy-natural-v1/propose.py data/method/complete-policy-natural-v1 /output/run > "$output/run.log" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$output/exit-code.txt"
tar -czf "$package/results.tar.gz" -C "$output" .
sha256sum "$package/results.tar.gz"
printf 'proposal_exit_code=%s\n' "$status"
