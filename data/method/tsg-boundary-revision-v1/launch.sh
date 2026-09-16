set -eu
study=/home/wsy/work/prompt-mechanism-study
input=$study/inputs/tsg-boundary-revision-v1
test "$(stat -c %a "$study/.env")" = 600
for version in revised baseline; do
  case "$version" in
    revised) expected=0f39e029d2fd77d7f1000e0c8d83cb29c8c8d439af8ca75ee56c09bd248c2862 ;;
    baseline) expected=17987dc2682c4e39e416c1daeac82e2b2bf28c7e190c6871e30a8481be487e0e ;;
  esac
  package=$input/$version
  output=$study/results/tsg-boundary-revision-v1/$version
  test "$(sha256sum "$package/execution-source.tar.gz" | cut -d ' ' -f 1)" = "$expected"
  test ! -e "$package/source"
  test ! -e "$output"
  mkdir -p "$package/source" "$output"
  tar -xzf "$package/execution-source.tar.gz" -C "$package/source"
  set +e
  docker run --rm --name "pms-tsg-boundary-$version" --user "$(id -u):$(id -g)" --env-file "$study/.env" -e PYTHONPATH=/input/src -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUTF8=1 -v "$package/source:/input:ro" -v "$output:/output" -w /input sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0 python scripts/run_tsg_development.py "data/method/tsg-boundary-revision-v1/$version" /output/run > "$output/run.log" 2>&1
  status=$?
  set -e
  printf '%s\n' "$status" > "$output/exit-code.txt"
  tar -czf "$package/results.tar.gz" -C "$output" .
  sha256sum "$package/results.tar.gz"
  printf '%s_exit_code=%s\n' "$version" "$status"
done
