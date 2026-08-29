# Prompt TSG Qwen3.7 / Oracle-v3 replication results

The prospective cross-model replication completed all 19 semantic task clusters and all 76 assigned arms on `qwen3.7-max-2026-05-20`. The intervention pilot and measurement pilot were scaled using protocol-integrity checks only. All 76 assignments remained in the final denominator, and both the remote and local independent verifiers reproduced the frozen analysis bundle.

The primary result is null. Secure-code yield was 12/19 (63.2%) in Absent, Specific, Generic, and Placebo. Specific minus Placebo was 0.0 percentage points: no cluster changed its observed secure indicator in either direction. Oracle unknowns leave a primary identification range from -26.3 to +21.1 percentage points, and the registered contrast is not statistically distinguishable from zero.

Functionality was 19/19 in both Specific and Placebo, so the primary functionality difference was zero and met the frozen non-inferiority rule. Absent functionality was 18/19. Secure-and-functional joint yield was 12/19 in every arm. Oracle evaluability was 15/19 in Specific and 14/19 in Placebo; the 5.3-point difference reflects one path result changing from unknown to insecure, not a security improvement.

Feature-level results explain the observed zero:

- `feature.safe_json_deserialization`: 4/4 secure in every arm;
- `feature.safe_yaml_deserialization`: 2/2 secure in every arm;
- `feature.sql_value_parameterization`: 5/5 secure in every arm;
- `feature.argv_without_shell`: 1/1 secure in every arm;
- `feature.path_confinement`: 0/7 secure in every arm. Specific produced three insecure and four unknown results; Placebo produced two insecure and five unknown results.

The first four features therefore had complete observed baseline security under this generator, leaving no improvement margin. Path confinement had intervention space but also an operationalization mismatch. Two Specific outputs correctly used resolved `Path` objects and `relative_to`, but their task contracts returned a path rather than accessing a file, so the access-sink Oracle reported `no_relevant_sink`. Several other Specific outputs implemented the high-level containment requirement with string-prefix checks, which the frozen Oracle deliberately did not certify. Thus the Prompt TSG binding selected the intended feature, but the natural-language realization neither forced an Oracle-recognized proof idiom nor guaranteed a task contract containing a measurable access sink.

The supported conclusion is limited but valid: on the complete 19-task strict-TSG census, Qwen3.7 Max showed no secure-yield benefit from a specific mechanism requirement over an equal-budget style placebo, while functionality was non-inferior. Together with the earlier Qwen3.5 result, this is a second model-level null on the same task census, not evidence that the true effect is exactly zero. The two runs should not be pooled as identically measured replications because Oracle-v3 was introduced prospectively for this run.

This result must not be tuned into significance. A future study should prospectively freeze a population with non-ceiling baselines and align each task contract, intervention wording, and Oracle sink definition before generation. In particular, path-return tasks should either receive a separately calibrated path-confinement outcome or be excluded before outcomes from an access-sink estimand. The present run remains immutable evidence of the current design boundary.

## Reproduction coordinates

- implementation commit: `27c2bce`;
- frozen task SHA-256: `d2c201d7ed7d9ca95356fb25da38db0e779ae39480ebd64130fbbab10d1fb4af`;
- frozen configuration SHA-256: `ecac3fa310e07bbac5fce7a7009a6d916df5d3d86c1314fbea7aa70a5d91bc2f`;
- deployment source archive SHA-256: `ab7efbec18d5292c6fb54eb96c383e1ff1972cf871359328162baf58c0527616`;
- analysis manifest SHA-256: `0c9251f430add1e8277ae90d9606151a23510a0a8b5c35089e3dd905cf6db694`;
- local closed run-detail archive: `.artifacts/prompt-tsg-qwen37-oracle-v3-run-details.tar.gz`, SHA-256 `b7e9884d8901fac4df9c901efc62f8096d0584db1ef27323245b8ad82bf5c58d`;
- deployment root: `/home/wsy/prompt-mechanism-study-deployments/prompt-tsg-qwen37-oracle-v3-27c2bce-20260826-19`;
- experiment root: `/home/wsy/prompt-mechanism-study-experiments/prompt-tsg-qwen37-oracle-v3-27c2bce-20260826-19`.

The implementation was frozen at `27c2bce`; the result bundle and independent
verification were closed together at archival commit `a733068`. The active
package intentionally no longer exposes the historical four-arm runner or
verifier. Reproduce this result from `a733068` in a separate checkout or Git
worktree, without restoring that path to the active package. From that checkout,
run:

```text
prompt-mechanism-four-arm verify-analysis \
  data/formal/results/prompt-tsg-strict-19-qwen37-oracle-v3-analysis \
  --config configs/formal/prompt-tsg-strict-19-qwen37-oracle-v3.json \
  --tasks data/formal/prompt-tsg-strict-v3-replication-tasks.jsonl
```
