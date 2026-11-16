# 2026-11-16 Formative Stage II Stress Tests: Negative Control and Attribute Measurement Noise

Evidence role: **formative simulation** (`formal_claim_allowed=false`, `new_provider_calls=0`). These runs test the Stage II machinery on a synthetic 64-attribute DGP. They are not natural-task or provider evidence.

## Why these runs were added

A framework review found two gaps in the earlier 48-cell validation ([2026-11-16-jci-grouped-crossfit-results.md](2026-11-16-jci-grouped-crossfit-results.md)):

1. In every scenario, the outcome loaded on attributes that some role in the JCI menu contains. `V_root` was added to the menu after a failure on `upstream_control` had been observed. So the validation could only confirm benefit; it could not show harm. The new `misaligned_signal` negative control loads the outcome only on latent-confounded proxy-chain intermediates. These are true `V_other` and lie outside every structural profile.
2. Stage I attributes are LLM-extracted and will contain errors. The new sensitivity arm flips each attribute independently with probability 0.10 (`attribute_measurement_flip_probability`). The flips apply to auxiliary, source, and target data alike, so they affect PAG discovery as well as learning.

The verifier was also strengthened. It now recomputes `harm_supported`, `downstream_gate_passed`, `upstream_harm_count`, `jci_harm_count_by_scenario`, `primary_passed`, and `direction_eligible_cells` from the replayed comparisons instead of copying them from the summary. A unit test confirms that a re-hashed summary with a forged verdict is rejected.

## Runs

| Plan | Output | Cells | CI queries verified | Comparisons | Status | `summary_sha256` |
|---|---|---|---|---|---|---|
| `configs/jci-directional-negative-control.json` (seeds 2026111621/22, no flips) | `results/jci-directional-negative-control-20261116` | 64 | 302,657 | 68 | VERIFIED | `612df46efbe73763e4adb52599709071987a52cdfe4a918925fb1224f8feeef2` |
| `configs/jci-directional-measurement-noise.json` (seeds 2026111631/32, flip 0.10) | `results/jci-directional-measurement-noise-20261116` | 64 | 330,901 | 68 | VERIFIED | `1ab247fee711e27b15905988110391cb0989e84d271c0c87eb297af309b7dde0` |

The Bonferroni family is 68 (4 scenarios × 17 pairs). A comparison is supported only if relative reduction is at least 5%, the simultaneous interval lies above 0, and both seed batches are positive.

## Results: no flips (negative-control plan)

Direction-eligible cells: 61/64. Supported JCI harms: 0 in every scenario. `primary_passed` = 19/28.

| Scenario | JCI supported (of 10) | ΔVar vs `full_logit` | ΔVar vs `skeleton_background` | Mean cond. variance jci / oracle / full_logit | Selected profile |
|---|---|---|---|---|---|
| `downstream_signal` | 10 | +14.11% | +13.25% | 0.003952 / 0.003761 / 0.004601 | downstream 15, uniform 1 |
| `target_new_attribute` | 8 (not vs sparse/screened) | +7.21% | +6.83% | 0.005018 / 0.005018 / 0.005408 | downstream 15, uniform 1 |
| `upstream_control` | 8 (not vs either skeleton) | +14.57% | +3.05% (n.s.) | 0.004206 / 0.004186 / 0.004924 | root 12, uniform 2, upstream 1, reachable 1 |
| `misaligned_signal` | 0 | +0.00% | −0.54% (n.s.) | 0.005214 / 0.005214 / 0.005214 | uniform 14, root 2 |

In `misaligned_signal`, JCI reduces to the unstructured `full_logit` learner: it selects the uniform profile in 14/16 cells, uses the target fallback in 32 folds, and matches `full_logit` variance to the printed precision. It is numerically worse than `sparse_logit` (−3.16%, interval [−3.23e−04, +3.54e−06]) and `screened_logit` (−2.01%), but neither difference is a supported harm.

## Results: 10% attribute flips (measurement-noise plan)

Direction-eligible cells: 54/64. Supported JCI harms: 0 in every scenario. `primary_passed` = **0/28**. `downstream_gate_passed` = **false**.

| Scenario | JCI supported (of 10) | ΔVar vs `full_logit` | Mean cond. variance jci / oracle / full_logit | Selected profile |
|---|---|---|---|---|
| `downstream_signal` | 0 | +3.63% | 0.005551 / 0.005255 / 0.005760 | downstream 5, reachable 6, uniform 5 |
| `target_new_attribute` | 0 | +1.80% | 0.006113 / 0.005939 / 0.006225 | downstream 9, reachable 4, uniform 3 |
| `upstream_control` | 0 | +2.57% | 0.005774 / 0.005653 / 0.005926 | root 9, uniform 4, reachable 1, downstream 1, upstream 1 |
| `misaligned_signal` | 0 | +0.00% | 0.006349 / 0.006349 / 0.006349 | uniform 16 |

## Reading

- **Robust**: validity–efficiency separation holds empirically. No supported harm appeared in any of 8 scenario × plan combinations, including the negative control. When the structure is uninformative, the learner falls back to unstructured behavior.
- **Established only for downstream structure**: an advantage over the *undirected* skeleton ablations is supported in `downstream_signal` in both seed sets. It is not supported in `upstream_control` (+2.53% earlier, +3.05% now). Results so far therefore do not show that edge *direction* adds value beyond adjacency when the signal sits at context entry points.
- **Seed sensitivity**: `target_new_attribute` passed 0/10 on seeds 2026111611/12 and 8/10 on seeds 2026111621/22. With 16 repetitions per scenario, pass counts near the 5% margin are unstable. Report interval estimates, not pass counts.
- **Main fragility**: at 10% attribute flips, the JCI advantage falls below the practical margin in every scenario. The gap between JCI and the oracle also widens: on `downstream_signal`, oracle-role ΔVar vs `full_logit` is about +8.8% (computed from the printed variances), against +3.6% for JCI. Noise therefore degrades both the recovered roles and the signal itself. For natural tasks, Stage I attribute reliability is a precondition for any Stage II efficiency claim, and it must be measured before Stage II results are interpreted.
