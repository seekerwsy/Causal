# Role-Grouped Directional JCI & Task-Unit Cross-Fitting Validation Results

- **Study ID**: `jci-directional-grouped-validation-20261116` (`BOUNDED_DIRECTIONAL_GROUPED_CROSSFIT_VALIDATION`)
- **Configuration**: [configs/jci-directional-grouped-validation.json](../../configs/jci-directional-grouped-validation.json)
- **Batch Seeds**: `[2026111611, 2026111612]` (8 repetitions/batch × 2 batches × 3 scenarios = 48 simulation cells)
- **Target Budget**: `auxiliary_size = 512`, `source_size = 128`, `target_size = 128`, `target_folds = 4` (identical 128-unit total target budget to prior `32 fit + 32 cal + 64 ranking` splits)
- **Artifact Provenance**:
  - `source.zip` SHA-256: `b2633b619a307fed6a3eb974c902c25d2417b428a7c523a30d54e65ccff29d01`
  - `summary/result.json` SHA-256: `2868243a15dc41dec73542b51bd173898c7ee1b7db3657eae78b9310c2283787`
  - `verification/result.json`: `status = "VERIFIED"`, `cells = 48`, `queries_verified = 227,250`, `comparisons_verified = 51`
- **Evidence Boundary**: `formal_claim_allowed = false`, `new_provider_calls = 0` (bounded simulation study; does not constitute natural-task or provider confirmation).

---

## 1. Variance Reduction Comparisons (51-Family Bonferroni Corrected)

Relative conditional score variance reduction of `jci` (using canonical PAG entry/exit role decomposition `(V_root, V_up, V_term, V_other)`, role-grouped finite shrinkage, and 4-fold task-unit cross-fitting) against each baseline. Passing requires `relative_reduction >= 5%`, Bonferroni lower bound `> 0`, and positive improvements in both independent seed batches.

| Scenario | Comparator Family | Relative $\Delta\text{Var}$ Range | Passed | Harm Supported | Selected Profiles (`jci`, $n=16$) |
| --- | --- | ---: | ---: | ---: | --- |
| `downstream_signal` | 7 direct + 3 structural | `+13.06%` to `+17.57%` | **10/10** | **0/10** | `downstream` (15), `reachable` (1) |
| `target_new_attribute` | 7 direct + 3 structural | `+2.25%` to `+5.33%` | 0/10 | **0/10** | `downstream` (13), `reachable` (3) |
| `upstream_control` | 7 direct + 3 structural | `+2.53%` to `+16.79%` | **7/10** | **0/10** | `root` (14), `upstream` (1), `uniform` (1) |

### Key Per-Comparator Breakdown (`jci`)

- **`downstream_signal`** (all 10/10 supported): `+16.98%` vs `direct_uniform` (`lo=+0.000537`), `+17.22%` vs `direct_context`, `+16.98%` vs `full_logit`, `+13.06%` vs `sparse_logit`, `+14.13%` vs `screened_logit`, `+17.40%` vs `boosted`, `+17.57%` vs `pca`, `+17.12%` vs `skeleton_background` / `propagated_skeleton`, `+17.28%` vs `shuffled`.
- **`upstream_control`** (`upstream_harm_count = 0`, 7/10 supported): `+15.31%` vs `direct_uniform` (`lo=+0.000347`, supported), `+15.31%` vs `full_logit` (supported), `+12.52%` vs `sparse_logit` (supported), `+13.57%` vs `screened_logit` (supported), `+16.79%` vs `boosted` (supported), `+15.77%` vs `pca` (supported), `+15.35%` vs `shuffled` (supported), `+8.46%` vs `direct_context` (`lo=-0.000027`), `+2.53%` vs `skeleton_background` (`lo=-0.000275`), `+4.37%` vs `propagated_skeleton` (`lo=-0.000250`).
- **`target_new_attribute`**: Every point estimate was positive (`+2.25%` vs `sparse_logit` up to `+5.33%` vs `boosted`), with zero harms (`0/10`). Cross-fitting invoked the `full_logit` fallback in `21/64` target folds to adapt to the shifted target-only attribute.

---

## 2. Descriptive Diagnostics & Guard Integrity

`47/48` cells passed `attribute_direction_checks`; 1 cell triggered the cycle/conflict guard and fell back cleanly to uniform penalties while remaining in the 48-cell denominator.

| Scenario | Method | Bias | MSE | Mean Cond. Variance | Coverage | Fallback Folds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `downstream_signal` | `jci` | `+0.00435` | `0.00330` | `0.003757` | `16/16` | `0` |
| `downstream_signal` | `oracle` (diag.) | `+0.00649` | `0.00325` | `0.003726` | `16/16` | `0` |
| `downstream_signal` | `direct_uniform` | `+0.00279` | `0.00360` | `0.004525` | `15/16` | `27` |
| `downstream_signal` | `target_only` | `-0.00111` | `0.00429` | `0.005864` | `16/16` | `0` |
| `target_new_attribute` | `jci` | `-0.02077` | `0.00479` | `0.005058` | `16/16` | `21` |
| `target_new_attribute` | `direct_uniform` | `-0.01451` | `0.00530` | `0.005288` | `16/16` | `33` |
| `upstream_control` | `jci` | `+0.01452` | `0.00360` | `0.004229` | `16/16` | `0` |
| `upstream_control` | `oracle` (diag.) | `+0.01285` | `0.00343` | `0.004162` | `16/16` | `0` |
| `upstream_control` | `skeleton_background` | `+0.00249` | `0.00336` | `0.004338` | `16/16` | `3` |
| `upstream_control` | `target_only` | `+0.01072` | `0.00165` | `0.006449` | `16/16` | `0` |

## Reproduce & Verify

```powershell
$env:OPENBLAS_NUM_THREADS="1"; $env:OMP_NUM_THREADS="1"
python -m prompt_mechanism_study study run results/NEW_RUN --plan configs/jci-directional-grouped-validation.json --workers 8
python -m prompt_mechanism_study study verify results/NEW_RUN --workers 8
```
