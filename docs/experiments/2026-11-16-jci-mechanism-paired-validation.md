# Verified 48-Cell Mechanism Discovery & Paired Counterfactual Validation (`2026-11-16`)

- **Run Directory**: `results/jci-mechanism-paired-validation-20261116` (`python -m prompt_mechanism_study study run results/jci-mechanism-paired-validation-20261116 --plan configs/jci-mechanism-validation.json --workers 4`)
- **Verification**: `python -m prompt_mechanism_study study verify results/jci-mechanism-paired-validation-20261116 --workers 4` -> **`VERIFIED`** (`48/48` cells replayed, `4,538` CI permutation queries verified, `summary_sha256: 22320497a4a3894d3601087176449e30340e5abba43c9218851deb4cee0645bb`)
- **Plan Scope**: `4` scenarios × `4` batch seeds × `3` repetitions = `48` cells (`n_discovery = 480`, `n_eval = 120` paired units/cell, `ci_draws = 299`, `ci_alpha = 0.05`, `eval_alpha = 0.05`, `practical_margin = 0.05`), `formal_claim_allowed = false`, `new_provider_calls = 0`.

---

## Scenario Summary Table

| Scenario (`12` cells each) | `JCI` Recall | `JCI` FP Cells | `Corr` Recall | `Corr` FP Cells | `JCI` Abstention | Mean `joint` (`base` / `corr_tsg` / `jci_flat` / `jci_tsg`) | `jci_tsg` vs `corr_tsg` ($\Delta$ joint, sig/12) | `jci_tsg` vs `jci_flat` ($\Delta$ joint, sig/12) | Mean Pairing VR | Harm Cells |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `confounded_and_scoped` | `0.833` | `1/12` | `0.083` | `12/12` | `0.167` | `0.494` / `0.508` / `0.467` / **`0.635`** | `+0.127` (`9/12`) | `+0.167` (`10/12`) | `0.714`–`0.777` | `0` |
| `pure_latent_trap` | `0.750` | `0/12` | `0.000` | `12/12` | `0.250` | `0.445` / `0.445` / `0.478` / **`0.574`** | `+0.128` (`9/12`) | `+0.095` (`9/12`) | `0.779`–`0.829` | `0` |
| `multi_op_high_interference` | `0.917` | `0/12` | `0.000` | `12/12` | `0.083` | `0.474` / `0.474` / `0.337` / **`0.620`** | `+0.147` (`11/12`) | `+0.283` (`11/12`) | `0.565`–`0.745` | `0` |
| `null_spurious_only` (Neg. Ctrl) | — | **`0/12`** | — | `12/12` | **`1.000`** | `0.395` / `0.395` / `0.395` / `0.395` | `0.000` (`0/12`) | `0.000` (`0/12`) | — | `0` |

## Key Findings

1. **Causal Deconfounding (`jci_tsg` vs `corr_tsg`, Contribution 2)**: Across all three active scenarios, naive observational correlation is trapped by latent-confounded or environment-confounded proxies (`12/12` false-discovery cells in every scenario), whereas JCI with post-generation sinks and intervention probes suppresses false discoveries (`0/12` in `null_spurious_only`, `pure_latent_trap`, and `multi_op_high_interference`; `1/12` finite-sample false positive in `confounded_and_scoped`) and yields `+0.127` to `+0.147` net joint yield lift with zero adverse harms.
2. **Scope Protection Against Functional Bleed (`jci_tsg` vs `jci_flat`, Contribution 1)**: Even when JCI identifies the true security driver (`Z_cau`), applying it flatly across multi-operation shared-object tasks degrades functionality (`jci_flat` functionality drops to `0.465` in `multi_op_high_interference` vs `0.839` for `jci_tsg`), reducing joint yield below baseline (`0.337` vs `0.474`). `tsg_scoped` intervention rendering retains full baseline functionality (`+0.095` to `+0.283` joint advantage over `jci_flat`).
3. **Within-Task Pairing Precision**: Paired counterfactual differences cut equivalent unpaired SE variance by `56.5%` to `82.9%` on joint yield (`SE` ~ `0.023`–`0.039` at `n_eval = 120`) without cross-fold linear shrinkage heuristics.
