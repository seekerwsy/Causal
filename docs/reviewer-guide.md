# Reviewer Guide

This guide maps the active two-stage method specified in [docs/jci-method.md](jci-method.md) to its single CLI entry point, stage invariants, verification commands, and a 10-file core reading order.

## Single Active Entry Point & Reproduction

Install with Python 3.12 (`pip install -e ".[dev]"`), set `OPENBLAS_NUM_THREADS=1` and `OMP_NUM_THREADS=1`, and run from the repository root (no external `Rscript` required by default; `--rscript PATH` remains optional for R `pcalg 2.7.12` replay):

```powershell
python -m pytest -q
python -m prompt_mechanism_study study inspect-tsg src/fixtures/object-participation.json .artifacts/tsg-inspect
python -m prompt_mechanism_study study smoke .artifacts/smoke-check --workers 2
python -m prompt_mechanism_study study verify .artifacts/smoke-check --workers 2
```

To reproduce the complete 48-cell bounded simulation validation (`configs/jci-directional-grouped-validation.json`):

```powershell
python -m prompt_mechanism_study study run results/NEW_RUN --plan configs/jci-directional-grouped-validation.json --workers 8
python -m prompt_mechanism_study study verify results/NEW_RUN --workers 8
```

`--workers` changes process scheduling only; random streams are deterministically indexed by `(batch_seed, scenario_index, repetition, role)`.

---

## Stage Invariants & Active Records

| Stage / Component | Active Invariant & Records |
| --- | --- |
| **Stage I: Prompt TSG** | Character-verified source spans, `part_of` ownership paths, local `unresolved` preservation, semantic links distinct from causal edges; relational attributes emitted by `extract_tsg_structural_attributes`. |
| **Stage II: JCI PAG Discovery** | Outcome-free JCI-12 PAG discovery on `(C, Z)` (`discover_jci_pag`), direction-validity guard, canonical role partition `(V_root, V_up, V_term, V_other)` with uniform fallback when cyclic/conflicted. |
| **Stage II: Cross-Fitted Estimator** | Source 3-fold CV selects role-grouped L2 shrinkage weights; target deterministic K-fold cross-fitting (`I_0..I_{K-1}`, independent of `A, Y`) adapts with `full_logit` fallback and scores `R_i = 2(2A_i - 1)[Y_i - g_hat^{(-k)}(X_i)]`. |
| **Measurement & ITT Accounting** | Primary `secure_code_yield` (`Y = Y_C * Y_E * I{secure}`) remains distinct from `Y_C`, `Y_E`, local functionality, `unknown` states, and drift; every committed assignment remains in the ITT denominator. |
| **Independent Verification** | `study verify` replays RNG draws, CI permutation tables, PAG roles, logistic KKT residuals, Ridge normal equations, risk integration, and Bonferroni intervals without importing production fitting code. |

---

## Server Execution & Archived Frozen Packages

When reproducing archived packages on a Linux compute host, keep all inputs, outputs, and archives under `$STUDY_ROOT` (`$STUDY_ROOT/inputs`, `$STUDY_ROOT/results`, `$STUDY_ROOT/archive`) with `OPENBLAS_NUM_THREADS=1` and `OMP_NUM_THREADS=1`. Historical frozen archives remain immutable with their self-contained `source.zip` snapshots and standalone verifiers:

- **2026-11-16 Role-Grouped Cross-Fit Validation**: [2026-11-16-jci-grouped-crossfit-results.md](experiments/2026-11-16-jci-grouped-crossfit-results.md) (`results/jci-grouped-crossfit-20261116`).
- **2026-11-05 Frozen Joint Package & Round 1**: [2026-11-05-graph-jci-joint-results.md](experiments/2026-11-05-graph-jci-joint-results.md) (4-regime 384-cell JCI Round 1 + 240-call unified-diff evaluation).
- **2026-11-10 Physical-Line Array Qualification Gate**: [FINAL_REPORT.md](../data/method/policy-expression-graph-65536-20261107/finalization-20261110-executed/FINAL_REPORT.md) (`QUALIFICATION_GATE_FAILED`, 114 assignments unstarted, `formal_claim_allowed=false`).

---

## Core Reading Order (10 Files)

1. [README.md](../README.md): Project entry point, quickstart, and evidence status.
2. [AGENTS.md](../AGENTS.md): Project-wide scientific invariants and governance rules.
3. [docs/jci-method.md](jci-method.md): Normative specification of the active two-stage method.
4. [src/cli.py](../src/cli.py): Single 4-command CLI (`smoke`, `run`, `verify`, `inspect-tsg`).
5. [src/tsg/prompt_tsg.py](../src/tsg/prompt_tsg.py): Canonical `Prompt TSG` schema, `part_of` ownership paths, and scoped binding readouts.
6. [src/tsg/source_representation.py](../src/tsg/source_representation.py): Stage I -> Stage II structural attribute bridge (`extract_tsg_structural_attributes`).
7. [src/discovery/jci_structure.py](../src/discovery/jci_structure.py): `ConditionalPermutation` and native Python JCI-12 PAG discovery (`discover_jci_pag`).
8. [src/discovery/prognostic_learning.py](../src/discovery/prognostic_learning.py): PAG role decomposition `(V_root, V_up, V_term, V_other)`, role-grouped shrinkage, K-fold cross-fitting, and the four simulation regimes, including the `misaligned_signal` negative control.
9. [src/verification/prognostic_learning.py](../src/verification/prognostic_learning.py): Independent numerical verifier that recomputes all summary verdicts. Design condition D1 is implemented in [src/experiment/assignment.py](../src/experiment/assignment.py) and replayed independently in [src/verification/assignment.py](../src/verification/assignment.py).
10. [docs/experiments/2026-11-16-negative-control-and-measurement-noise.md](experiments/2026-11-16-negative-control-and-measurement-noise.md): Latest formative stress tests (negative control, 10% attribute noise). The earlier 48-cell validation is in [2026-11-16-jci-grouped-crossfit-results.md](experiments/2026-11-16-jci-grouped-crossfit-results.md).
