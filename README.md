# Prompt Mechanism Study (`CausalGuide`)

Research codebase for **task-grounded security requirement causal analysis** in LLM code generation, built around two core contributions normatively specified in [docs/jci-method.md](docs/jci-method.md):

1. **Task-Grounded Graph Representation (`Prompt TSG`)**: Scoped semantic graphs binding requirements to exact operations, `part_of` object-ownership chains, and logical conditions (`src/tsg/`), extracting pre-assignment relational attributes `Z = q(G_P, r)` with graceful local `unresolved` semantics while decoupling semantic representation from target-unit code splicing.
2. **Context-Anchored Directional JCI & Cross-Fitted Effect Learning**: Native-Python exogenous-context JCI-12 PAG discovery (`src/discovery/jci_structure.py`), canonical PAG role decomposition `(V_root, V_up, V_term, V_other)` with role-grouped shrinkage and `full_logit` fallback, and task-unit K-fold cross-fitted randomized residual estimation (`src/discovery/prognostic_learning.py`) paired with an independent verifier (`src/verification/prognostic_learning.py`).

Formal natural-task protocol activation remains `SPECIFIED_DRAFT` (`formal_claim_allowed=false`). All previously frozen experimental archives under `data/method/`, `results/`, `archive/`, and `docs/experiments/` remain intact and read-only.

---

## Quickstart & Verification

Requires Python 3.12 (`pip install -e ".[dev]"`). No external R installation is required by default (JCI-12 PAG discovery runs natively in Python; `--rscript PATH` remains optionally supported for R `pcalg 2.7.12`).

```powershell
$env:OPENBLAS_NUM_THREADS="1"; $env:OMP_NUM_THREADS="1"

# 1. Run default test suite (tests/jci scientific invariants + tests/substrate)
python -m pytest -q

# 2. Extract Stage I -> Stage II structural attributes from a Prompt TSG fixture
python -m prompt_mechanism_study study inspect-tsg src/fixtures/object-participation.json .artifacts/tsg-inspect

# 3. Run the 8-cell (4 scenarios x 2 seeds) directional JCI cross-fitting smoke check
python -m prompt_mechanism_study study smoke .artifacts/smoke-check --workers 2

# 4. Run the offline natural-task end-to-end smoke check (Stage I 16-predicate bridge -> D1 -> splice -> Oracle -> Stage II)
python -m prompt_mechanism_study study natural-smoke .artifacts/natural-smoke-check

# 5. Independently reconstruct and verify all RNG streams, CI queries, KKT residuals, and scores
python -m prompt_mechanism_study study verify .artifacts/smoke-check --workers 2
python -m prompt_mechanism_study study verify .artifacts/natural-smoke-check
```

---

## Active CLI Entry Point (`python -m prompt_mechanism_study study`)

| Command | Operation |
| --- | --- |
| `smoke OUTPUT [--rscript PATH] [--workers N]` | Execute 8-cell smoke run (4 scenarios incl. `misaligned_signal` negative control) using `configs/jci-directional-grouped-smoke.json` |
| `natural-smoke OUTPUT [--rscript PATH]` | Execute offline natural-task end-to-end smoke check using `configs/jci-natural-task-smoke.json` |
| `run OUTPUT --plan PLAN [--rscript PATH] [--workers N]` | Execute a declared directional JCI or natural-task (`study_mode: "natural_task"`) study plan |
| `verify OUTPUT [--workers N]` | Independently reconstruct inputs, TSG/Oracle records, CI queries, PAG roles, fits, and intervals |
| `inspect-tsg INPUT OUTPUT` | Compile `PromptTSG` source record and emit Stage I -> Stage II structural attributes (7-dim summary + 16 binary predicates) |

Superseded multi-track prototypes and plans are preserved in [archive/legacy_jci_20261116/](archive/legacy_jci_20261116/) and `configs/archive/legacy_jci_20261116/`. The superseded schema-3 selector pipeline (prioritization, schema-3 randomization and inference, reviewer workflow, frozen-data verifiers) is preserved in [archive/legacy_pipeline_20261116/](archive/legacy_pipeline_20261116/README.md). `src/` keeps only the two contributions and the natural-task substrate: Stage I extraction, fold-nested assignment (D1), generation, and Oracle/functional measurement.

---

## Current Verified Evidence Summary

| Artifact / Study | Scope | Key Verified Outcome |
| --- | --- | --- |
| [2026-11-16-jci-grouped-crossfit-results.md](docs/experiments/2026-11-16-jci-grouped-crossfit-results.md) | 48 simulation cells (`227,250` CI queries, `VERIFIED`) | `downstream_signal`: **10/10 passed** (`+13.06%` to `+17.57%` $\Delta\text{Var}$); `upstream_control`: **0 harms**, `+2.53%` to `+16.79%` (**7/10 passed**); `target_new_attribute`: `+2.25%` to `+5.33%` (0 harms) |
| [2026-11-16-negative-control-and-measurement-noise.md](docs/experiments/2026-11-16-negative-control-and-measurement-noise.md) | 2 × 64 formative simulation cells (`VERIFIED`) | `misaligned_signal` negative control: JCI reduces to `full_logit` (0/10 passed, 0 harms); at 10% attribute flips: **0/28 primary passed**, `downstream_gate_passed=false`, 0 harms (Stage I reliability is a precondition) |
| [2026-11-05-graph-jci-joint-results.md](docs/experiments/2026-11-05-graph-jci-joint-results.md) | Frozen Round 1 (384 simulation cells) + 240 local Qwen unified-diff calls | `JCI_ROUND1_SUCCESS` in `reference` `downstream_signal` (`+12.51%` to `+18.38%`, prior to role-grouped upstream fix); 240/240 local generation format failures (`JOINT_SCIENTIFIC_BOUNDED_UNMET`) |
| [finalization-20261110-executed](data/method/policy-expression-graph-65536-20261107/finalization-20261110-executed/FINAL_REPORT.md) | 120-assignment `P0/P1` cohort (6-call qualification gate) | 6/6 rejected pre-measurement (`delete_count > 16` or duplicate coordinate under native XGrammar); 114 remaining assignments `NOT_STARTED_BY_PREDECLARED_INTERFACE_GATE` |

---

## Documentation Map

- [docs/jci-method.md](docs/jci-method.md): Normative specification of the active two-stage method.
- [docs/reviewer-guide.md](docs/reviewer-guide.md): Stage invariants, reproduction instructions, and 10-file core reading order.
- [tests/README.md](tests/README.md): Scientific invariant test suite documentation.
- [docs/experiments/historical-development-ledger-202610-202611.md](docs/experiments/historical-development-ledger-202610-202611.md): Consolidated Oct–Nov 2026 development chronology and frozen SHA-256 pointers.
- [paper/fse2027/](paper/fse2027/README.md): Anonymous ACM TOSEM manuscript draft (`SPECIFIED_DRAFT`).
