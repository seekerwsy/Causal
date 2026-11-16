# Prompt Mechanism Study (`CausalGuide`)

Research codebase for **task-grounded prompt representations and Joint Causal Inference (JCI) mechanism discovery** in LLM code generation, normatively specified in [docs/jci-method.md](docs/jci-method.md):

1. **Contribution 1 — Task-Grounded Graph Representation (`Prompt TSG`)**: Scoped semantic graphs binding operations, shared `data_object` ownership paths (`part_of`), logical conditions, and propositions with tolerant span resolution and local `unresolved` semantics (`src/tsg/`); an 8-bit orthogonal structural mechanism vector `TSG_ORTHOGONAL_MECHANISM_NAMES`; operation-scoped prompt intervention rendering (`src/tsg/scoped_intervention.py`, preserving sibling operation contracts against unscoped flat bleed); and deterministic AST symbol splicing (`src/experiment/code_generation.py`).
2. **Contribution 2 — Joint Causal Mechanism Discovery & Paired Evaluation**: Strictly split-isolated ($D_{\text{disc}} \cap D_{\text{eval}} = \emptyset$) native-Python JCI-12 PAG discovery with post-generation outcome sinks (`src/discovery/jci_structure.py`, `src/discovery/mechanism_discovery.py`) separating true causal security drivers from environment/latent-confounded proxies and unscoped scope-bleed hazards, evaluated via Within-Task Paired Counterfactual ITT (`baseline`, `corr_tsg`, `jci_flat`, `jci_tsg`) with AST security Oracles and isolated Python unit tests (`src/measurement/unit_test_oracle.py`), audited end-to-end by independent verifiers (`src/verification/`).

Formal natural-task protocol activation remains `SPECIFIED_DRAFT` (`formal_claim_allowed=false`). Historical frozen archives under `data/method/`, `results/`, `archive/`, and `docs/experiments/` remain intact and read-only.

---

## Quickstart & Verification

Requires Python 3.12 (`pip install -e ".[dev]"`). No external R installation is required by default (`--rscript PATH` remains optional for R `pcalg 2.7.12`).

```powershell
$env:OPENBLAS_NUM_THREADS="1"; $env:OMP_NUM_THREADS="1"

# 1. Run default test suite (tests/jci scientific invariants + tests/substrate)
python -m pytest -q

# 2. Extract Stage I structural and orthogonal mechanism vectors from a Prompt TSG fixture
python -m prompt_mechanism_study study inspect-tsg src/fixtures/object-participation.json .artifacts/tsg-inspect

# 3. Run and verify the 8-cell JCI mechanism discovery & paired counterfactual smoke check
python -m prompt_mechanism_study study smoke .artifacts/smoke-check --workers 2
python -m prompt_mechanism_study study verify .artifacts/smoke-check --workers 2

# 4. Run and verify the offline 24-task (96 evaluations) multi-operation paired natural smoke check
python -m prompt_mechanism_study study natural-smoke .artifacts/natural-smoke-check
python -m prompt_mechanism_study study verify .artifacts/natural-smoke-check
```

---

## Active CLI Entry Point (`python -m prompt_mechanism_study study`)

| Command | Operation |
| --- | --- |
| `smoke OUTPUT [--rscript PATH] [--workers N]` | Run 8-cell JCI mechanism + paired simulation smoke check (`configs/jci-mechanism-smoke.json`) |
| `natural-smoke OUTPUT [--rscript PATH]` | Run offline 24-task multi-operation natural-task paired check (`configs/jci-natural-task-smoke.json`) |
| `run OUTPUT --plan PLAN [--rscript PATH] [--workers N]` | Execute a declared `mechanism_simulation` or `natural_task` (`offline_fixture` or `local_vllm`) plan |
| `verify OUTPUT [--workers N]` | Independently replay inputs, TSG/Oracle/unit-test checks, CI queries, PAGs, fits, and paired intervals |
| `inspect-tsg INPUT OUTPUT` | Compile `PromptTSG` source record (tolerant mode) and emit orthogonal & structural vectors |

Live `local_vllm` multi-operation pilot configuration: [configs/jci-local-vllm-pilot.json](configs/jci-local-vllm-pilot.json) paired with `$STUDY_ROOT`-relative runner [scripts/run_local_vllm_pilot.sh](scripts/run_local_vllm_pilot.sh).

---

## Current Verified Evidence Summary

| Artifact / Study | Scope | Key Verified Outcome |
| --- | --- | --- |
| [2026-11-16-jci-mechanism-paired-validation.md](docs/experiments/2026-11-16-jci-mechanism-paired-validation.md) | 48 simulation cells (`4,538` CI queries, `VERIFIED`) | `jci_tsg` beats `corr_tsg` (`+0.127` to `+0.147` joint, `9/12`–`11/12` sig) & `jci_flat` (`+0.095` to `+0.283` joint); **`0/12`** false positives (`100%` abstention) on `null_spurious_only` vs `12/12` for `corr`; `56.5%`–`82.9%` paired SE variance reduction |
| [2026-11-16-jci-mechanism-paired-validation.md](docs/experiments/2026-11-16-jci-mechanism-paired-validation.md) | Live `Qwen2.5-Coder-32B-Instruct` 24-task / 96-call run (`$STUDY_ROOT`, `VERIFIED`, `formal_claim_allowed=false`) | **`jci_tsg`: `0.917` (`22/24`) joint success** (`100%` sec, `91.7%` func) vs `baseline` `0.292` ($\hat{\Delta}=+0.625, p=6.10\times 10^{-5}$), `corr_tsg` `0.000` ($\hat{\Delta}=+0.917, p=4.77\times 10^{-7}$), and `jci_flat` `0.125` ($\hat{\Delta}=+0.792, p=3.81\times 10^{-6}$) |
| [2026-11-16-jci-grouped-crossfit-results.md](docs/experiments/2026-11-16-jci-grouped-crossfit-results.md) | Archived pre-consolidation unpaired baseline (`48` cells, `VERIFIED`) | Preserved read-only reference for legacy directional shrinkage prior to Direction 1 refactoring |

---

## Documentation Map

- [docs/jci-method.md](docs/jci-method.md): Normative specification of the Direction 1 two-stage method.
- [docs/reviewer-guide.md](docs/reviewer-guide.md): Stage invariants, reproduction commands, and 10-file core reading order.
- [tests/README.md](tests/README.md): Scientific invariant and substrate test suite documentation.
- [docs/experiments/historical-development-ledger-202610-202611.md](docs/experiments/historical-development-ledger-202610-202611.md): Archived Oct–Nov 2026 development chronology and frozen SHA-256 pointers.
- [paper/fse2027/](paper/fse2027/README.md): Anonymous ACM TOSEM manuscript draft synchronized with Direction 1 and verified formative 32B multi-operation results (`formal_claim_allowed=false`; prospective multi-model cells `\pendingresult`).
