# Reviewer Guide

This guide maps the active Direction 1 framework specified in [docs/jci-method.md](jci-method.md) to its single CLI entry point, stage invariants, reproduction commands, and a 10-file core reading order.

## Single Active Entry Point & Reproduction

Install with Python 3.12 (`pip install -e ".[dev]"`), set `OPENBLAS_NUM_THREADS=1` and `OMP_NUM_THREADS=1`, and run from the repository root (no external `Rscript` required by default; `--rscript PATH` remains optional for R `pcalg 2.7.12` replay):

```powershell
python -m pytest -q
python -m prompt_mechanism_study study inspect-tsg src/fixtures/object-participation.json .artifacts/tsg-inspect
python -m prompt_mechanism_study study smoke .artifacts/smoke-check --workers 2
python -m prompt_mechanism_study study verify .artifacts/smoke-check --workers 2
python -m prompt_mechanism_study study natural-smoke .artifacts/natural-smoke-check
python -m prompt_mechanism_study study verify .artifacts/natural-smoke-check
```

To reproduce the complete 48-cell mechanism discovery & paired counterfactual simulation benchmark (`configs/jci-mechanism-validation.json`):

```powershell
python -m prompt_mechanism_study study run results/NEW_RUN --plan configs/jci-mechanism-validation.json --workers 4
python -m prompt_mechanism_study study verify results/NEW_RUN --workers 4
```

To run the bounded live `local_vllm` multi-operation pilot on a compute server under `$STUDY_ROOT`:

```bash
export STUDY_ROOT=/path/to/study
export LOCAL_VLLM_BASE_URL=http://127.0.0.1:8000/v1
export LOCAL_VLLM_MODEL_ID=Qwen2.5-Coder-7B-Instruct
bash scripts/run_local_vllm_pilot.sh
```

---

## Stage Invariants & Active Records

| Stage / Component | Active Invariant & Records |
| --- | --- |
| **Stage I: Prompt TSG & Tolerant Grounding** | `compile_source_propositions(..., tolerant=True)` with `resolve_evidence_span` whitespace/backtick recovery and local `unresolved` fallback; `part_of` ownership paths; 8 orthogonal mechanism predicates `TSG_ORTHOGONAL_MECHANISM_NAMES`. |
| **Stage I: Scoped Intervention & AST Splicing** | `render_prompt_intervention` distinguishes `baseline`, unscoped `flat`, and `tsg_scoped` (binding only target operation/`part_of` inputs and protecting sibling contracts); `splice_target_unit_code` extracts one code block and splices deterministically by AST symbol. |
| **Stage II: JCI PAG with Temporal Sinks** | Strict split isolation ($D_{\text{disc}} \cap D_{\text{eval}} = \emptyset$). `discover_jci_pag(..., context_vars, sink_vars)` initializes exogenous root tails at $C = (C_{\text{env}}, I)$ and temporal sink arrowheads at $Y = (Y_{\text{sec}}, Y_{\text{func}})$ (forbidding sink-to-pre-gen tails). |
| **Stage II: Mechanism Classification** | `classify_jci_mechanisms` separates `causal_security_driver` ($Z_m \to Y_{\text{sec}}$), `latent_confounded_proxy` ($Z_k \leftrightarrow Y_{\text{sec}}$), `environment_confounded_proxy`, and `scope_bleed_hazard` ($I_{\text{flat}} \to Z_{\text{bleed}} \to Y_{\text{func}}$), abstaining cleanly in `null_spurious_only`. |
| **Paired Counterfactual ITT Evaluation** | Held-out $D_{\text{eval}}$ runs all 4 matched arms (`baseline`, `corr_tsg`, `jci_flat`, `jci_tsg`) per task unit, measuring AST security (`evaluate_security_profile`) and isolated unit tests (`evaluate_python_unit_tests`) over full ITT denominators. |
| **Independent Verification** | `study verify` replays RNG streams, CI permutation tables, PAGs, classifications, TSG compilations, AST splices, Oracles, unit tests, and paired Student-t/Bonferroni/McNemar statistics without importing production experiment/discovery pipelines. |

---

## Core Reading Order (10 Files)

1. [README.md](../README.md): Project entry point, quickstart, and verified evidence summary.
2. [AGENTS.md](../AGENTS.md): Project-wide scientific invariants and governance rules.
3. [docs/jci-method.md](jci-method.md): Normative specification of the Direction 1 framework.
4. [src/cli.py](../src/cli.py): Single 5-command CLI (`smoke`, `natural-smoke`, `run`, `verify`, `inspect-tsg`).
5. [src/tsg/prompt_contract.py](../src/tsg/prompt_contract.py): Tolerant evidence span resolver and local `unresolved` compiler.
6. [src/tsg/scoped_intervention.py](../src/tsg/scoped_intervention.py): Scope-bounded TSG directive renderer (`baseline` / `flat` / `tsg_scoped`).
7. [src/discovery/jci_structure.py](../src/discovery/jci_structure.py): `ConditionalPermutation` and native Python JCI-12 PAG discovery with `sink_vars`.
8. [src/discovery/mechanism_discovery.py](../src/discovery/mechanism_discovery.py): Causal mechanism classifier, policy derivation, paired counterfactual ITT evaluator, and 4-scenario simulator.
9. [src/experiment/natural_study.py](../src/experiment/natural_study.py): End-to-end offline fixture and live `local_vllm` natural-task study runner (with `src/measurement/unit_test_oracle.py`).
10. [src/verification/mechanism_discovery.py](../src/verification/mechanism_discovery.py): Independent simulation verifier (paired with [src/verification/natural_study.py](../src/verification/natural_study.py) for end-to-end natural tasks).
