# Archived: Schema-3 Selector Pipeline (2026-11-16)

This directory preserves the superseded natural-task orchestration from before the two-contribution consolidation. It is read-only reference material. It is not importable from the active package, and the default test suite does not run it.

## Why archived

The pipeline implemented an earlier method: outcome-blind candidate *prioritization* and selector scores, fixed slots, schema-3 complete-block randomization, Yield@K inference, and a seven-stage reviewer workflow. The active method replaces it as follows:

- Stage II directional JCI with cross-fitted residual scoring (`src/discovery/prognostic_learning.py`) replaces selector-based prioritization.
- Fold-nested assignment (`src/experiment/assignment.py`, design condition D1 in `docs/jci-method.md`) replaces schema-3 block randomization. Block randomization that is not nested in cross-fitting folds voids exact unbiasedness of the residual score.

## Contents

| Path | Former role |
|---|---|
| `src/target_workflow.py` | Seven-stage reviewer smoke / bounded development execution |
| `src/data/` | Frozen v4/v5 task-unit and contract verification, discovery population, eligibility, curation, qualification data, benchmark normalization |
| `src/discovery/{prioritization,mechanisms,selector_numerics,safe_yield}.py` | Selector scores, context-conditioned mechanism specs, ranking solver, safe-yield policy |
| `src/experiment/{inference,randomization,reporting,reviewer_fixture,study_design,study_planning}.py` | Schema-3 ITT inference, block randomization, tables, power planning |
| `src/verification/{design,effects,qualification,reporting,verifier,integrity}.py`, `jci_trace.R` | Independent replay for the schema-3 pipeline |
| `src/tsg/{source_calls,prepared_prompts}.py` | libcst call catalog; P0/P1 policy-expression prompt variants |
| `src/measurement/*` (13 modules) | Task-specific controlled command / session / redirect measurement adapters, unreachable from any entry point |
| `src/fixtures/{reviewer_smoke.json,local-llm-viewer.html}` | Reviewer workflow fixture; unused viewer |
| `tests/` | The 11 test modules of this pipeline, `tests/development/`, `tests/fixtures/`, plus the original (unstripped) `test_candidate_construction.py`, `test_open_prompt_tsg.py`, `test_security_profiles.py` |

The matching configs are in `configs/archive/legacy_pipeline_20261116/formal/`. Frozen results produced by this pipeline under `data/method/` and `results/` were not modified.

## Last observed status before archival

With the active CLI already reduced to `study`, the legacy top-level suite (run without `test_selector_study.py`, which imports the missing module `discovery.rq1_baselines`) gave `5 failed, 99 passed`. The 5 failures (`test_target_workflow.py` ×3, `test_task_unit_data.py` ×2) call removed CLI groups such as `data`.

## Kept in `src/` as natural-task substrate

`llm.py`; `tsg/` (prompt_tsg, prompt_contract, source_representation, task_input, source_codec, source_records, scope_assessment, prompt_contract_extract, prompt_contract_qualification, candidate_construction, representation, tsg_visualization); `measurement/{security_profiles,evaluate,functional_judge}.py`; `experiment/{code_generation,outcomes,assignment}.py`.
