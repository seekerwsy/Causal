# Default Test Suite (`tests/jci/`, `tests/substrate/`)

Install the editable package in Python 3.12 (`.\.venv\Scripts\python.exe -m pip install -e ".[dev]"` or `python -m pip install -e ".[dev]"`), set `OPENBLAS_NUM_THREADS=1` and `OMP_NUM_THREADS=1`, and run:

```powershell
python -m pytest -q
```

The default suite needs no external `Rscript` binary. JCI-12 Partial Ancestral Graph discovery runs natively in Python (`prompt_mechanism_study.discovery.jci_structure.discover_jci_pag`). `--rscript` remains optional for R `pcalg 2.7.12` verification.

## Scientific invariants (`tests/jci/`)

- [test_contracts.py](jci/test_contracts.py): pre-execution contract guards (`formal_claim_allowed=false`, `new_provider_calls=0`, unique `batch_seeds`, strictly positive penalties, non-negative structure strengths, `target_folds >= 2`, valid conditioning orders) and the single 4-action `study` CLI surface.
- [test_source_participation.py](jci/test_source_participation.py): uses the natural-task fixture [object-participation.json](../src/fixtures/object-participation.json) to check:
  - Stage I `Prompt TSG` `part_of` ownership paths and operation participant distinction;
  - explicit incomplete bindings, and rejection of cyclic or mistyped composition;
  - the Stage I → Stage II `extract_tsg_structural_attributes` bridge, with local `unresolved` preservation;
  - `study inspect-tsg`.
- [test_prognostic_learning.py](jci/test_prognostic_learning.py): checks:
  - native JCI-12 PAG recovery of the roles `(V_root, V_up, V_term, V_other)`;
  - uniform fallback on cyclic or conflicted PAGs;
  - zero-leakage, finite-sample-unbiased task-unit cross-fitting;
  - the `misaligned_signal` negative control, whose outcome loads only on true `V_other`;
  - an 8-cell `study smoke` with independent `study verify`, plus rejection of a forged summary verdict.
- [test_assignment_design.py](jci/test_assignment_design.py): checks:
  - fold-nested assignment under design condition D1: within-fold balance, exact 1/2 marginals, determinism, and an independent replay that rejects tampering;
  - ITT endpoint separation: `unknown` is never coerced to insecure or absent, and terminal no-code assignments stay in the denominator.

## Natural-task substrate (`tests/substrate/`)

Stage I source extraction, contract/TSG compilation, qualification replay, candidate construction, the TSG viewer, artifact bundles, and AST Oracle security profiles (`test_task_input.py`, `test_open_prompt_tsg.py`, `test_source_inventory_*.py`, `test_candidate_construction.py`, `test_representation.py`, `test_artifacts.py`, `test_security_profiles.py`, shared `annotation_fixture.py`).

## Historical notes

- Superseded multi-track JCI prototype tests are preserved under [archive/legacy_jci_20261116/](../archive/legacy_jci_20261116/).
- Tests of the superseded schema-3 selector pipeline (`target_workflow`, prioritization, schema-3 inference/randomization, frozen v4/v5 data verification), together with `tests/development/`, are preserved under [archive/legacy_pipeline_20261116/tests/](../archive/legacy_pipeline_20261116/tests/).
- The original versions of the three substrate files whose legacy-dependent tests were removed are preserved alongside them.
