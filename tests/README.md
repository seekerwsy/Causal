# Default Test Suite (`tests/jci/`, `tests/substrate/`)

Install the editable package in Python 3.12 (`.\.venv\Scripts\python.exe -m pip install -e ".[dev]"` or `python -m pip install -e ".[dev]"`), set `OPENBLAS_NUM_THREADS=1` and `OMP_NUM_THREADS=1`, and run:

```powershell
python -m pytest -q
```

The default suite needs no external `Rscript` binary. JCI-12 Partial Ancestral Graph discovery runs natively in Python (`prompt_mechanism_study.discovery.jci_structure.discover_jci_pag`). `--rscript` remains optional for R `pcalg 2.7.12` verification.

## Scientific invariants (`tests/jci/`)

- [test_contracts.py](jci/test_contracts.py): pre-execution contract guards (`formal_claim_allowed=false`, `new_provider_calls=0`, valid `study_mode`, valid `provider_mode`, `evaluator` validation for `local_vllm`, CI parameters) and the 5-action `study` CLI surface.
- [test_source_participation.py](jci/test_source_participation.py): uses [object-participation.json](../src/fixtures/object-participation.json) to verify `Prompt TSG` `part_of` ownership paths, local `unresolved` semantics, 16-predicate + 8-predicate orthogonal vectors (`TSG_ORTHOGONAL_MECHANISM_NAMES`), reliability gating, and `study inspect-tsg`.
- [test_mechanism_discovery.py](jci/test_mechanism_discovery.py): verifies:
  - JCI-12 PAG `sink_vars` temporal orientation (`I -> Z -> Y` via Zhang R1 vs `I -> Z <-> Y` collider vs `Z <- C -> Y` separation);
  - causal mechanism classification & abstention in `null_spurious_only`;
  - `resolve_evidence_span` + tolerant `compile_source_propositions` local degradation;
  - `render_prompt_intervention` (`baseline`, `flat`, `tsg_scoped`);
  - `evaluate_paired_counterfactuals` Student-t, Bonferroni, sign-test, and variance-reduction metrics;
  - end-to-end 8-cell `study smoke` + `study verify`, plus tamper rejection.
- [test_natural_study.py](jci/test_natural_study.py): verifies `evaluate_python_unit_tests`, end-to-end 12-task 4-arm paired `study natural-smoke` + `study verify`, `ProviderError` ITT retention under mocked `local_vllm`, and tamper rejection.

## Natural-task substrate (`tests/substrate/`)

- [test_artifacts.py](substrate/test_artifacts.py): canonical JSON and SHA-256 manifest bundle verification.
- [test_code_generation_contract.py](substrate/test_code_generation_contract.py): single fenced code block extraction and AST symbol splicing (`splice_target_unit_code`).
- [test_security_profiles.py](substrate/test_security_profiles.py): bounded local AST security profiles (`LOCAL_PROFILE_IDS`) and explicit `unknown` preservation.
