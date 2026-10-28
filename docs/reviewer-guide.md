# JCI reviewer guide

The active specification is [the JCI method](jci-method.md). The entry point is
`python -m prompt_mechanism_study study smoke OUTPUT --rscript PATH_TO_RSCRIPT`.
Use Python 3.12 with `pip install -e ".[dev]"`, R with pcalg 2.7.12 and jsonlite,
and `OPENBLAS_NUM_THREADS=1`, `OMP_NUM_THREADS=1`. Run from the repository root.

The declared SCM reproduction executes four learning repetitions with real
conservative FCI. Verify with `study verify-jci-reliability OUTPUT --workers 2`.
Run the default suite with `python -m pytest -q --rscript=PATH_TO_RSCRIPT`.
The result remains `NON_CLAIM_METHOD_REPRODUCTION`.

## Stage records

| Stage | SCM records | Real-outcome replay records |
| --- | --- | --- |
| Representation | `training` and `calibration` source/task/count fields | `inputs/design.json` and original prompt metadata |
| Prioritization | `structure` graphs, CI queries and guarded penalties | `learned` effects, family graphs and rankings |
| Hypothesis freeze | `inputs/plan.json`, `identity.json`, `source.zip` | Frozen plan, design, original input hashes and `source.zip` |
| Intervention/randomization | Exact task/role/assignment replay | Budgeted original physical request identities |
| Measurement | Integer success counts and response proportions | Original terminal outcomes, unknowns and finite-function checks |
| Outcome assembly | All fit candidates, CAL roles, choices and exact values | Fixed slots, separate confirmation and final test records |
| Inference/reporting | `summary/result.json`, `verification/result.json` | Task-level summary and independent verification |

Each cell and summary is a canonical, exact-byte verified bundle. Source archives
bind execution implementation; independent verifiers retain their own identity.
Existing frozen results keep their evidence scope and are verified independently
of the current source layout. Reproduction writes a new output directory.

## Core reading order

1. `docs/jci-method.md`: variables, seven stages and evidence boundaries.
2. `src/cli.py`: explicit commands.
3. `src/discovery/jci_structure.py`: shared CI and backend.
4. `src/discovery/jci_reliability.R`: actual conservative FCI and JCI constraints.
5. `src/discovery/jci_reliability.py`: randomized counts, effect fits and CAL choices.
6. `src/discovery/policy_value.py`: common features, baseline actions and exact values.
7. `src/experiment/jci_reliability.py`: frozen execution and simultaneous comparisons.
8. `src/verification/jci_reliability.py`: independent numerical reconstruction.
9. `src/experiment/jci_replay.py`: real-outcome discovery, confirmation and testing.
10. `src/verification/jci_replay.py`: independent real-outcome replay verification.

The 2026-10-14 full study remains a bounded computational method check; its 384
simultaneous intervals all include zero. The real-outcome budget replay remains
post-hoc. Archived Atomic studies and their original commands are reproduced with
the matching source at `main` commit `d304d4ec` or their frozen source archive.
