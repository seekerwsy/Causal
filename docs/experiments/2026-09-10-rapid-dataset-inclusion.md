# Rapid dataset inclusion

Date: 2026-09-10. Owner request: quickly include every usable task under the
relaxed research-prototype requirements. This is source preparation, with zero
provider calls, no new semantic annotations and no formal experimental admission.

## Result

The pass accounts for all **2,165** prepared source tasks:

| Disposition | Tasks |
|---|---:|
| Included independent research-pool representatives | 1,995 |
| Protected development, legacy or qualification inputs preserved | 122 |
| Unprotected source defects pending correction | 47 |
| Dependent source variant retained without another independent count | 1 |

Included functional scopes are **788 complete, 1,206 partial and one unresolved**.
Thus 1,207 tasks are retained despite incomplete or unresolved functional
specifications. Full functionality and joint success remain unknown where needed.
The unresolved C# rotation task is interpretable but lacks a resolved structured
functional contract; it remains in the pool with that limitation. No requirement
or security boundary was invented to turn it into an eligible intervention.

All nine languages remain: Python 724, C 274, C++ 243, JavaScript 212, C# 169,
Rust 122, PHP 119, Java 116 and Go 16. Missing language-specific interventions,
Oracle support or policy definitions do not exclude natural sources from this pool.
Within each near-duplicate group the lexicographically first usable task ID is
the representative. This choice uses no outcome, selector rank or relation support.

The pass also reuses all **1,482 existing candidate reviews**. Context, security
boundary and non-target invariants support **218 Atomic task-policy combinations
on 97 tasks**. These include ADD and REMOVE proposals; the original operation
states are not changed, so this does not establish that both operations apply.
An additional 1,064 combinations retain unresolved source judgments, 162 retain
source contradictions and 38 belong to tasks outside the independent pool.
No Pair combination passes the three source axes in this existing book.
That says nothing about all possible Pair definitions or interactions.

The old five-axis result of 11 supported combinations remains unchanged in its
frozen package. The 218 count is a new projection onto the three source axes,
not an assertion that 207 interventions have now qualified. All target-operation,
arm-compatibility, representation, Oracle and formal design requirements remain
visible for the applicable candidate. No old unknown was turned into absence.

## Artifact and reproduction

Input: `data/dataset-curation/research-source-use-v2`, manifest SHA-256
`2015d760cbeaacff16e701ad25a507e5973960a31b0ecd7de8d4b769bf7a741c`.
Output: `data/dataset-curation/research-candidate-pool-v1`, manifest SHA-256
`ea8f290ef7a3eb7e27cc1a75587af0eb21d787a6234179bd31b8c70738916a29`.

- `tasks.json`: the 1,995 complete prepared task records, unchanged from the input.
- `screening.json`: all 2,165 membership decisions, limits and representative IDs.
- `candidate-screens.json`: all 1,482 projections, exact policy identities,
  original design states and source-review hashes.
- `report.json`: counts, explicit screening rule, input and implementation hashes.

The existing preparation module implements `screen_prepared_source_pool`; the
existing CLI exposes it directly. The frozen source-use preparation remains the
upstream input, not a competing live method. No new acquisition, corpus-wide LLM
review, source restoration or role assignment was performed.

Reproduction in the current Windows/Python 3.12.13 reviewer environment:

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
$poolPython = '.tmp/sequential-source-review-20260909/final-reviewer-env/Scripts/python.exe'
& $poolPython -m prompt_mechanism_study.cli curate prepare candidate-pool data/dataset-curation/research-source-use-v2 .tmp/replayed-research-candidate-pool --qualification-manifest configs/formal/qualification_data_manifest.json
& $poolPython -m pytest tests/test_datasets.py -k 'prepared_pool or candidate_source or candidate_context' -q -p no:cacheprovider --basetemp=.tmp/replayed-pool-tests
```

This is the current command, which also protects subsequent method exposures;
it now yields 1,992 tasks as documented in the [successor preparation](2026-09-11-main-study-preparation.md).
The 1,995-task output above remains the frozen result of the original pass.
Use a new output directory. The original focused run passed **4 tests**, with 26 unrelated
tests deselected. The pool test independently derives representative membership
from the frozen source dispositions, checks protected roles and unchanged task
records, retains complete/partial/unresolved scopes, and verifies each candidate
projection without modifying its design judgments. Output byte integrity was
also verified. This verifies the quick reuse of existing evidence; it is not a
new independent semantic review of every prompt or an experiment result.
