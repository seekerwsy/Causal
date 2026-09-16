# Prospective research dataset contract

This document describes source admission and role capacity for the single
[active protocol](protocol.md).
It does not freeze a formal sample size, assign experimental roles, or authorize
data acquisition. Earlier 240/296-task layouts and 100-Atomic/170-Pair suggestions
are superseded planning history recoverable from Git.

## Source authority

`data/dataset-curation/reviewer-task-unit-dataset-v5` is the immutable source/contract
quality baseline. Its manifest SHA-256 is
`33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`.
It retains 2,165 task units: 720 quality-included, 1,284 excluded for insufficient
source specification and 161 excluded for source defects. Of the included tasks,
381 are Python. The active data-preparation population now includes all 2,165
tasks across the nine source languages and all three quality dispositions.
Existing mechanism bindings, Oracle readiness and method scores do not determine
which source tasks exist in that population. Current prompt-bound contracts and source-quality decisions come from the
independently reviewed `research-source-use-v2` preparation package described
below. Formal task-candidate admission is separate and remains unqualified.

The task unit is the highest independent sampling/resampling unit. Source
variants, paraphrases, repeated requests and multiple policies applied to a task
are dependent descendants. Frozen `semantic_cluster_id` names belong to curation
history and continue to identify those same units.

The structural data contract is [task-unit data](task-unit-data.md); source-only
contract review follows [contract content cleaning](contract-content-cleaning.md).
The immutable v5 baseline can be verified without replaying development history:

```text
prompt-mechanism-study curate finalize task-units verify data/dataset-curation/reviewer-task-unit-dataset-v5
```

## Disjoint roles

The formal manifest must distinguish `QUAL_DEV`, one-shot `QUAL_ACCEPT`,
`DISCOVERY`, `CONFIRMATION` and `LEGACY_ONLY`, with task-unit and near-duplicate
firewalls. Development exposure is recorded and cannot be erased by changing a
dataset name. Source-only curation alone is not a model-development exposure;
using task-level feedback to revise the method is.

The source-only review-candidate reservation bundle
`data/method/qwen37flash-qualification-source-review-candidates-v1` reserves 28
tasks for each qualification role, with manifest SHA-256
`1912f9c5cad5d43ddfdc44aff688c3eee62891184dc39aa6bb7e1a61ab4860ff`.
Those reservations do not constitute a complete formal role manifest or permit
an acceptance call. Their source labels, any subsequent development results,
and role authorization are separate records.

## Full-source preparation and candidate sufficiency

The current broad research pool is
`data/dataset-curation/research-candidate-pool-v4`, derived from the prepared
inputs below and the recorded qualification/development exposures. It includes
**1,954 independent tasks** across all nine languages: 775 complete, 1,178 partial
and one unresolved functional specification. The 1,179 non-complete specifications
are retained for task-relative functional review, not assigned unknown in advance.
It preserves 163 protected tasks outside this pool, leaves 47 unprotected source
defects pending correction, and retains one duplicate only as a dependent variant.
Thus all 2,165 source task identities remain accounted for.

The same pass reuses existing source evidence for context, security boundary and
non-target invariants: **144 Atomic task-policy combinations on 65 tasks** pass
these three axes. Original target-operation and control judgments are retained
for intervention review, not converted to success. Pair has no supported joint
source combination in the existing review book. Missing policy definitions and
Oracle support do not remove tasks from the broad pool. Pool membership is not
candidate eligibility or formal admission. See the
[current preparation record](experiments/2026-09-11-main-study-preparation.md) for
the original command, input identity and validation. The
[natural-source preflight](experiments/2026-09-16-tsg-natural-source-preflight.md)
adds eight prospectively recorded development exposures, taking the additional
exposure count from 33 to 41 and the Python pool from 692 to 684. All 30 additional exposures in
the [open-TSG development comparison](experiments/2026-09-11-open-tsg-effects.md)
are protected, including tasks that were not assigned experimental arms. The
earlier 1,995-, 1,992- and 1,962-task snapshots retain their original exposure boundaries.

`data/dataset-curation/research-source-use-v2` is the single active preparation
package. Its manifest SHA-256 is
`2015d760cbeaacff16e701ad25a507e5973960a31b0ecd7de8d4b769bf7a741c`.
It contains nine data files plus the exact-byte manifest. `prepared-tasks.json`
contains every actual prompt, unchanged parent task identity, language, near-duplicate
group, protected use and current measurement contract. `task-uses.json` records
current source quality, restrictions and pending requirements. `source-material.json`
contains inert source assets and exact recovery provenance.
`source-contract-reviews.json` carries eight complete independent review rounds;
`native-source-reviews.json`, `candidate-context-reviews.json` and
`candidate-source-reviews.json` preserve the separate source-only judgments.
`source-use-rule.json` fixes their rules and `report.json` records reproducible
counts, environment and input identities.

The package's frozen rule requires source-supported context, target operation, security boundary,
non-target invariants and arm compatibility for each exact Atomic or Pair policy.
Missing facts remain unresolved; Pair review does not require selected Atomic
parents. A partially specified task may pass this source-only rule while complete
functionality remains unknown. Source defects require correction and independent
review. Passing source sufficiency alone grants no representation, intervention,
Oracle or formal design qualification.

The prospective revision in [protocol Section 19](protocol.md#19-prospective-sample-size-and-data-gate)
separates three source axes (context, operation/security boundary and non-target
invariants) from operation and control design. The frozen package remains the
current prepared input source, with its original review counts; it has not been
rescored under the revision. Its builder/verifier reproduce the earlier rule only.
The [bounded development check](experiments/2026-09-10-proportional-prototype.md)
uses already exposed material to examine the new semantics before any expanded
qualification or formal admission.

The executed preparation and independent byte replay cover all 2,165 tasks and
2,283 source members. Original source quality and role files are unchanged.
SeCodePLT's upstream default prompt includes the function name, security policy
and setup code; the earlier import omitted parts of these original inputs.
The package records 134 restored input candidates, applies 124 to unexposed,
unreserved tasks, and withholds 10 to preserve frozen role/reservation inputs.
Each applied restoration retains its parent task and has fresh independent
source-contract review; it cannot inherit the old prompt's qualification.
No independent task is added.

An additional 893 original asset references are recovered: 765 CodeSecEval
functional-test/security-test/entry-point references and 128 SeCodePLT setup or
dependency references. There are now 1,645 bindings to 1,458 unique byte assets
across 606 tasks. Source test roles are upstream declarations, not verified coverage;
reference answers are excluded and no source code is executed.

| Preparation boundary | Tasks |
|---|---:|
| All Python sources | 853 |
| All non-Python sources | 1,312 |
| Preserve existing QUAL_DEV / LEGACY_ONLY | 25 / 41 |
| Preserve QUAL_DEV / QUAL_ACCEPT reservations | 28 / 28 |
| Unexposed and unreserved, before any eligibility decision | 2,043 |
| Independent near-duplicate groups in that remainder | 2,042 |
| Originally quality-included in that remainder | 638 |
| Of those: Python / other languages | 306 / 332 |
| Of those: unchanged input / restored input | 584 / 54 |
| Currently source-quality included in that remainder | 789 |
| Of those: Python / other languages | 397 / 392 |

The four authorized cohorts were processed in order, with disjoint task membership:

| Cohort | Tasks | Current source quality: included / insufficient / defect |
|---|---:|---|
| Restored upstream inputs | 124 | 88 / 31 / 5 |
| Unchanged insufficient sources with native assets | 124 | 61 / 61 / 2 |
| Other unchanged insufficient sources | 1,055 | Original insufficient quality retained |
| Unchanged source defects | 156 | 56 / 60 / 40 |

The first, second and fourth cohorts have 404 current contracts that are faithful,
evidence-supported and terminal after independent review and required repairs.
The third cohort received candidate-level review while retaining its source
quality. Across all 2,165 tasks, current quality is 871 included, 1,246 insufficient
and 48 source defects. The corresponding functional scope is 871 complete, 1,245
partial and 49 unresolved; these are specification scopes, not observed functional
success. The 789 available quality-included tasks comprise 584 unchanged tasks
outside this follow-up and 205 included tasks from the reviewed cohorts.

All 1,459 cohort tasks have context screening over all 22 frozen proposal groups
(32,098 group decisions) and 1,482 required candidate records. Eleven Atomic
records on 11 distinct tasks pass source sufficiency only; no Pair record passes.
The proposal book contains 48 Atomic and eight Pair proposals
with concrete definitions currently limited to Python. All 964 retained non-Python
tasks in this follow-up have explicit missing-definition states (21,208 group
decisions). They are not declared semantically inapplicable. Likewise,
`NO_SOURCE_CONTEXT` means no supported context in this finite book, not feature
absence or universal ineligibility. Pair review is independent of Atomic selection
or support. The other 584 available tasks still need this candidate review.

Native content review covers 284 tasks and all 662 of their bindings. It records
450 functional-assertion mappings and 123 security-assertion mappings, each tied to
exact source and asset evidence. Mappings do not establish passing tests or complete
coverage; no source asset was executed and no measurement qualification was granted.
The preparation retains every source-quality disposition, adds no task units and
has zero formal admissions. Source-CWE routing remains diagnostic and cannot
replace these semantic judgments.

`measure_generated_code` now parses exact source in Python, C, C++, C#, Go, Java,
JavaScript, PHP and Rust through the same measurement path. Python uses AST/compile;
the other languages use pinned Tree-sitter grammars from the `languages` extra.
These are nonexecuting syntax checks, not compiler, security or functional
qualification. Profiles must match the source language before generation.
An incomplete or restored-unreviewed source keeps functionality and joint success
unknown even if independently measured security is evaluable. Non-Python target
interventions and security/functional qualification remain pending.

After installing `.[dev,selectors,languages]`, independently verify the released
prepared inputs, role firewall, current contracts, complete review lineage, source
assets and counts:

```text
prompt-mechanism-study curate finalize source-use data/dataset-curation/reviewer-task-unit-dataset-v5 data/method/qwen37flash-qualification-source-review-candidates-v1 data/method/prompt-tsg-catalog-source-contract-v2.json data/method/phase-context-policy-v3-mechanism-registry-v1.json data/dataset-curation/research-source-use-v2
```

Without raw source locations this reports `SOURCE_USE_STRUCTURE_VERIFIED`. The
report's `reproduction.command` records the exact producer invocation, seven
source roots, two pinned archives and review inputs; use a new output directory
to reproduce preparation. Add the recorded `--source-root` and `--source-archive`
arguments to the verification command above for full `SOURCE_USE_VERIFIED`
replay. Review-lineage verification reads the complete embedded judgments and
does not require the original development review directories.
The recorded environment is Python 3.12.13 on Windows 11 build 26200. Parser
versions and producer-file hashes are recorded in the package. No provider calls,
new roles or scientific effects were produced.

Validation on 2026-09-10 used a fresh Python 3.12.13 environment with a
non-editable installation of `.[dev,selectors,languages]`. The retained suite uses
the released v2 preparation and then-current configuration references. The commands
below record that historical validation, before the minimum-suite cleanup; current
checks use the [test guide](../tests/README.md). Its exact command was:

```text
python -m pytest -q -o addopts= -o cache_dir=.tmp/sequential-source-review-20260909/v2-release-pytest-cache --basetemp .tmp/sequential-source-review-20260909/v2-release-test-01
```

Use a new temporary output directory for a new run. A default-temp attempt was
blocked during fixture setup by existing Windows directory permissions; the
command above keeps temporary files and cache in the workspace.
The full run passed 272 checks and found one obsolete test assumption: it searched
for an unreviewed restored contract, while v2 has reviewed all 124 restorations.
The existing test now replaces a current reviewed-contract reference with its
original v5 reference and verifies rejection. Its focused rerun passed, completing
validation of all 273 retained checks:

```text
python -m pytest -q -o addopts= -p no:cacheprovider --basetemp .tmp/sequential-source-review-20260909/v2-restored-contract-recheck "tests/test_datasets.py::test_released_source_use_replays_and_rejects_permission_drift[restored_contract]"
```

The installed-package commands `study smoke` and `study verify-result` ran against
`.tmp/sequential-source-review-20260909/final-reviewer-smoke`.
The seven-stage smoke produced 80 assignments, measurements and outcomes across
20 synthetic task units; independent verification returned
`TARGET_RESULT_BUNDLE_VERIFIED`. The artifact remains `NON_CLAIM_TEST_ARTIFACT`,
with zero provider calls. Its bundle SHA-256 is
`3c63bb76176af0f344b40cab8e388917005a9d7895e7e57d29e9afcb7a8e073e`.

## Prior bounded Python capacity diagnostic

`qualification_data.summarize_source_role_capacity` verifies both source and
reservation bundles, reads source quality, CWE routing and exposure metadata,
and counts the prior 21-CWE residual population. It does not read Prompt TSG results,
candidate ranks, generated code, experimental arms or outcomes. The checked
2026-09-07 census is:

| Population | Task units |
|---|---:|
| Quality-included Python | 381 |
| In the current 21-CWE layer | 227 |
| Unexposed before the qualification reservations | 211 |
| Reserved in the two qualification candidates | 56 |
| Prior scoped residual capacity before candidate eligibility | 155 |

The 155 residual tasks also have 155 distinct near-duplicate groups.

| Source family | Residual task units |
|---|---:|
| Injection/interpreter | 64 |
| File/parser/external resource | 52 |
| Identity/authorization/permissions | 25 |
| Cryptography/randomness/integrity | 14 |

These remain reproducible subset diagnostics, not the active full-source selection
rule. They are pre-eligibility upper bounds. A policy scoped to one CWE or context
cannot treat the entire pool as eligible. Actual support additionally requires
qualified representation, context/operation-source rules, independent Oracle
coverage, complete arm protocolization, realization support and frozen folds.
No candidate-specific Confirmation population has passed those checks.

## Capacity and power gates

Formal task counts must come from an accepted task-level power simulation of the
actual weighted family bootstrap. The former Gaussian planning figures no longer
qualify any sample size. The study cannot currently claim either that 155 tasks
are sufficient or that a particular new acquisition count is scientifically required.
Global counts cannot replace candidate-specific eligibility, and extra request
slots cannot create independent task units.

Discovery supplementation is optional pre-Discovery preparation only. After
representation qualification and a frozen outcome-blind coverage target, D0 may
use one bounded round of independently sourced natural tasks. It may not use
paraphrases, synthetic cell filling, interventions, outcome/selector scores or
relation support to choose acquisitions. D0 does not supply or relabel a
Confirmation population. Any separate Confirmation acquisition or scope change
needs a prospective source/role decision before its outcomes.

An authorized D0 round keeps its original role manifest and appends new Discovery
bindings in a successor manifest. The receipt binds both versions; all existing
bindings, qualification identities, Confirmation reservations and exposure records
remain exact. New units must match the receipt, be independent of every existing
role, and lie within the frozen qualification/source scope.

Power planning now supports exact task-effect membership, including partial
overlap. Before Confirmation, the existing preflight reconstructs actual support
and realization allocation and reruns the frozen assumptions. This changes no
target power, K, task counts, margins or budget after Discovery. Failure blocks
execution; it does not justify replacing tasks or hypotheses. This capability
does not establish that the present source capacity has adequate scientific power.

The present status is blocked on qualification, candidate coverage, role allocation
and the scientific power/budget freeze. No source records, exclusions or historical
results are changed to make a numerical target pass.

The [data preparation follow-up](experiments/2026-09-09-data-preparation-next-steps.md)
records an import repair for five additional source records, a mislabeled external
snapshot, and a metadata-only worklist. These pending records and source inventories
do not change the frozen v5 population. The five additional records remain outside
the 2,165-task preparation package; the 155-task count above retains its prior scope.
