# Gate E readiness and evidence audit

**Cutoff:** 2026-08-30

**Role:** implementation and evidence status only. This file is not a second
method contract. The sole normative protocol remains
[`2026-08-20-context-conditioned-intervention-policy-framework.md`](superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).

## Decisions applied to the implementation plan

The feedback plan was adopted with four explicit scope corrections:

1. The paper may present three macro stages, while the artifact retains the
   seven auditable stages required by `AGENTS.md`.
2. `Target - operation-matched No-op` remains the primary atomic estimand.
   An unedited Original prompt is not silently added to an arm family after
   outcomes have been inspected. It may be added only by a later prospective
   arm-family freeze.
3. Pair selection is operation-aware and aligned to the risk-difference
   estimand. The ridge-logit interaction coefficient is a diagnostic, not the
   ranking target or randomized effect estimate.
4. A pair result is first a Prompt-policy response-surface result. A mechanism
   interaction claim additionally requires a pre-randomization
   `mechanism_eligible` scope; statistical significance cannot upgrade a
   `policy_only` pair.

These are protocol choices, not interpretations of a new outcome.

## Gate status

| Gate | Status | Evidence and exact boundary |
| --- | --- | --- |
| A — Protocol-complete | **PASS** | One normative spec maps hypothesis, discovery state, selector, eligible population, policy, estimand, evidence status, and permitted claim. Pairwise-only scope, task-bound background, per-pair fitting, operation coding, factorial compatibility, Original-arm boundary, and policy/mechanism claim scope are explicit. |
| B — Method-complete | **PASS under the revised protocol** | Atomic selector schema 2.1 embeds catalog/prompt/Prompt TSG evidence and recomputes states; `association.v3` is operation- and expected-direction-aware; pair selector schema 1.2 uses operation-aware cross-fitted RD ranking and admits only factorial-compatible relations; factorial schema 1.1 freezes claim scope and emits neutral response-surface labels. Focused synthetic and tamper tests pass. This does not claim that the feedback plan's deferred Original arm was implemented. |
| C — Experiment-ready | **PARTIAL** | The active paths, Security Oracle qualification, Functional Judge qualification, and offline end-to-end smoke exist. The seven-source raw input was deterministically rebuilt, but a fresh semantic-curation/contract bundle, formal discovery support audit, outcome-blind hypothesis/policy freeze, and study-specific power/multiplicity freeze do not yet exist under the active protocol. |
| D — Claim-bearing | **NOT REACHED** | No prospective provider run has been executed under selector schema 2.1 or factorial schema 1.1. Historical factorial schema-1.0 bundles remain independently verifiable but cannot be relabelled as active-protocol evidence. |
| E — Paper-ready | **NOT REACHED** | Method prose and implementation are aligned, but RQ1–RQ3 do not yet have a common prospective evidence package. Any RQ4 expert study also remains a separate, unexecuted human-evaluation work package. |

Gate C is the current stopping gate. Advancing the status by running another
development canary on previously inspected tasks would not be scientifically
valid.

## Claim-to-artifact map

| Intended output | Frozen input | Active implementation | Result field / builder | Current evidence |
| --- | --- | --- | --- | --- |
| Atomic selector support and ranking | selector schema 2.1 universe, embedded Prompt TSG evidence, discovery outcomes, selector plan | `build_active_selector_evidence()`, `run_selector_suite()` | `SelectionFreezeManifest.runs`; `run_selector_experiment()` builds strict ConfirmedYield@K | implemented/tested; no formal freeze |
| Atomic operation-specific observational priority | same discovery freeze plus candidate operation and expected direction | `_association_scores()` in `prioritization.py` | `association.v3` ranking evidence | implemented/tested; no formal ranking |
| Pair selector priority | pair-selector schema 1.2 catalog, graphs, baseline outcomes, compatible relation specs | `build_tsg_pair_universe()`, `run_interaction_selector()` | selected pair slots, cross-fitted standardized RD interaction, stability diagnostics | implemented/tested; no natural formal selection |
| Atomic policy effect | successor freeze, complete randomized blocks, independent measurements | `freeze_successor_experiment()`, `run_successor_experiment()` | assigned-arm task-unit ITT and matching verifier | implemented/tested; no active-protocol provider result |
| Pair policy interaction | factorial schema 1.1 freeze, four-cell blocks, qualified endpoint | `freeze_factorial_experiment()`, `run_factorial_experiment()` | `primary_estimates`, `security_policy_interaction_claim_ready_coordinates`, `mechanism_interaction_claim_ready_coordinates` | implemented/tested; only historical schema-1.0 formal results |
| Reproducible paper table | exact result bundle and independent verification | matching result verifier plus report JSON | table builder must read verified report fields only | blocked on Gate D |

## Evidence inventory

The labels below distinguish execution from inherited evidence.

| Evidence | `evidence_type` | Result |
| --- | --- | --- |
| Seven-source deterministic normalization at `runs/gate-c-20260830/prepared` | `newly_run` | 2,283 records, 2,166 exact clusters, 117 exact duplicate descendants; bundle SHA-256 `c391c7a13603542e5edd725dcc4018b4abaae0bfaa75177067561a166f7816d4`; no outcomes used and no scientific claim allowed |
| Prompt-TSG v1 ten-task extractor-development pilot | `newly_run` | 10/10 responses and graph bundles were structurally valid, but evidence review found role overreach for permissions, credential source, SQL identifier/value, and URL authority. The extractor therefore failed semantic qualification; all ten task units are development-only and cannot enter discovery or confirmation. |
| Focused Prompt-TSG/selector/factorial suite | `newly_run` | 45 passed, 1 deselected; includes state-tamper rejection, operation coding, RD ranking, compatibility filtering, claim-scope replay, and historical verifier compatibility |
| Default reviewer suite and milestone smoke | `newly_run` | Recorded in the final verification section below after the current change set is frozen |
| SQL from-scratch factorial v3 | `preexisting_artifact` | schema 1.0, 30 task units / 240 assignments, interaction 0, simultaneous interval `[-0.0833, 0.0833]` |
| SQL scaffold-repair follow-up | `preexisting_artifact` | schema 1.0, 30 task units / 240 assignments, bounded context-specific positive interaction; not a universal mechanism-synergy result |
| Earlier discussion of expected selector or intervention effects | `user_claim` or development interpretation | never substituted for a frozen result bundle |

## Protocol risks and remaining blockers

1. **Fresh population debt.** The rebuilt records are not yet semantically
   adjudicated, contract-complete, split-disjoint task units. Reusing the old
   31-task Prompt-TSG population would make a new run a development replication,
   not an independent claim-bearing study.
2. **Natural-support risk.** The operation-aware support gate may again reject
   most atomic or pair candidates. That is a valid null availability result;
   it must not be repaired by manufacturing Prompt states or selecting a known
   responsive CWE after outcomes.
3. **Pair-universe risk.** The active reviewed registry currently contains one
   qualified SQL pair. It supports a bounded pair study, not a broad Pair
   Yield@K claim.
4. **Power debt.** Functionality non-inferiority and interaction claims require
   study-specific pre-outcome power qualifications. Existing calibrations prove
   measurement support, not adequate sample size.
5. **Historical-schema boundary.** Schema-1.0 formal results are preserved and
   verifiable. They do not prove schema-1.1 execution or selector-schema-2.1
   behavior.
6. **Selector stability interpretation.** Pair bootstrap diagnostics resample
   frozen cross-fitted task contributions; they rank stability and are not a
   confirmatory confidence interval or a replacement for randomized inference.
7. **Human evidence debt.** An expert study, if retained as RQ4, needs consent,
   materials, sampling, and analysis outside the computational runner.
8. **Provider adherence.** In the first Gate-C attempt, two separate 24-item
   semantic batches returned only indices 1–10 despite a valid JSON `stop`; a
   later mixed-language batch returned only eight of ten. All attempts remain
   closed diagnostics. The active outcome-blind curation limit is therefore
   five items for semantic adjudication and contract extraction; every index
   must still be present, and no partial provider response is admitted. The
   provider also once duplicated an identical JSON key. The active parser may
   collapse only duplicates whose types and values are identical; conflicting
   duplicates remain closed errors. The frozen plan binds this policy plus the
   curation and provider-adapter source digests.
9. **Extractor semantic qualification.** Structural validation alone did not
   catch four task-role overgeneralizations in the first ten-task pilot. The
   first successor attempt also failed a disjoint holdout through invented
   evidence spans and security-role overreach on filename hashing and random
   log generation. `qwen3.5-flash` is therefore not qualified as the formal
   extractor. The stronger extractor has a new identity and remains
   unqualified until a further disjoint holdout evidence review passes. A
   successful JSON response or graph construction is not an accuracy claim.

## Exact next Gate C package

No further method change is authorized by an observed pilot result. The next
prospective package must be frozen in this order:

1. semantic adjudication and functional contracts for a fresh task-unit split;
2. Prompt TSG extraction and independent state/support audit;
3. atomic Top-`K_A` and pair Top-`K_I`, including every empty or failed slot;
4. exact eligible confirmation tasks, hypotheses, policies, models, Oracles,
   realization/order weights, and seeds;
5. primary/secondary endpoints, task-unit weights, multiplicity families,
   unknown policy, power assumptions, and stopping rule;
6. a small real-provider canary that may only test execution integrity;
7. one immutable prospective run followed by the independent verifier.

If the support or power gate fails, Gate C remains failed and the paper scope
must narrow prospectively. Repeating pilots until a favorable effect appears is
not an allowed path to Gate D.

## Final verification section

The following checks were run on the working tree immediately before its
reference commit:

```text
python -m compileall -q src tests
python -m pytest -q
# 30 passed, 126 deselected

python -m pytest -q -m extended \
  tests/test_prompt_tsg.py tests/test_selector_study.py \
  tests/test_selector_experiment.py tests/test_interaction_selector.py \
  tests/test_interaction_selector_experiment.py \
  tests/test_factorial_generalization.py
# 45 passed, 1 deselected

python -m pytest -q -m milestone tests/test_factorial_reviewer_smoke.py
# 1 passed

prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3
# FACTORIAL_RESULT_BUNDLE_VERIFIED: 30 task units, 240 assignments

prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-scaffold-repair-qwen35-v1
# FACTORIAL_RESULT_BUNDLE_VERIFIED: 30 task units, 240 assignments
```

`git diff --check` reported no whitespace errors; Git emitted only the existing
Windows line-ending conversion warnings. Ruff and Black are not installed in
the current environment, so no lint or formatter result is claimed.
