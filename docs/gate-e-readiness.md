# Gate E readiness and evidence audit

**Cutoff:** 2026-08-30

**Role:** implementation and evidence status only. This file is not a second
method contract. The sole normative protocol remains
[`2026-08-20-context-conditioned-intervention-policy-framework.md`](superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).

## Implementation-plan decisions

The final PHASE plan is implemented under four explicit scope corrections:

1. The paper may summarize three macro phases, while the artifact keeps the
   seven auditable stages required by `AGENTS.md`.
2. `Target - operation-matched No-op` remains the active primary atomic
   estimand. An Original arm was proposed after prior outcomes existed and is
   not silently added to the current arm family.
3. Atomic and pair selection are operation-aware and risk-difference aligned.
   A ridge-logit coefficient is diagnostic, not the randomized estimand.
4. A factorial result is first a Prompt-policy response-surface result.
   Mechanism-interaction language additionally requires a prospectively frozen
   `mechanism_eligible` scope.

## Exact gate status

| Gate | Status | Evidence boundary |
| --- | --- | --- |
| A — Protocol-complete | **PASS** | The normative protocol maps representation, support, selector, hypothesis, policy, estimand, evidence status, and permitted claim. Pairwise-only scope and task-bound background are explicit. |
| B — Method-complete | **PASS under the revised protocol** | Prompt TSG, operation-aware atomic/pair selectors, RD-aligned pair ranking, factorial compatibility, assigned-arm ITT, multi-state outcomes, independent measurement, and result verifiers are implemented and covered by focused tests. This does not claim that a post-result Original arm was implemented. |
| C — Experiment-ready | **FAIL** | Semantic curation, functional contracts, local Security Oracle qualification, and measurement qualifications are closed. The prospectively frozen disjoint Prompt TSG semantic qualification failed: 18/21 exact, 85.7% accuracy, 72.7% present recall, zero false-positive present states, and zero wrong realization bindings. The frozen requirements were at least 90% accuracy and 80% recall. |
| D — Claim-bearing | **NOT REACHED** | The failed representation Gate prohibits formal Prompt TSG extraction, discovery measurement, selector freeze, and active-protocol confirmation. No schema-2.1/schema-1.1 claim-bearing provider run was started. |
| E — Paper-ready | **NOT REACHED** | The active method can be described, but RQ1–RQ3 lack one prospective evidence package under the active protocol. Historical schema-1.0 evidence cannot be relabelled. |

Gate C is the enforced stopping point. Lowering the threshold, relabelling the
three missed cases, or restricting the CWE scope after reading the holdout
would be an outcome-dependent protocol change.

## Gate C evidence closure

### Data and contracts

- Seven sources were normalized into 2,283 records.
- Blind semantic adjudication closed all 4,744 candidate pairs and produced
  2,165 task units; arms, generated code, Oracle labels, and experiment
  outcomes were unavailable to curation.
- Functional contracts were extracted and validated for all 2,165 task units.
  The complete archive SHA-256 is
  `6efad8095165ab2133691408d447f0527cf7bd635e1e68ddb1509956f35aed01`.
- The active local Security Oracle boundary replayed 37/37 frozen gold cases
  across 12 profiles, with `secure`, `insecure`, and `unknown` represented for
  every profile. This is an idiom-bound calibration, not a global CWE accuracy
  claim.

### Prompt TSG qualification

The active candidate is a two-stage blind extractor:

```text
LLM evidence-fact proposal
  -> deterministic evidence/type projection
  -> blind LLM accept/reject review of proposed facts only
  -> normalized Prompt TSG and four-valued queries
```

The semantic reviewer cannot add a fact, change an evidence span, or invent a
global semantic ID. Every request, response, projection, and digest is closed
in the extraction bundle.

Development failures were retained rather than hidden:

- a first disjoint holdout exposed invented evidence and security-role
  overreach;
- a stronger proposer still overgeneralized owner-only permission semantics;
- the two-stage reviewer removed false-positive bindings but initially lost
  too many true contexts;
- catalog guidance then became complete for every query-bound semantic.

The first intended final holdout (`v4`) was withdrawn before qualification and
before any extractor output was read. Gold review had incorrectly treated two
end-user credentials as application credentials and an ordinary process-lock
identifier as security-sensitive hashing. Its 24 task units are permanently
marked exposed in
[`prompt-tsg-two-stage-holdout-v4-withdrawal.json`](../data/method/prompt-tsg-two-stage-holdout-v4-withdrawal.json).

The replacement `v5` selection was frozen only after excluding v4 and every
earlier development, qualification, and outcome-exposed unit. Its 21 tasks had
zero exclusion overlap. Gold labels and thresholds were committed before the
extractor ran. The downloaded extraction archive had matching local/remote
SHA-256
`f6253aa63bfb16b755ac22bfa5c953e2231aa7586d9c11f7284731f115db54ed`.

The immutable qualification result is
[`prompt-tsg-two-stage-qualification-v5`](../data/method/results/prompt-tsg-two-stage-qualification-v5):

| Metric | Frozen requirement | Result |
| --- | ---: | ---: |
| Exact context/realization accuracy | at least 0.90 | **0.857143** |
| Present-context recall | at least 0.80 | **0.727273** |
| False-positive present | at most 0 | **0** |
| Wrong realization | at most 0 | **0** |

The three errors were conservative unresolved decisions for:

1. an API-test prompt requiring JSON serialization/deserialization;
2. a job-ID prompt requiring a subprocess command whose executable was not
   named explicitly; and
3. a libvirt volume configuration containing externally supplied
   authentication material.

This result supports a narrower diagnostic statement—high precision with
insufficient context recall on the frozen holdout—but not formal extraction.

## Claim-to-artifact map

| Intended output | Active implementation | Current evidence |
| --- | --- | --- |
| Prompt TSG task-security representation | `prompt_tsg_extract.py`, `prompt_tsg.py`, catalog v3 | implemented/tested; final semantic qualification failed |
| Atomic support and selector ranking | `audit_discovery_positivity()`, `build_active_selector_evidence()`, `run_selector_suite()` | implemented/tested; formal execution prohibited by failed representation Gate |
| Pair selector priority | `build_tsg_pair_universe()`, `run_interaction_selector()` | implemented/tested; no active natural-data freeze |
| Atomic policy effect | `freeze_successor_experiment()`, `run_successor_experiment()` | implemented/tested; no active-protocol provider result |
| Pair policy interaction | `freeze_factorial_experiment()`, `run_factorial_experiment()` | implemented/tested; only historical schema-1.0 results |
| Reproducible RQ tables | independent result verifiers plus future table builders | blocked before Gate D |

The task-partition/positivity interface is now linear: the positivity audit can
read the verified partition bundle's `discovery-graphs.json` directly. This
closes an engineering defect but does not change the failed scientific Gate.

## Evidence inventory

| Evidence | `evidence_type` | Result |
| --- | --- | --- |
| Seven-source semantic curation | `newly_run` | 2,283 records, 4,744 blind pair decisions, 2,165 task units |
| Full functional-contract curation | `newly_run` | 2,165/2,165 resolved and bundle-verified |
| Local Security Oracle qualification | `newly_run` | 37/37 frozen cases, 12 active profiles, unknown preserved |
| Prompt TSG v5 extraction and qualification | `newly_run` | extraction bundle verified; qualification failed at 18/21 and 8/11 present recall |
| Reviewer and focused tests | `newly_run` | recorded in the final verification section after the working tree is frozen |
| SQL from-scratch factorial v3 | `preexisting_artifact` | schema 1.0; 30 task units / 240 assignments; interaction 0; simultaneous interval `[-0.0833, 0.0833]` |
| SQL scaffold-repair follow-up | `preexisting_artifact` | schema 1.0; bounded context-specific positive interaction; not universal mechanism synergy |
| Earlier expected intervention or selector effects | `user_claim` or development interpretation | never substituted for frozen evidence |

## Protocol risks and remaining blockers

1. **Representation recall.** The active extractor is conservative but missed
   three required contexts. Formal natural discovery cannot start.
2. **Gold scope.** The final holdout evaluates its frozen task mixture, not
   global natural-language understanding or per-CWE accuracy.
3. **Natural support.** Even after a future representation qualification,
   positivity and source-lineage overlap may reject all selector candidates.
4. **Pair breadth.** The reviewed active registry contains one qualified SQL
   pair, so it cannot support a broad Pair Yield@K claim.
5. **Power and multiplicity.** Study-specific qualifications remain absent
   because the pipeline correctly stopped before hypothesis/policy freeze.
6. **Historical schema.** Schema-1.0 results remain valid for their own frozen
   protocols but do not establish schema-1.1 or selector-schema-2.1 behavior.
7. **Human evidence.** Any expert study remains a separate, unexecuted work
   package requiring its own governance.

## Permitted next work

The next valid move is not another holdout against the same tuned candidate.
It must be a new prospectively declared representation study, for example:

- replace free-form context extraction with a more constrained annotation
  protocol and independently qualified adjudication; or
- freeze a materially new extractor before selecting a new, fully disjoint
  corpus and qualification set.

Only after that new representation Gate passes may the project regenerate the
formal selection, partition task units, run discovery positivity, and continue
through hypothesis, power, policy, canary, and confirmation freezes.

## Final verification

The following checks were run on the final working tree:

```text
python -m compileall -q src tests
# completed without errors

python -m pytest -q
# 73 passed, 129 deselected

python -m pytest -q tests/test_discovery_support.py
# 4 passed

python -m pytest -q -m milestone tests/test_factorial_reviewer_smoke.py
# 1 passed

prompt-mechanism-study verify \
  data/method/results/prompt-tsg-two-stage-qualification-v5
# VERIFIED

prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3
# FACTORIAL_RESULT_BUNDLE_VERIFIED: 30 task units, 240 assignments

prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-scaffold-repair-qwen35-v1
# FACTORIAL_RESULT_BUNDLE_VERIFIED: 30 task units, 240 assignments
```

`git diff --check` reported no whitespace errors. The deliberately failed
Prompt TSG qualification was also deterministically rebuilt from its frozen
gold and verified extraction bundle; its failed status is evidence, not a test
failure to suppress. The historical extended incident suite was not rerun.
