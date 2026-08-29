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
| C — Experiment-ready | **FAIL** | Semantic curation, functional contracts, local Security Oracle qualification, and measurement qualifications are closed. The final prospectively frozen disjoint Prompt TSG qualification was 13/14 exact (92.9%) with 3/4 present recall (75.0%), zero false-positive present states, and zero wrong realization bindings. Accuracy passed, but recall did not reach the frozen 80% requirement. |
| D — Claim-bearing | **NOT REACHED** | The failed representation Gate prohibits formal Prompt TSG extraction, discovery measurement, selector freeze, and active-protocol confirmation. No schema-2.1/schema-1.1 claim-bearing provider run was started. |
| E — Paper-ready | **NOT REACHED** | The active method can be described, but RQ1–RQ3 lack one prospective evidence package under the active protocol. Historical schema-1.0 evidence cannot be relabelled. |

Gate C is the enforced stopping point. Lowering the threshold, relabelling the
missed case, restricting the CWE scope, or repeatedly drawing same-population
holdouts after reading these results would be outcome-dependent tuning.

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
  -> normalize an occurrence only when the quoted span is exact and unique
  -> blind LLM re-annotation within the proposer-declared semantic scope
  -> reject and record relations outside the query-declared semantic triples
  -> normalized Prompt TSG and four-valued queries
```

The reviewer cannot widen the proposer-declared catalog scope or invent a
global semantic ID. A query can use only exact prompt spans, catalog facts, and
its declared relations. Catalog v5 also distinguishes a caller-supplied base
from an independently trusted base and requires the latter to qualify the
specific file-access sink. Every request, response, projection, and digest is
closed in the extraction bundle.

The bounded repair sequence remains visible without promoting development
replays to evidence:

- the predecessor v5 qualification failed at 18/21 exact and 8/11 present
  recall;
- bounded ambiguity adjudication improved a fresh v2 holdout to 20/21 exact
  and 5/5 recall, but one caller-supplied directory was falsely treated as a
  trusted base, so the zero-false-positive Gate still failed; the immutable
  result is
  [`prompt-tsg-adjudicated-qualification-v2`](../data/method/results/prompt-tsg-adjudicated-qualification-v2);
- the trust-boundary v3 extraction stopped before qualification because the
  proposer supplied an impossible occurrence index for a unique exact span;
  all 21 selected task units were exposure-excluded and not retried, as
  recorded in
  [`prompt-tsg-trust-boundary-holdout-v3-failure.json`](../data/method/prompt-tsg-trust-boundary-holdout-v3-failure.json);
- deterministic unique-span occurrence normalization was then frozen before a
  replacement v4 selection and gold review.

The immutable final result is
[`prompt-tsg-evidence-occurrence-qualification-v4`](../data/method/results/prompt-tsg-evidence-occurrence-qualification-v4):

| Metric | Frozen requirement | Result |
| --- | ---: | ---: |
| Exact context/realization accuracy | at least 0.90 | **0.928571** |
| Present-context recall | at least 0.80 | **0.750000** |
| False-positive present | at most 0 | **0** |
| Wrong realization | at most 0 | **0** |

The only mismatch was conservative: a document-retrieval task listed
`base_dir` under `Context` and `doc_path` under `Arguments`; the frozen gold
treated `base_dir` as the independently supplied application context, while
both LLM stages treated it as caller-supplied. The label and threshold remain
unchanged. The result supports a narrow high-precision diagnostic, not formal
extraction or any active-protocol intervention claim.

## Claim-to-artifact map

| Intended output | Active implementation | Current evidence |
| --- | --- | --- |
| Prompt TSG task-security representation | `prompt_tsg_extract.py`, `prompt_tsg.py`, catalog v5 | implemented/tested; final semantic qualification failed |
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
| Prompt TSG bounded-adjudication v2 | `newly_run` | 20/21 exact and 5/5 recall, but one false-positive present state failed the frozen Gate |
| Prompt TSG trust-boundary v3 | `newly_run` | formal extraction stopped after 2/21 graphs on an impossible occurrence index; no qualification metric; all selected units excluded |
| Prompt TSG final v4 extraction and qualification | `newly_run` | extraction bundle verified; qualification failed at 13/14 exact and 3/4 present recall |
| Reviewer and focused tests | `newly_run` | recorded in the final verification section after the working tree is frozen |
| SQL from-scratch factorial v3 | `preexisting_artifact` | schema 1.0; 30 task units / 240 assignments; interaction 0; simultaneous interval `[-0.0833, 0.0833]` |
| SQL scaffold-repair follow-up | `preexisting_artifact` | schema 1.0; bounded context-specific positive interaction; not universal mechanism synergy |
| Earlier expected intervention or selector effects | `user_claim` or development interpretation | never substituted for frozen evidence |

## Protocol risks and remaining blockers

1. **Representation recall.** The active extractor retained zero false-positive
   present states but recovered only 3/4 frozen present contexts. Formal natural
   discovery cannot start.
2. **Gold scope and size.** Exhaustion of the repeatedly exposure-excluded
   CWE-328 stratum limited the final replacement holdout to 14 task units. It
   evaluates that frozen task mixture, not global understanding or per-CWE
   accuracy.
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

The next valid move is not another holdout from the remaining 373-task source
population. It must be a new prospectively declared representation study on a
genuinely independent corpus, for example:

- replace free-form context extraction with a more constrained annotation
  protocol and independently qualified adjudication; or
- replace trusted-boundary inference with an explicit dataset-side trust field
  whose annotation is qualified independently; or
- freeze a materially new extractor before selecting a new external corpus and
  qualification set.

Only after that new representation Gate passes may the project regenerate the
formal selection, partition task units, run discovery positivity, and continue
through hypothesis, power, policy, canary, and confirmation freezes.

## Final verification

The following checks were run on the final working tree:

```text
python -m compileall -q src tests
# completed without errors

python -m pytest -q
# 79 passed, 129 deselected

python -m pytest -q tests/test_prompt_tsg.py
# 12 passed, 5 deselected

python -m pytest -q tests/test_discovery_support.py
# 4 passed

python -m pytest -q -m milestone tests/test_factorial_reviewer_smoke.py
# 1 passed

prompt-mechanism-study verify \
  data/method/results/prompt-tsg-evidence-occurrence-qualification-v4
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
