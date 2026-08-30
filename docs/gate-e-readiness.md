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
| C — Experiment-ready | **FAIL** | Semantic curation, functional contracts, local Security Oracle qualification, and measurement qualifications are closed. The structured-authority successor was evaluated once on a prospectively frozen external 16-task population: 14/16 exact (87.5%), 3/5 present recall (60.0%), zero false-positive present states, and one wrong realization. The three path-authority cases were all correct, but the complete frozen Gate failed. |
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

The final same-population predecessor result is
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
| Prompt TSG task-security representation | `prompt_tsg_extract.py`, `prompt_tsg.py`, catalog v5 | implemented/tested; the independent external qualification failed, although its three structured path-authority cases were all correct |
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
| Structured path-authority successor trial | `newly_run` development evidence | real 5-case replay completed at 5/5 exact with no false-positive or wrong realization; all cases and labels were previously exposed, so this is interface validation rather than Gate evidence |
| Structured-authority external qualification v1 | `newly_run` | independent 16-task extraction closed once at 16/16; qualification failed at 14/16 exact, 3/5 present recall, zero false-positive present states, and one wrong realization; all three path cases matched |
| Reviewer and focused tests | `newly_run` | recorded in the final verification section after the working tree is frozen |
| SQL from-scratch factorial v3 | `preexisting_artifact` | schema 1.0; 30 task units / 240 assignments; interaction 0; simultaneous interval `[-0.0833, 0.0833]` |
| SQL scaffold-repair follow-up | `preexisting_artifact` | schema 1.0; bounded context-specific positive interaction; not universal mechanism synergy |
| Earlier expected intervention or selector effects | `user_claim` or development interpretation | never substituted for frozen evidence |

## Protocol risks and remaining blockers

1. **Representation recall and realization identity.** The external Gate
   retained zero false-positive present states but recovered only 3/5 frozen
   present contexts and assigned one SQL case to the wrong realization. Formal
   natural discovery cannot start.
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

## Post-Gate explicit-authority development trial

After the immutable v4 failure, one development-only successor rule was tried
on five previously exposed CWE-22 task units. The rule requires base authority
to be explicit: a base in a function signature or `Arguments` is
caller-supplied; an application-configured, predefined, trusted, global, or
literal task root is trusted; and a base named only as generic `Context` is
unresolved. Arms, generated code, Oracle labels, and experiment outcomes were
not used. Because every task unit was already exposed, none of these replays is
qualification evidence.

Three bounded candidates were run:

| Development candidate | Exact cases | Present recall | Diagnostic result |
| --- | ---: | ---: | --- |
| principle-only two-stage prompt | 1/5 | 1/3 | confused all three authority states |
| closed decision table, thinking reviewer | 3/5 | 1/3 | correctly made the former v4 mismatch unresolved, but rejected two explicit predefined roots |
| closed decision table, non-thinking reviewer | 3/5 | 1/3 | retained the corrected ambiguous and caller-supplied states, but still inconsistently rejected two explicit trusted roots |

The verified extraction archives have SHA-256 digests
`c8ea42770c5f643e9577fba194745068a15e25aa1a57ac0db3c6faec80bc2218`,
`c245ab03fc74f04aaae16a950b63ef8ffe45e29af68c66fdbdfb2ba299c44821`,
and `fd09a924d3dd12b0fab6069845aea16891eac142a9c9d8e22bb3bf35aa13505a`.
They remain development archives, not reviewer or paper evidence. The result is
useful but negative: explicit-authority prompting fixes the original ambiguous
case, yet prompt engineering alone has not produced a qualified representation
extractor. The active Gate C therefore remains failed.

### Structured authority successor

The follow-up removed path-base authority from the two LLM stages rather than
adding more examples. A separate outcome-blind annotation is bound to each
selected `task_id` and prompt hash, cites an exact occurrence, and uses four
states: `application_configured`, `caller_supplied`, `unspecified`, or
`no_bounding_base`. The deterministic projection maps the first two to one
authority fact, maps `unspecified` to unresolved authority, and keeps
`no_bounding_base` absent. Stage-one model authority facts and relations are
removed and recorded before semantic review; the reviewer is not offered those
semantics, and any scope widening still fails closed.

Three real development executions exposed two general interface defects and
then closed the five-case path:

| Execution | Completed graphs | Result |
| --- | ---: | --- |
| structured-authority v4 | 2/5 | reviewer relation vocabulary still named an endpoint outside its candidate set, so the fail-closed extractor stopped on scope widening |
| structured-authority v5 | 4/5 | reviewer accepted a repeated `theme_path` fact but returned impossible occurrence indices; the extractor stopped rather than guessing a span |
| structured-authority v6 | 5/5 | reviewer relations were candidate-closed, and accepted proposer facts reused their already validated evidence binding |

The v6 archive SHA-256 is
`0bdcf14b182c9bf9ce177234ad883c7e0b403c87eaff7f5f23f2addd13df61f0`;
the downloaded bundle was independently verified. The annotation input SHA-256
is `8c6103a040804b8bce0becc2ea308915e04e02ac414dabb5d8a2fb15a85824bb`,
and the extractor implementation SHA-256 is
`e34177339d4a4a18deb95c1e418ab48f694726de183046d32f64b2ef3c10d917`.
Replaying the existing verifier against the development labels produced 5/5
exact contexts, 3/3 present recall, zero false-positive present states, and
zero wrong realizations. One explicit path-confinement feature was already
present in its source prompt and remained a diagnostic
`target_feature_present` case; it was not denominator-filtered.

These metrics do **not** pass or reopen Gate C: the same five prompts and labels
had already been used to design the rule, and the v4/v5 failures were examined
before v6. They establish that the structured interface now behaves as
specified and that the two observed failures were fail-closed. A claim-bearing
Gate still requires a prospectively frozen independent corpus and annotation
review.

### Prospective external qualification

The independent follow-up used the pinned
[`AI-Security-Benchmark`](https://github.com/miroku0000/AI-Security-Benchmark)
source commit `c21cd8b601c85f8a5a32dd77dceb1533a2227104`. The source census mapped
18 Python prompts to seven already registered CWE/task-family coordinates.
Before extraction, semantic overlap review excluded two tasks whose principal
operation and functional contract duplicated the prior seven-source pool: one
tar extraction task and one username/password login task. All 16 remaining
tasks were retained; there was no result-based or hash-ranked sampling.

Selection, gold labels, thresholds, and three path-authority annotations were
committed at `6e452b2` before any extractor request. The only external
extraction then completed 16/16 graphs on the A800 host. The downloaded bundle
verified independently and is frozen at
[`prompt-tsg-external-extraction-v1`](../data/method/results/prompt-tsg-external-extraction-v1).
Its bundle SHA-256 is
`76ba792eb90214d8f8e3184d256ec018dd52d7b8036cadad8f6d7699a2cff201`.
The result is frozen at
[`prompt-tsg-external-qualification-v1`](../data/method/results/prompt-tsg-external-qualification-v1):
its bundle SHA-256 is
`0276830aef300b79b6133d7fd60193f9d67dcee1b3a167e3127f2ec7d4fb2b28`.

Run provenance is deliberately small: input-freeze commit `6e452b2`, source
archive SHA-256
`8ebf7836b9caf18dda0d8cd9993d27314dbe8c61e312abbf5dbde1a5fcf179b9`,
Python 3.12.13 on Linux 6.8.0 x86-64, and one NVIDIA A800 80 GB host. The
immutable remote coordinates were
`/home/wsy/prompt-mechanism-study-deployments/gate-c-external-6e452b2-20260830-01`
and
`/home/wsy/prompt-mechanism-study-experiments/gate-c-external-6e452b2-20260830-01`.
The executed stage was the single `prompt-tsg-extract` entry point with catalog
v5, proposer v12, ambiguity adjudicator v6, the external selection, and the
structured path-authority annotation bundle. The provider credential remained
environment-only and is absent from all tracked artifacts.

| Metric | Frozen requirement | External result |
| --- | ---: | ---: |
| Exact context/realization accuracy | at least 0.90 | **0.875000** |
| Present-context recall | at least 0.80 | **0.600000** |
| False-positive present | at most 0 | **0** |
| Wrong realization | at most 0 | **1** |

The structured path-authority direction itself transferred: the fixed uploads
base plus caller filename was present, the fixed uploads base without a stated
caller path was unresolved, and the root of unspecified authority was
unresolved (3/3 exact). Gate failure came from two different semantic
boundaries:

1. A SOAP task required DTD validation but not external entity resolution.
   The frozen gold treated XXE control as applicable; both LLM stages promoted
   DTD support to `constraint.external_entities_required`, making the context
   absent.
2. A search API accepted any combination of four named filter arguments. The
   frozen gold treated this as a finite dynamic-identifier context; both LLM
   stages treated the identifiers as fixed and returned the value-only SQL
   realization.

The first is a DTD-versus-entity distinction. The second exposes a deeper
task-semantics rule: optional named filters do not necessarily require caller
provided SQL identifier text, whereas a generic `field` argument does. These
cases remain mismatches; neither gold nor output is relabelled after seeing the
result. The qualification verifier required a separately supplied annotation
bundle and checked its hash before accepting the heterogeneous extractor IDs;
this was an identity-closure repair, not a case-label change.

## Permitted next work

The v4 internal population and the external 16-task population are both now
exposed. Neither can be resampled or retuned into a passing Gate. The next
valid representation study must first freeze two prospective semantic
clarifications:

- DTD validation is distinct from required external-entity resolution; and
- a finite set of optional named SQL parameters is not a dynamic identifier
  source unless the caller supplies an identifier token or the task otherwise
  requires identifier selection in generated SQL.

After those definitions and extractor behavior are frozen, validation requires
another genuinely independent corpus. Valid options remain:

- replace free-form context extraction with a more constrained annotation
  protocol and independently qualified adjudication; or
- replace trusted-boundary inference with an explicit dataset-side trust field
  whose annotation is qualified independently; or
- freeze a materially new extractor before selecting a new external corpus and
  qualification set.

The structured authority implementation now has prospective external support
for the two authority states actually present in this source
(`application_configured` and `unspecified`). `caller_supplied` and
`no_bounding_base` remain engineering-tested only. The complete representation
Gate remains failed, so discovery and effect estimation are still prohibited.

Only after that new representation Gate passes may the project regenerate the
formal selection, partition task units, run discovery positivity, and continue
through hypothesis, power, policy, canary, and confirmation freezes.

## Final verification

The following checks were run on the final working tree:

```text
python -m compileall -q src tests
# completed without errors

python -m pytest -q
# 88 passed, 129 deselected

python -m pytest -q tests/test_prompt_tsg.py
# 21 passed, 5 deselected

python -m pytest -q tests/test_discovery_support.py
# 4 passed

python -m pytest -q -m milestone tests/test_factorial_reviewer_smoke.py
# 1 passed

prompt-mechanism-study verify \
  data/method/results/prompt-tsg-evidence-occurrence-qualification-v4
# VERIFIED

prompt-mechanism-study verify \
  data/method/results/prompt-tsg-external-extraction-v1
# VERIFIED

prompt-mechanism-study verify \
  data/method/results/prompt-tsg-external-qualification-v1
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
