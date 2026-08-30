# Gate E readiness and evidence audit

**Cutoff:** 2026-08-31

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
| C — Experiment-ready | **FAIL** | Semantic curation, functional contracts, local Security Oracle qualification, and measurement qualifications are closed. The active task-level contract successor completed 28/28 DevEval task units, but matched only 24/28 (`0.857143`), recalled 7/10 present cases (`0.70`), and produced one false-positive present state plus one wrong realization. |
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

The prospective successor is a two-stage blind extractor with a compiled
catalog boundary:

```text
LLM semantic-ID and exact-evidence proposal (no structural node type)
  -> derive every node type from the frozen catalog
  -> deterministic evidence projection
  -> normalize an occurrence only when the quoted span is exact and unique
  -> blind LLM re-annotation over the complete task-family catalog slice
  -> reject and record relations outside the query-declared semantic triples
  -> normalized Prompt TSG and four-valued queries
```

The reviewer may recover a proposer omission, but only from the finite catalog
slice computed before either model call and only with a new exact prompt span.
It cannot invent a global semantic ID or structural type. A query can use only
exact prompt spans, catalog facts, and its declared relations. Catalog v11
carries forward the distinction between a
caller-supplied base and an independently trusted base, and additionally
freezes the DTD/entity, dynamic-identifier, named-tool, checkpoint-format, and
evidence-occurrence boundaries diagnosed before the BigCodeBench run. It also
removes redundant format-required facts when a typed deserialization source,
sink, and flow already identify the format, and requires each query-bound
constraint to qualify its particular sink. Every
request, response, projection, and digest is closed in the extraction bundle.

Commit `5c81bd0` implements the compiled response contract as proposer v17 and
reviewer v7; commit `e49020f` freezes catalog v11 and limits any passing claim
to realizations represented by positive holdout gold. A four-case
replay of already exposed BigCodeBench failures completed and agreed with the
previously visible labels, including the former schema-stop case. This is
development evidence only, not an accuracy estimate or a reopened Gate. Its
bounded provenance and disposition are recorded in
[`prompt-tsg-compiled-successor-development-v1.json`](../data/method/prompt-tsg-compiled-successor-development-v1.json).

### DevEval compiled-successor qualification

The next qualification was frozen at commit `d1eabd7` before any model
request. It used 31 independent Python task units from the pinned DevEval
without-context prompt source, distributed across eight registered task
families. Exact normalized overlap with the seven-source corpus and all prior
external qualification prompts was zero. Gold contained 16 present and 15
absent-or-unresolved cases. Only 10 catalog realizations had positive gold;
six other realizations were prospectively outside the qualification claim
boundary.

One formal run completed all 31 proposer and 31 reviewer calls without retries.
All 31 graphs closed, no response supplied the locally compiled `node_type`,
and neither arms nor outcomes were available. The verified artifacts are
[`prompt-tsg-external-extraction-v4`](../data/method/results/prompt-tsg-external-extraction-v4)
and
[`prompt-tsg-external-qualification-v4`](../data/method/results/prompt-tsg-external-qualification-v4).

| Metric | Frozen requirement | DevEval result |
| --- | ---: | ---: |
| Exact context/realization accuracy | at least 0.90 | **0.870968 (27/31)** |
| Present-context recall | at least 0.80 | **0.875000 (14/16)** |
| False-positive present | at most 0 | **2** |
| Wrong realization | at most 0 | **2** |

Archive extraction, command execution, deserialization, message hashing, and
XML parsing closed perfectly; SQL missed one of four cases. The four
mismatches expose three contract boundaries:

1. A correct proposer SQL relation disappeared because the reviewer omitted,
   rather than explicitly rejected, the same relation.
2. An RNG factory with seeded deterministic branches was promoted to
   security-value generation.
3. External application credentials, per-request bearer credentials, and
   end-user Basic-Auth header construction were not separated sharply enough;
   this caused one false negative and one false positive.

The immutable machine-readable disposition is
[`prompt-tsg-external-qualification-v4-failure.json`](../data/method/prompt-tsg-external-qualification-v4-failure.json).
This population is fully exposed and is never retried, resampled, relabelled,
or used to lower the Gate.

### Contract-first architecture canary

The v4 failures motivated one architectural change rather than another
case-specific prompt patch. Catalog v11 remains the only mechanism vocabulary.
For each task unit, one `TaskContextContract` must now jointly decide every
required/forbidden semantic, actionable feature, and required relation across
all catalog queries matching its frozen CWE and task family. Missing queries or
rows are invalid. A local
compiler derives the schema-2.0 Prompt TSG, including an explicit unresolved-
relation field, while schema-1.0 frozen graph identities remain unchanged.

The four exposed v4 mismatch cases compiled to the prospectively intended
states: SQL `present`, RNG-factory `absent`, bearer-token verification
`present`, and Basic-Auth header construction `absent`. The focused suite also
shows that deleting any required semantic or relation decision fails closed,
and that an unresolved SQL relation remains `unresolved` rather than becoming
`absent`. That query-scoped development canary is retained only in Git commit
`9fc884e`; it is not an active method input. The active task-level implementation
also rejects an incomplete query set and independently replays its contract,
graph, requests, responses, and Gate calculation.

Relation state is model-authored only when both semantic endpoints are present.
Before validating either independent annotation, deterministic endpoint closure
forces `absent` if either endpoint is absent, otherwise `unresolved` if either
endpoint is unresolved. Raw model tables remain retained for audit.

The subsequent v7 formal extraction passed that deterministic boundary but
stopped before writing a bundle when one reviewer row violated the JSON Object
field shape. v8 used strict JSON Schema and fixed that field-shape failure, but
its static row arrays still allowed one task-specific semantic identity to be
omitted or substituted. Neither run retained a response artifact or Gate score.
The prospective successor deterministically compiles each frozen task scope into
two keyed JSON objects whose complete semantic and relation coordinate sets are
required and whose additional properties are forbidden. Local completeness,
evidence, semantic, consensus, and replay checks remain strict.

The first sequential v9 run was deliberately terminated after about two minutes
at the owner's request to replace scheduling prospectively; its experiment root
contained no files and no Gate score was computed. The successor freezes four
task workers. Proposer and reviewer remain sequential within a task, total calls
remain 56, output remains in selection order, and the independent qualification
checks the configured and effective worker counts.

The prospectively frozen v10 run completed all 28 task units, 28 contracts, 28
graphs, and 56 provider calls without retries. Four workers reduced wall-clock
time to 506.63 seconds from the approximately 14-minute sequential baseline;
provider throttling and request-length long tails limited the realized speedup
to about 1.66x. The content-addressed extraction and independent qualification
bundles both replayed successfully.

| Metric | Frozen requirement | Contract v10 result |
| --- | ---: | ---: |
| Exact context/realization accuracy | at least 0.90 | **0.857143 (24/28)** |
| Present-context recall | at least 0.80 | **0.700000 (7/10)** |
| False-positive present | at most 0 | **1** |
| Wrong realization | at most 0 | **1** |

Three expected-present cases became unresolved because the annotators disagreed
on whether ordinary function parameters, generic JSON values, or project-local
YAML files establish caller/external input. The single false positive treated
`ldd` as fixed even though its executable path is itself a function parameter.
These are representation-contract ambiguities rather than scheduler or JSON
transport failures. Gate C therefore remains failed; the frozen result is not
relabelled, rescored, or rerun.

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
| Prompt TSG task-security representation | `prompt_contract_extract.py`, `prompt_contract.py`, `prompt_tsg.py`, catalog v11 | task-level contract successor implemented, tested, and executed on a frozen 28-unit DevEval holdout; qualification failed at 24/28 with 7/10 present recall, one false positive, and one wrong realization, so formal use remains prohibited |
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
| SecCodeBench successor extraction v2 | `newly_run` development evidence | disjoint 10-task inputs and gold were frozen first; extraction stopped on task 2 after one graph, and task 1 already made present recall mathematically unable to reach 0.80; no qualification metric was produced |
| BigCodeBench successor extraction v3 | `newly_run` development evidence | disjoint 31-task inputs and gold were frozen first; extraction stopped on task 16 after 15 graphs. The completed prefix already contained one false-positive present state and one wrong realization, so the frozen Gate was unreachable; no qualification metric was produced |
| DevEval compiled-successor qualification v4 | `newly_run` | 31/31 extraction complete; 27/31 exact, 14/16 present recall, two false-positive present states, and two wrong realizations; frozen Gate failed and the population is exposure-excluded |
| DevEval task-contract qualification v10 | `newly_run` | 28/28 extraction complete with four task workers and 56 calls in 506.63 seconds; independent qualification failed at 24/28 exact, 7/10 present recall, one false-positive present state, and one wrong realization |
| Reviewer and focused tests | `newly_run` | recorded in the final verification section after the working tree is frozen |
| SQL from-scratch factorial v3 | `preexisting_artifact` | schema 1.0; 30 task units / 240 assignments; interaction 0; simultaneous interval `[-0.0833, 0.0833]` |
| SQL scaffold-repair follow-up | `preexisting_artifact` | schema 1.0; bounded context-specific positive interaction; not universal mechanism synergy |
| Earlier expected intervention or selector effects | `user_claim` or development interpretation | never substituted for frozen evidence |

## Protocol risks and remaining blockers

1. **Relation adjudication.** A reviewer omission currently removes a proposer
   relation without recording whether the relation was rejected or merely
   overlooked. The DevEval SQL false negative shows that every query-required
   relation needs an explicit `accept`/`reject`/`unresolved` decision before
   another Gate attempt.
2. **Semantic taxonomy.** The catalog must separate application/deployment
   credentials from end-user or per-request credentials, and RNG selection
   from actual password/token/nonce generation. Mixed deterministic branches
   also need a frozen blocking rule. These are construct definitions rather
   than prompt-tuning details.
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

### SecCodeBench successor attempt

The DTD/entity and SQL-identifier distinctions were prospectively frozen at
commit `c3f18f2` as catalog v8, proposer prompt v13, and proposer evaluator
v15. A second source was selected only after that commit. It used the complete
census of 10 mappable Python `gen` cases in SecCodeBench v2.2.0, pinned at
commit `67126efb88c6dd75f1fb4963048cab2f7b23d83d`. The three excluded Python
cases were outside the already registered query scope (two SSTI cases and one
arbitrary-code-evaluation case). Selection, exact task text, source blobs,
overlap review, four present labels, six absent-or-unresolved labels, and the
unchanged thresholds were committed at `aebd3b1` before any request.

The one formal extraction was run on Python 3.12.13 and an NVIDIA A800 80 GB
host. It stopped on the second selected task and is preserved at
[`prompt-tsg-external-extraction-v2`](../data/method/results/prompt-tsg-external-extraction-v2),
whose bundle SHA-256 is
`a008255615e19891423f35bca1666dce9ab15cd7e32d46b22920b5e912cd1ee2`.
The immutable remote coordinates were
`/home/wsy/prompt-mechanism-study-deployments/gate-c-seccodebench-aebd3b1-20260830-01`
and
`/home/wsy/prompt-mechanism-study-experiments/gate-c-seccodebench-aebd3b1-20260830-01`.
The gold file was not deployed to the extraction host, and the provider
credential remained environment-only.

The first task required a predetermined `sort` then `uniq` pipeline with only
caller-supplied arguments. The extractor left `constraint.fixed_executable`
unresolved, so a frozen expected-present case was already missed. Because the
population had four expected-present cases, the maximum possible recall after
that miss was `3/4 = 0.75`, below the frozen `0.80` threshold. The second task
used `torch.load` for a framework checkpoint; the proposer incorrectly mapped
it to Python-literal deserialization and cited the third occurrence of
`checkpoint_path` even though the exact substring occurs twice. Strict
evidence validation stopped the run. No remaining task was called, no retry
was made, and no qualification metric was manufactured from the partial
bundle.

These observations motivated prospective catalog v9, proposer prompt v14,
and evaluator v16: a predetermined multi-tool pipeline is fixed when the
caller cannot choose tools; unsupported binary/object/checkpoint formats must
not be mapped to the nearest registered text format; and every occurrence
index must be checked against the exact substring count. SecCodeBench exposed
those changes and is prohibited from qualifying them. The population also
contains no XML task, so it supplies no independent DTD-boundary evidence.

### BigCodeBench catalog-v9 attempt

Catalog v9, proposer prompt v14, and evaluator v16 were frozen before selecting
a third source. PurpleLlama autocomplete was rejected because all 1,404 local
Instruct Prime records have the same repository/file/line/pattern coordinates
in that 1,916-record source; changing prompt presentation would not create an
independent lineage. The replacement used BigCodeBench v0.1.1 at commit
`a3b89850db670d7302571142b881e4f85eef18e3`. Its compressed source blob has
SHA-256
`58142744edaf6036387f8761701f1b353432b0ed33f2edec1de8a59e7431ef7a`.

Before extraction, fixed library/operation filters and a salted ordering chose
31 task units across eight registered families: four each for command
execution, SQL, deserialization, hashing, randomness, credentials, and
outbound requests, plus three XML tasks. Nineteen labels were present and 12
were absent-or-unresolved. Exact overlap with both the seven-source pool and
the earlier two external populations was zero. Source lineage, exclusions,
tasks, selection, labels, and unchanged thresholds were committed at
`6fa3688`. The first remote preflight rejected extra provenance keys in the
selection JSON before reading a credential or calling the provider. Those
duplicated keys already existed in the source manifest; removing only them and
adding an exact-schema regression assertion produced input commit `da74834`.
Tasks, order, gold, catalog, prompts, model, and thresholds did not change.

The one provider run used Python 3.12.13 on the A800 host. It is preserved at
[`prompt-tsg-external-extraction-v3`](../data/method/results/prompt-tsg-external-extraction-v3),
whose independently verified bundle SHA-256 is
`2f0f274d46981570d23f1971ae747a8a9286e8915995625f97ecb550862e93de`.
The immutable remote coordinates were
`/home/wsy/prompt-mechanism-study-deployments/gate-c-bigcodebench-da74834-20260830-02`
and
`/home/wsy/prompt-mechanism-study-experiments/gate-c-bigcodebench-da74834-20260830-02`.
The deployed archive excluded gold and had SHA-256
`070694912fdb25b5c4655489b1fecca79b5ee9c17a9ad7eae253cb48a6c7b829`.

Extraction closed 15 graphs, then stopped on BigCodeBench/256. The bounded
reviewer returned node type `feature` for
`feature.current_cryptographic_hash`, although the request supplied the
catalog type `safety_requirement`; strict validation rejected the response.
The completed prefix is not a substitute qualification metric, but a blinded
diagnostic replay against the already frozen gold established that the Gate
was independently unreachable:

- BigCodeBench/1028 names no executable and says only that different commands
  are used across operating systems. Both LLM stages nevertheless asserted a
  fixed named executable, producing one false-positive present state and one
  wrong realization.
- BigCodeBench/681 contained a JSON source, JSON-deserialization sink, and
  their flow, but no separately duplicated JSON-format constraint, so the
  query returned absent.
- BigCodeBench/216 exposed the same redundant requirement by leaving the
  JSON-format constraint unresolved despite explicitly requiring JSON files.

The frozen maximum for false-positive present states and wrong realizations is
zero. Both counts were already one after the first 15 graphs, so unexecuted
suffixes cannot rescue the Gate. No formal accuracy or recall statistic is
reported, no retry is made, and the complete 31-task selection is permanently
exposure-excluded. The machine-readable disposition is
[`prompt-tsg-external-qualification-v3-failure.json`](../data/method/prompt-tsg-external-qualification-v3-failure.json).

## Permitted next work

All prior qualification populations, including the 31-task DevEval v4 set,
are exposed and cannot be reused as Gate evidence. Drawing another holdout
immediately would spend independent data before the newly observed construct
defects are repaired.

The only permitted development work is therefore bounded and outcome-blind:

1. make every query-required relation receive an explicit reviewer decision,
   so omission is not silently interpreted as rejection;
2. split application/deployment credentials from bearer/end-user credentials
   and distinguish header construction from authenticating to a service;
3. split RNG factory selection from generation of a security-sensitive value,
   with mixed seeded/deterministic behavior blocking an asserted context;
4. validate those rules on synthetic fixtures and already exposed cases only.

After the construct definitions, evaluator behavior, and thresholds are
frozen, one genuinely independent population may be selected and run once.
Only a passing representation Gate permits formal discovery, positivity
analysis, hypothesis and policy freeze, Gate D, or Gate E.

## Final verification

The following checks were run on the final working tree:

```text
python -m compileall -q src/prompt_mechanism_study
# completed without errors

python -m pytest -q
# 94 passed, 129 deselected

python -m pytest -q tests/test_prompt_tsg.py
# 27 passed, 5 deselected

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

prompt-mechanism-study verify \
  data/method/results/prompt-tsg-external-extraction-v3
# VERIFIED

prompt-mechanism-study verify \
  data/method/results/prompt-tsg-external-extraction-v4
# VERIFIED

prompt-mechanism-study verify \
  data/method/results/prompt-tsg-external-qualification-v4
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
