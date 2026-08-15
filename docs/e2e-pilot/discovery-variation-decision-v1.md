# Discovery variation decision v1

## Decision status

As of 2026-08-14, scaling Prompt extraction over the existing natural Python pool is not
approved. This is a design limitation in the available prompt distribution, not a shortage of raw
records and not a reason to relax FCI, G-square, provenance, or hypothesis-freeze gates.

## Evidence produced in this stage

The initial CyberSecEval v2 discovery pool contained 48 independent candidates across CWE-78 and
CWE-89. The deterministic catalog yielded no usable marginal variation. An eight-task,
outcome-blind LLM-facts canary was then frozen and audited before scale-up.

The LLM-facts protocol was revised only at the extraction trust boundary:

1. the deterministic FeatureSpec catalog projects the feature IDs applicable to the prompt's CWE
   and task family;
2. the LLM returns one PRESENT/ABSENT fact for every projected feature and an exact unique quote
   for every PRESENT fact;
3. the validator derives offsets and SHA-256 digests locally and rejects missing, extra,
   duplicated, fabricated, or non-unique evidence;
4. the deterministic catalog adds NOT_APPLICABLE facts for the remaining closed-world features;
5. the existing proposal validator and Prompt-TSG builder remain the publication boundary.

The first protocol stability run produced 4/8 valid responses. After applicability projection, the
second independent run produced 8/8 valid responses, with no provider errors and no retries. The
formal atomic stage then committed eight proposals and eight Prompt-TSGs under one extractor-policy
digest.

Against a frozen outcome-blind semantic audit, target-task recall was 2/8 for the deterministic
catalog and 7/8 for the LLM facts extractor. Both extractors correctly kept all eight scoped safety
features ABSENT. One LLM false negative concerned a `ps` command task that still requires process
launch. Therefore the apparent within-CWE target variation was not accepted as real variation.

The natural-variation audit was then broadened to deduplicated, independent, Python,
candidate-neutral records from CyberSecEval, CWEval, SALLM, and SecurityEval. The exact-duplicate
`cyberseceval_secure_code` source was excluded. Results were:

| Scope | Independent tasks | Safety-feature PRESENT | Broad phrase candidates |
|---|---:|---:|---:|
| CWE-78 / CWE-89 | 87 | 0 | 0 |
| CWE-20 / CWE-22 / CWE-502 | 59 | 0 | 0 |
| Total | 146 | 0 | 0 |

The CWE-78/89 audit was replayed after the script was generalized; its feature-row artifact was
byte-identical to the original. All audit runs saved their configuration, command, environment,
selection, exclusion, proposal, TSG, feature-row, distribution, and report artifacts in separate
directories.

## Why the current observational discovery cannot simply proceed

Within each CWE scope, the safety-control variable is constant ABSENT. Adding more records from the
same distribution does not make a constant column identifiable. Laplace smoothing, a different CI
test, FDR correction, or a larger bootstrap budget cannot manufacture treatment variation.
Cross-CWE pooling would turn NOT_APPLICABLE states and task-family differences into structural
confounding and is therefore not an acceptable shortcut.

The existing JCI implementation is also not an escape hatch. It consumes the already frozen
confirmation experiment and is explicitly secondary. It cannot select, alter, or replace frozen
hypotheses or the primary randomized ITT analysis.

## External dataset classification

The following classification is based on public primary project documentation inspected on
2026-08-14.

| Dataset | Relevant asset | Recommended SecAware role | Main incompatibility with primary discovery |
|---|---|---|---|
| CyberSecEval Instruct v2 | cleaned natural secure-code-generation instructions | Python baseline, Oracle calibration, confirm task source | no prompt-side safety-control arms |
| SecCodeBench | 98 project tasks, including 13 Python, in native/security-aware generation and fix modes | small external confirmation or replication; functional/PoC oracle reference | too few Python tasks per CWE; modes are designed interventions |
| SecRepoBench | 318 C/C++ repository tasks and four prompt types | future C/C++ four-arm external replication | requires repository build, unit-test, and PoC execution infrastructure |
| CodeGuard+ | 91 Python/C/C++ prompts with unit tests and CodeQL queries | functional-contract and Oracle calibration candidate | perturbed prompt set is publicly marked pending |
| ICSE 2026 THEA evaluation | CyberSecEval over 30 vulnerability types | comparison of evaluation breadth and intervention reporting | model-execution intervention, not prompt-feature variation |

Primary source URLs:

- https://github.com/meta-llama/PurpleLlama/blob/main/CybersecurityBenchmarks/README.md
- https://github.com/alibaba/sec-code-bench
- https://github.com/ai-sec-lab/SecRepoBench
- https://github.com/CodeGuardPlus/CodeGuardPlus
- https://conf.researchr.org/details/icse-2026/icse-2026-research-track/168/Repairing-LLM-Executions-for-Secure-Automatic-Programming

## Method decision

On 2026-08-15 the randomized exploratory-discovery path was approved for a bounded engineering
canary. This is not yet approval to replace the primary discovery design or run a scaled
experiment. The frozen canary boundaries and ordered gates are specified in
`docs/superpowers/specs/2026-08-15-randomized-exploratory-discovery-canary-design.md`.

Two defensible paths remain.

### Recommended: add a preregistered exploratory randomized-discovery phase

Keep the existing observational FCI run as a baseline and availability diagnostic. On a dedicated
discovery pool, randomize outcome-blind prompt variants that add or remove one finite FeatureSpec,
plus the relevant controls. Represent randomized assignment as a discovery-context variable and run
a separately labeled constrained structural analysis. Freeze candidates using only this discovery
pool. Keep the held-out four-arm confirmation pool and task-clustered ITT unchanged.

This requires an explicit specification change because the current JCI stage is confirm-only and
must not select hypotheses. The new stage must have separate artifacts, assumptions, multiplicity
budget, and train/discovery/confirmation boundaries. It must not reuse confirmation outcomes or
silently call randomized discovery "observational FCI."

### Conservative fallback: make discovery descriptive and confirmation preregistered

Retain observational FCI as a diagnostic that may legitimately yield no hypotheses. Pre-register a
small finite set of theory/catalog-driven FeatureSpecs and test them only in held-out randomized
confirmation. This preserves the current pipeline boundary but weakens the paper's claim from
data-driven causal discovery to graph-constrained hypothesis operationalization and randomized
confirmation.

The approval authorizes paid calls only for the bounded canary after its zero-provider gate passes.
It does not authorize additional paid extraction over the full 146-task natural pool or a scaled
randomized-discovery run.

## Execution incident log

The following incidents are retained so later stages do not repeat them:

| Incident | Impact | Root cause | Resolution |
|---|---|---|---|
| Initial read-only commands were denied by the Windows sandbox | no project mutation and no API call | child-process launch permission | reran the same scoped read checks through the approved project path |
| Two extractor-contract tests failed after `enable_thinking` was added | 67/69 tests passed on the first targeted run | exact-field assertions retained the old configuration contract | added `enable_thinking` to both contract assertions; the next targeted run passed 69/69 |
| First LLM-facts production attempt failed on its first response | zero proposals published; seven requests were not sent | the prompt omitted exact evidence keys and prompt context, and incorrectly asked the LLM to compute SHA-256 | kept the failed v1 run; added an isolated raw-response diagnostic; made the validator derive the digest |
| Second isolated response failed | no formal artifact published | the model miscounted Unicode character offsets | changed model evidence to a unique exact quote; the validator derives offsets and the digest |
| First eight-task stability run produced only 4/8 valid proposals | all eight diagnostic responses were preserved; no formal TSG publication | the LLM confused ABSENT with NOT_APPLICABLE across twenty catalog features | the deterministic FeatureSpec layer now projects only applicable features and fills NOT_APPLICABLE after validation; the next independent run passed 8/8 |
| First v3 launcher invocation failed before execution | no API request and no run directory | a PowerShell expression supplied `-LiteralPath` twice without grouping | split the expression into two grouped `Test-Path` calls, parsed the script, and completed the formal run |
| Ruff was unavailable in the fixed Python 3.12 environment | no runtime or test failure | the environment intentionally lacks that optional development command | did not mutate the environment mid-run; used `py_compile`, `git diff --check`, and targeted/adjacent pytest gates |
| Gate B micro v1 rejected its first generic-reminder arm | the run stopped before target-arm feasibility could be measured | the validator incorrectly required the generic reminder to be recognized as `PRESENT`, although this control is a diagnostic rather than the target mechanism | retained the failed run and made generic-reminder realization diagnostic while preserving AllowedDelta and target-state hard gates |
| Gate B micro v1 and v2 failed on the CWE-89 target arm | no candidate was admitted | the intervention model treated the embedded source prompt as an instruction to solve and returned code instead of an edited prompt | retained both failed runs and introduced the v3 inert-data boundary, exact-source-prefix requirement, and prompt-editing-only system contract |
| Gate B micro v3 stopped on the fifth of eight planned variants | four CWE-89 variants validated; the remaining three CWE-78 variants were not sent | the source extractor labeled `task.process_launch` `ABSENT`, then labeled it `PRESENT` after a generic reminder was appended even though the source text was preserved byte-for-byte | classify this as extractor task-projection drift; future validation will keep append-only text and security-layer AllowedDelta as hard gates while reporting independently extracted task-layer drift as a diagnostic |
| Three read-only inspection commands failed during v3 diagnosis and pre-commit checking | no artifact or project file was changed | one command used an invalid in-memory hashing overload, one contained an empty pipeline element, and one passed Windows wildcard paths directly to `rg` | replaced them with simpler metadata-only reads and `rg -g` path filtering; retained this note to avoid reusing those command forms |
| First v4 offline replay failed before validation | no API call and no project mutation | the intervention request intentionally stores an AllowedDelta projection, not the complete `AllowedDeltaRecord` required by the validator | joined the request to the immutable Gate A variant by `exploratory_variant_id` and replayed with the complete frozen record |
| First strict-reuse preflight stopped before replay | no API call; no response was imported | raw effective-configuration digests differed because `run.output_dir` is resolved to each distinct run directory | compare a canonical policy-configuration digest that excludes only `run.output_dir`, retain both raw file digests for provenance, and continue to require exact request-byte equality |
| Second strict-reuse preflight stopped before the first variant extraction | no API call; two source responses and one intervention response were reused | the longer preflight directory plus a full content-addressed variant label exceeded the Windows path limit before the extractor request could be written | use a deterministic 32-hex SHA-256 artifact stem on disk, retain the full label in provenance, and support both the v3 long-name layout and the new short-name layout when reusing artifacts |
| Two follow-up read-only diagnostics referenced files or directories that did not exist after the early stop | no artifact or project mutation | the inspection assumed a validation directory and a specific variant reuse filename had already been created | list actual run contents first and treat absent partial-run directories as zero-count diagnostics |
| First six-call completion process was terminated during its first unavailable intervention | twelve prior calls were reused and one request was persisted, but no new response or terminal report was written; the provider may have observed one orphaned request | the execution-session handle was lost during an environment refresh and no matching Python process remained | preserve `runs/e2e-pilot/gate-b-v4-resume-live-20260815-01` as an incomplete attempt, do not treat it as reusable evidence, and restart once in a new directory while reporting the possible orphaned provider attempt separately |
| The authorized six-call completion run failed its final target gate | seven of eight variants passed; Gate C remained blocked | the CWE-78 target candidate preserved the source exactly and appended the reviewed safe-subprocess clause, but the blind extractor still labeled `safety.safe_subprocess` `ABSENT` and also changed `task.process_launch` relative to the source extraction | classify the intervention as operationally correct and the current LLM-facts extractor as insufficiently sensitive for this mechanism; do not override the blind graph or silently admit the candidate |
| One target-suffix diagnostic initially treated `source_prompt` as a string | no artifact or project mutation | the structured request stores the text under `source_prompt.content` | reran the metadata-only diagnostic with the correct field and recorded only the appended suffix |
| The first complete re-extraction plan had ten arm records but only eight request artifacts | zero provider calls; the incomplete plan is preserved | two pairs of identical no-op/placebo Prompt IDs caused request filenames and arm metadata to collide | key artifacts and extraction state by source/variant identity rather than Prompt ID, and fail closed on any artifact-identity collision |
| The corrected ten-arm plan contained only eight unique extractor request byte sequences | zero provider calls; re-extraction was not authorized | for both tasks, the LLM intervention returned a zero-length suffix for `length_matched_placebo`, exactly duplicating the `noop_rewrite`, while target suffixes were 57 and 55 characters | treat both placebo arms as intervention-protocol failures; do not spend extractor calls or let improved extraction mask the invalid control; freeze an explicit length-matching tolerance before regenerating only the two placebo variants |

All failed attempts, diagnostics, stability runs, and the final atomic run use distinct directories.
No historical artifact was forced, edited in place, or deleted.

## Gate B micro v3 status

The preserved run is
`runs/e2e-pilot/randomized-exploratory-gate-b-micro-v3-20260815-01`. It made twelve
successful provider calls: two source extractions, five prompt interventions, and five blind variant
extractions. Four complete CWE-89 arm units passed. The fifth unit, the CWE-78 generic-reminder
control, passed the exact-source-prefix boundary and realized the generic security reminder, but was
rejected because the independent extractor changed a task-feature state. There were zero provider
or transport errors, zero code-generation calls, one validation failure, and three variants not run.

No automatic retry is permitted for this run. The next implementation revision must preserve v3 as
historical evidence, emit task-projection drift explicitly, and be reviewed locally before any new
paid micro run. This result does not authorize Gate C or a scaled experiment.

The v4 implementation was then checked offline against two preserved v3 units without any provider
call. The previously accepted CWE-89 target arm remained accepted with only
`safety.sql_parameterization` changed. The stopped CWE-78 generic-reminder arm was accepted with
only `safety.generic_security_reminder` counted as a validated non-task change, while
`task.process_launch` was emitted separately as extractor drift. No v4 paid run has been started.

The final zero-provider strict-reuse preflight is preserved at
`runs/e2e-pilot/gate-b-v4-resume-preflight-20260815-03`. It reused twelve exact request/response
pairs (two source extractions, five interventions, and five variant extractions), revalidated all
five existing variants as `PASSED`, made zero provider calls, and then stopped at the first of the
three unavailable CWE-78 interventions because live calls were disabled. This is the required
precondition for the bounded six-call completion run.

The authorized completion attempt is preserved at
`runs/e2e-pilot/gate-b-v4-resume-live-20260815-02`. It reused the same twelve historical calls and
completed six new provider calls: three interventions and three blind variant extractions. All eight
variants received validation artifacts. Seven passed. The CWE-78 `target_patch` failed only
`TARGET_VARIATION_VIOLATION`: its source prefix was exact and its 55-character suffix was the
reviewed requirement to pass arguments as a list and run without a shell, while the blind extractor
reported `safety.safe_subprocess=ABSENT`. The run therefore remains `GATE_B_FAILED`, no code was
generated, and Gate C is not authorized. The earlier interrupted attempt may add one orphaned
provider request to the accounting upper bound.

The admitted semantic-facts extractor subsequently passed an independent six-Prompt CWE-78/CWE-89
extension, but a zero-provider audit blocked immediate re-extraction of the saved Gate B texts. Both
`length_matched_placebo` variants are byte-identical to their corresponding no-op variants and add
zero characters, whereas the target additions contain 57 and 55 characters. The current Gate B
validator checked task/safety feature invariants but did not operationalize the placebo length
requirement. The two zero-provider plans are preserved separately; no re-extraction provider call
was made. The placebo variants must be regenerated under a preregistered quantitative length rule
before the complete Gate B block can be admitted.
