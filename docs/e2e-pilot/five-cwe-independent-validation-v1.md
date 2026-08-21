# Five-CWE independent validation v1

## Frozen question and scope

This run independently tests the previously frozen Phi-4-14B relation
`z.target_mechanism_realized -> y.discovery_functional`. It does not reinterpret the relation as
a complete mediation effect and does not use an Oracle security label as the outcome. The held-out
pool contains 55 task clusters and 220 pre-randomized four-arm assignments across CWE-78, CWE-89,
CWE-502, CWE-328, and CWE-338.

The generation model is Phi-4-14B. Functional behavior is measured once by the frozen arm-blind
Qwen Judge. The code mechanism is measured by the separately calibrated, arm-blind multilingual
facts extractor using `mechanism-operational-definitions-v2`. The primary discovery replication
uses causal-learn FCI/G-square, JCI context restrictions, 200 complete-task-block bootstrap samples,
stability at least 0.8, and failed-bootstrap fraction at most 0.1.

## Local environment and immutable artifacts

- Local worktree: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`.
- Branch: `codex/discovery-v2-mechanism`.
- Python: `D:\MyCode\Causal\.venv\Scripts\python.exe`.
- Gate A: `runs/restricted/five-cwe-independent-validation-gate-a-phi14b-20260819-02`.
- Functional contracts: `runs/restricted/five-cwe-independent-validation-functional-contracts-20260819-02`.
- Superseded runtime/analysis freeze v2: `data/e2e-pilot/five-cwe-independent-validation-runtime-analysis-freeze-20260819-02`.
- Current runtime/analysis freeze v3: `data/e2e-pilot/five-cwe-independent-validation-runtime-analysis-freeze-20260819-03`.
- Standard execution plan: `runs/restricted/five-cwe-independent-validation-execution-plan-phi14b-20260819-01`.

The v2 runtime freeze supersedes v1 without modifying it. It adds the exact generation-provider
runtime fingerprint after the multilingual response parser was connected to the provider. The
v3 freeze supersedes v2 without modifying either historical freeze. It increases the maximum
retained evidence lines for one functional requirement from 8 to 32 after the bounded canary
returned nine valid in-range lines. It does not alter the Judge's status, requirement verdict,
counterexample, blindness, or one-pass policy. Its functional-Judge policy SHA-256 is
`5cffaa26b9fec5daa84eca3e96a94c28b2b5f40f3d40a7121ec866f825371907`.
standard execution plan contains 55 blocks, 220 variants, 220 assignments, 220 generation requests,
and 55 functional contracts. It was created with zero provider calls and zero consumed outcomes.

## Small-first execution sequence

1. Run the frozen CWE-338 Java target-arm assignment only.
2. Inspect source-envelope extraction, functional evidence, mechanism evidence, token usage, and all
   raw transports.
3. If and only if the pilot completes, run the remaining assignments in the five-task/four-language
   canary without rerunning the completed pilot.
4. Diagnose and repair any failure before completing the canary.
5. Run the remaining frozen assignments, then perform the unchanged FCI/JCI and 200-sample task
   bootstrap analysis.

The pilot execution performs at most one generation call, one functional-Judge call, and one
mechanism-extractor call. It performs no Oracle call.

## Targeted validation

- Generated-source extraction and OpenAI-compatible provider regression: passed.
- Multilingual mechanism facts and calibration regression: passed.
- Combined targeted result: 168 passed.
- Ruff import/error checks on changed files: passed.
- Full repository test suite: intentionally not run at this checkpoint.

## Operational error log

- The first runtime config contained a provisional response-parser digest rather than the digest
  computed by the implementation. The zero-call freeze rejected it; the config was corrected before
  any outcome was generated.
- The first freeze implementation referenced a nonexistent configuration property for the system
  template digest. It was replaced with a digest computed from the validated template text.
- During source inspection, guessed paths for `generation/executor.py`,
  `generation/provider_factory.py`, and `prompt-variants.jsonl` did not exist. The actual existing
  implementations and `variants.jsonl` were located before editing.
- A broad confirmation-generation test command was started while checking adjacency regressions and
  ran much longer than the intended small validation. It was terminated without using its partial
  output. The retained validation is the explicit 168-test set above; no full-suite claim is made.
- The first remote pilot attempt stopped before creating its run directory or making a provider
  call. Git archive exported two tracked configuration files as CRLF even though the worktree and
  repository blobs use LF, so their raw-byte digests differed even though their parsed content was
  identical. Text configuration inputs now declare `lf_normalized_text_v1`; manifests and generated
  artifacts retain exact raw-byte digests. A new deployment is used for the repaired attempt.
- The first remaining-canary preflight made no provider call and exposed a nested-manifest checker
  bug. The root run manifest includes each unit's `artifact-manifest.json`, but the checker excluded
  every file with that name rather than only the root manifest being verified. The checker now
  excludes by exact path, and a nested-unit-manifest regression test protects the closure rule.
- The next zero-call preflight found that the canary config's manually copied standard assignment ID
  contained one extra hexadecimal character. Rather than correcting a duplicated identity by hand,
  the batch now reads the sole pilot assignment ID from the closed execution plan and requires exact
  equality with the completed run. The plan remains the single identity authority.
- The first remaining-canary execution completed five new assignments and then stopped on the sixth
  as designed. Generation and the functional Judge both completed, but the local Judge parser
  rejected the response because one requirement cited nine valid source lines while the response
  schema and stored decision allowed only eight. The ninth line was the in-range return statement,
  all five requirement IDs and verdicts were present, and the failure was therefore an overly narrow
  evidence-capacity constraint rather than a semantic Judge failure. The failed run remains at
  `/home/ubuntu/secaware-experiments/runs/five-cwe-independent-validation-phi14b-canary-remaining-20260819-01`
  with 5 complete, 1 error, and 13 unattempted assignments. Runtime freeze v3 lifts only this
  capacity to 32, retains every evidence line, and is validated by a nine-line regression test.

## Server execution prerequisites

The target server, repository and output roots, model path, service command, GPU and disk state,
port, environment fingerprint, and deployment archive digests are recorded with the remote runs.
Every attempt uses a new output directory.

## Completed one-assignment pilot

The repaired remote pilot is stored at
`/home/ubuntu/secaware-experiments/runs/five-cwe-independent-validation-phi14b-pilot-20260819-02`.
It completed 1/1 assignment with zero errors and zero pending assignments. Generation, the
single-pass functional Judge, and the code-mechanism extractor each made one call; no Oracle ran.
The requested Java/XML artifact was extracted as
`src/main/java/com/example/service/SessionService.java`. All five functional requirements were
judged met, and the mechanism extractor identified `cryptographic_rng`, producing `proved_safe` and
`z.target_mechanism_realized=1`.

The root and unit manifests are closed (29 and 20 covered files respectively). Every recorded
request/response digest matches its transport record, and no configured API-key byte sequence occurs
in the run artifacts. This is an engineering execution-chain result, not an arm effect or causal
discovery conclusion.

Because runtime freeze v3 changes the measurement-policy fingerprint, the successful v2 pilot and
the five v2 canary completions remain engineering history but will not be mixed into the independent
validation result. A replacement one-assignment v3 pilot is run first, followed by its remaining 19
canary assignments. The replacement outputs use new directories, record per-unit elapsed time and
cumulative speed/ETA, and still stop at the first error for diagnosis.

## Completed v3 measurement canary

The replacement pilot is stored at
`/home/ubuntu/secaware-experiments/runs/five-cwe-independent-validation-phi14b-pilot-v3-policy-20260819-01`,
and the remaining assignments are stored at
`/home/ubuntu/secaware-experiments/runs/five-cwe-independent-validation-phi14b-canary-remaining-v3-policy-20260819-01`.
Together they contain exactly the 20 assignment IDs in the frozen canary: four arms for one task
from each of the five CWEs, with Python, Java, Go, and C represented. All 20 assignments completed;
generation, the functional Judge, and mechanism extraction each made 20 one-attempt calls, with no
Oracle call. The remaining-19 batch took 175.53 seconds (9.23 seconds per assignment).

The canary contains observable variation rather than constant discovery variables: functional
status is 15 pass and 5 fail, while the mechanism state is 13 `proved_safe` and 7 `proved_unsafe`.
Every arm has five observations. Root and unit manifests close, all recorded transport-payload
digests match, every functional pass binds to the v3 Judge policy, and no configured API-key byte
sequence occurs in an artifact. Functional failures are retained as observed outcomes and are not
execution errors or filters.

The first cumulative audit script incorrectly expected every transport record to use the key
`attempts`; generation records use singular `attempt`, while the two structured transports use
plural `attempts`. The audit was corrected to validate each established schema and then passed.
Likewise, transport digests cover payload bytes while persisted JSON files append one newline; the
audit validates the payload after removing that storage delimiter. These are audit-script issues,
not experiment failures.

The next run authenticates both closed v3 canary directories, requires their disjoint union to equal
the frozen 20-assignment canary, and executes only the remaining 200 assignments from the 220-item
full selection. It retains serial execution and first-error stop behavior; the estimated runtime at
the observed canary rate is approximately 31 minutes before validation and analysis.

## Full-run interruption and no-regeneration recovery

The first full-remaining run is stored at
`/home/ubuntu/secaware-experiments/runs/five-cwe-independent-validation-phi14b-full-remaining-v3-policy-20260819-01`.
It stopped at its first execution error after 37 complete assignments. One additional assignment
completed generation and the single Judge call, then failed local Judge-response validation; 162
assignments remained unattempted. No mechanism call occurred for the failed assignment and no
Oracle ran. The 37 complete assignments, one error, and 162 pending assignments are all preserved.

The failed response is valid JSON but not the required schema. It contains 10,694 persisted bytes,
a 5,814-character repetitive rationale, and malformed top-level keys instead of the required
`status` and `requirements`. The assigned Go program and its frozen contract are present; this is a
functional-Judge response-format failure, not a generation failure. The call lasted about 399
seconds before returning the invalid payload, so the anomaly was inspected rather than attributed
to model randomness.

Gate C already defines and tests the project-wide treatment for this exact condition: preserve and
hash-bind the invalid single-pass response, publish functional `unknown`, make no additional Judge
call, and continue later measurements. The independent-validation runner had omitted that existing
branch. It now reuses the same implementation. A dedicated recovery command copies the immutable
generation and Judge transports to a new run, publishes the provenance-bound `unknown`, and makes
only the missing mechanism-extractor call. It never regenerates code or asks the functional Judge
again. The original failed run is not modified.

After recovery, the resume batch accepts the old ERROR assignment only when the same assignment is
COMPLETE in a separate closed recovery run. Its four prior runs must jointly equal the 20 canary
assignments plus the first 38 assignments attempted by the full run. It will then execute exactly
the remaining 162 assignments. Malformed Judge responses encountered during the resume follow the
same preserved-response-to-unknown policy and therefore remain outcomes/diagnostics rather than
batch execution failures.

The production Python environment does not include pytest; the updated recovery and resume code was
therefore checked in the local fixed environment with 43 focused tests rather than installing new
packages on the experiment server. No full repository suite was run.

## Completed 220-assignment execution and frozen analysis entry

The resume run completed the remaining 162 assignments in 1,459.64 seconds (9.00 seconds per
assignment), with zero execution errors and zero pending assignments. Across the pilot, canary,
first full attempt, recovery, and resume directories, the authenticated completion union contains
exactly the 220 assignments in the frozen 55-task plan: 55 assignments in each of the four arms.
Generation, the single-pass functional Judge, and the code-mechanism extractor each made exactly
220 calls in total; the Oracle made no call. Functional status is 185 pass, 31 fail, and 4 unknown.
The code-mechanism state is 148 `proved_safe`, 62 `proved_unsafe`, 4 `no_relevant_sink`, and 6
`unresolved`. The original ERROR unit is retained and is covered by its separate COMPLETE recovery
unit; it is not silently replaced in place.

The complete server archive is retained as
`five-cwe-independent-validation-phi14b-complete-20260819-01.tar.gz` with SHA-256
`eac45598fd5f8fb30ec3239072a6c8fd820e38d1132454fb9af11f6f729bb0dc`. The analysis table binds
that archive, all five recursive run manifests, the execution-plan manifest, and runtime-freeze v3.
It maps functional `pass` to one and both `fail` and `unknown` to zero, exactly matching the frozen
v3 method-development projection; the original three-valued functional status remains in a
diagnostic field. This step makes no provider or Oracle call.

On Windows, verifying the archive under its original deeply nested extraction path initially failed
because Python could not open paths beyond the local path-length limit. Independent PowerShell
hashing showed that every listed file digest and manifest closure matched. The same authenticated
archive was therefore materialized under short aliases in `runs/iv`; the configuration records the
alias-to-archive-member mapping and the original manifest digest. No digest check was weakened, and
the original extraction remains preserved.

The independent full-sample raw PAG and JCI-constrained PAG both contain zero edges, so neither
contains the frozen tail-arrow `z.target_mechanism_realized -> y.discovery_functional` relation.
This is an interim reference result, not the preregistered replication decision. A three-replicate
engineering bootstrap completed with 3 successes, 0 failures, and 0/3 support, validating complete
task-block resampling and artifact recovery before the configured 200-replicate run.

## Independent replication result

The complete task-cluster bootstrap ran all 200 configured replicates. All 200 FCI runs succeeded,
none failed, and 40 retained an endpoint pattern compatible with the frozen tail-arrow mechanism to
function relation. The resulting support is 20.0%, below the frozen 80% threshold; the frozen
hypothesis is therefore **not replicated**. This is a valid independent result rather than a backend
or data-pipeline failure. The full-sample raw and JCI-constrained PAGs both contain zero edges, in
agreement with the bootstrap decision. No replacement hypothesis was selected from the validation
outcomes.

The predeclared Prompt-only sensitivity removes the code-mechanism variable and reruns the same
G-square FCI/JCI backend on `c.arm` and `y.discovery_functional`. Its raw and constrained PAGs also
contain zero edges, with candidate yield zero. Thus adding Z did not improve stable independent
candidate yield in this sample, although 20% of task-bootstrap resamples recover a compatible Z-to-Y
edge.

Post-replication randomized ITT diagnostics retain all 55 task blocks and all four arms. They are
explicitly explanatory rather than a new preregistered confirmation family. Target patch increases
`z.target_mechanism_realized` from 63.6% to 78.2% relative to no-op, an ITT risk difference of
+14.5 percentage points with a Bonferroni simultaneous percentile interval of +3.0 to +24.3 points.
Relative to the length-matched placebo, the increase is +18.2 points, with an interval of +7.8 to
+32.7 points. Relative to the generic reminder, the point estimate is +10.9 points and its interval
touches zero. The corresponding functional-outcome contrasts are -1.8, -5.5, and -1.8 points; all
three intervals include zero.

The mechanism/function association explains the failed replication. In the 93-task development
population, functional success is 78.4% when Z=1 and 61.3% when Z=0, an unadjusted difference of
+17.1 points. In the independent population, the rates are 82.4% and 87.5%, respectively, a
difference of -5.1 points with a task-cluster interval of -18.7 to +6.9 points. This association is
descriptive, not a causal effect. Together, the randomized and discovery results show that target
patch changes the intended security mechanism, but the previously discovered coupling between that
mechanism and functional success does not transport to the independent task pool.

The first Prompt-only invocation was stopped before FCI because a new reference-directory argument
was accidentally added to the mechanism-analysis function rather than the Prompt-only function.
Static checking detected the unused and undefined variables, no output directory was created, and
the signature was corrected before the successful run. This failure is retained here to prevent the
same parameter-placement error in later sensitivity backends.
