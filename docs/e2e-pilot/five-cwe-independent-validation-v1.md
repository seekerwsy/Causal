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
- Runtime/analysis freeze v2: `data/e2e-pilot/five-cwe-independent-validation-runtime-analysis-freeze-20260819-02`.
- Standard execution plan: `runs/restricted/five-cwe-independent-validation-execution-plan-phi14b-20260819-01`.

The v2 runtime freeze supersedes v1 without modifying it. It adds the exact generation-provider
runtime fingerprint after the multilingual response parser was connected to the provider. The
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

## Server execution prerequisites

The pilot has not yet been called. Before it runs, record the target host, repository path, output
path, model path, model-service command, GPU state, disk state, port state, environment fingerprint,
and input archive digests. New output directories must be used for every attempt.

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

The next bounded phase contains the other 19 assignments from the already frozen five-task canary.
It authenticates the completed pilot, does not regenerate it, records per-unit elapsed time and
cumulative speed/ETA, and stops at the first error for diagnosis.
