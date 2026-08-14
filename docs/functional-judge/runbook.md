# Functional Audit and Blind Judge Runbook

## Frozen boundaries

- Prompt TSG remains the only discovery graph. Generated code never becomes a causal TSG.
- Task functional contracts are frozen before prompt intervention and code generation.
- The functional judge sees only the task contract, language, environment dependencies, numbered
  program lines,
  and output schema. Arm, CWE, security result, generator model, seed, assignment ID, and task ID
  are withheld from its request.
- Security Oracle findings never enter the judge request or functional contract.
- The program-functional result changes `functional_ok` and `secure_functional_success`; it does
  not change the CWE security result.
- All assigned arms remain in ITT. Judge `unknown` is primary zero plus sensitivity uncertainty.

## Pilot artifacts

Environment:

- Machine: local Windows workstation
- Workspace: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`
- Branch: `codex/dataset-adjudication-stage1`
- Python: `D:\MyCode\Causal\.venv\Scripts\python.exe`
- Fixed runtime: Python 3.12

Immutable runs:

- Packet run: `runs/functional-audit/pilot-packets-20260812-01`
- Codex decision input: `runs/functional-audit-inputs/pilot-codex-20260812-01`
- Contract run: `runs/functional-audit/pilot-contracts-20260812-01`
- Versioned snapshot: `data/functional-audit/pilot-v1`
- Source: `runs/dataset-audit/stage0-combined-20260810-08/record-audit.jsonl`

Published counts:

- CWE scopes: 16
- Packets: 48
- Codex A/B decisions: 96
- Consistent contracts: 48
- Failed/pending: 0/0
- Judgeability: 48 semantic-only, 0 executable, 0 unjudgeable
- Contracts with explicit environment dependencies: 30
- Requirements: 44 one-requirement contracts and 4 two-requirement contracts

The contract bundle SHA-256 is
`77983120356ca6bdb9dfe22b349f34fbfe096d7d35eb8356be8d8ec297c1d0bf`.
The audit corrected four source-language mismatches based on exact prompt text: records 80, 383,
1504, and 1217.

## Runtime procedure

1. Start from the frozen evaluator coordinates in `configs/paper_v0.yaml`: Ali Bailian's Beijing
   pay-as-you-go OpenAI-compatible endpoint, dated model snapshot
   `qwen3.5-flash-2026-02-23`, `enable_thinking: false`, zero temperature, credential environment
   variable `ALI_BAILIAN_API_KEY`, primary `single_pass` mode, and seed 73001. The separately
   versioned `configs/functional-judge/two-pass-sensitivity-v1.yaml` configuration uses
   `two_pass_consensus` with seeds 73001/73002 for sensitivity analysis only.
2. Point `data.task_functional_contracts_path` to a contract bundle whose task IDs exactly cover
   the randomized assignment tasks.
3. Set the credential only in the declared environment variable. It must never appear in config,
   logs, requests, manifests, or artifacts.
4. Run `secaware preflight`. Missing credential, missing contracts, malformed contracts, or an
   incomplete config fails before generation/judging.
5. Run the frozen prompt variant, randomization, generation, confirmation Oracle, and
   `judge-functionality` stages.
6. Inspect `analysis/functional_judge_passes.jsonl`,
   `analysis/program_functional_outcomes.jsonl`, and `.stages/judge-functionality.json`.
7. Run `confirm`; inspect `functional_outcome_status` in assignment outcomes and primary/sensitivity
   bounds in ITT effects.

## Current execution status

The primary evaluator coordinates are frozen and passed two real single-pass validations. The
immutable `runs/functional-judge-canary/bailian-qwen35flash-single-lines-20260814-01` run matched
the expected pass/fail decisions on two minimal fixtures. The research-task calibration
`runs/functional-judge-canary/bailian-qwen35flash-single-research-20260814-05` matched all ten
human-frozen decisions across five CyberSecEval Instruct v2 task clusters and CWE-78/89/94/502.
It produced ten pass records, ten outcomes, and ten request/response traces under one evaluator
policy. This calibrates Judge behavior on clear semantic-only examples; it is not intervention
effect evidence and is excluded from ITT estimates.

The Judge returns bounded integer source-line numbers rather than copied code. Local validation
rejects booleans, duplicates, out-of-range values, blank lines, and excess evidence, then resolves
accepted line numbers to exact source strings for provenance. This avoids treating the LLM as a
reliable source-code renderer while retaining inspectable evidence. The earlier immutable
two-pass run `bailian-qwen35flash-20260812-04` remains the sensitivity-mode transport record.

Record every later validation or experiment invocation in a new immutable run directory; do not
overwrite the pilot contract audit or any API run. Local fake-transport tests additionally verify
exact request blindness, single-pass publication, two-pass sensitivity consensus, disagreement to
unknown, bounded line-number evidence and deterministic resolution, no-code handling, Python
syntax gating, complete success/report recovery, and the effect on the primary outcome and ITT
sensitivity.

## Error ledger

1. Initial nested requirement hashing was not JSON-normalized. Fixed by canonical model dumping;
   the same small tests were rerun.
2. Adding a nullable Judge status initially changed legacy v1.0 outcome hashes. Fixed with explicit
   v1.0/v1.1 schema evolution; legacy golden hashes remain unchanged.
3. JSON response arrays initially failed strict tuple validation. Fixed with bounded tuple
   snapshotting before semantic validation.
4. The first invalid-Python test forged an internally inconsistent code record. Replaced it with a
   valid canonical record whose code text is syntactically invalid, and added exact model
   revalidation at the Judge boundary.
5. A first adjacent-test command named a nonexistent test file. The filename was corrected before
   rerunning; no artifact or result was changed.
6. The worktree has no private `.venv`; the first verification command therefore did not start.
   The shared project interpreter was then used with the worktree `src` directory explicitly first
   on `PYTHONPATH`, preventing its editable install from resolving the main workspace package.
7. One combined effects/run-all/preflight/packaging invocation reached its five-minute command
   limit without a test result. The suite was split by file: core contracts/Judge/ITT, preflight,
   packaging, the complete effect transaction, Judge-disabled compatibility, and Judge-enabled
   run-all order were rerun independently. No timeout is counted as a pass.
8. Persisted task contracts initially exposed a read/write asymmetry: strict tuple fields were
   serialized as JSON arrays but not normalized on read. Array-to-tuple normalization was added at
   the schema boundary; the published 96 decisions and 48 contract contents were not changed.
9. The first transaction-level Judge test found that its upstream prompt-variant commitment check
   omitted the frozen feature-catalog digest. The same catalog binding used by downstream effects
   was added before accepting the producer bundle.
10. The local no-pass validation branch constructed a set containing mutable sets. It was replaced
    with an explicit empty-or-exact-`A/B` check and rerun through the transaction-level test.
11. The first offline transaction assertion expected `unknown` for unjudgeable contracts, but the
    test generator had produced terminal/no-code results. The existing priority rule correctly
    returns `fail` before the unjudgeable branch; the assertion was corrected without changing the
    evaluator policy.
12. The shared Python environment used for the Bailian adapter validation does not contain Ruff,
    so the requested format/check command did not start. This is not counted as a pass; syntax
    compilation and targeted/adjacent pytest verification are run instead, and formatting remains
    an explicit release-gate item in an environment that includes the development extra.
13. A later validation command again referenced `.venv\\Scripts\\python.exe` relative to the
    worktree, which has no worktree-local environment. PowerShell treated the missing path as a
    module name and neither check started. Worktree commands must use the fixed repository-root
    interpreter `D:\\MyCode\\Causal\\.venv\\Scripts\\python.exe`.
14. The corrected interpreter path was first reused without placing the worktree `src` directory
    ahead of its editable main-workspace installation. Test collection therefore imported stale
    modules and failed before executing tests. This repeated the import-path class of error in item
    6; all subsequent commands must set `PYTHONPATH` to the resolved worktree `src` directory in
    the same process invocation.
15. The first no-credential canary preflight exposed an entrypoint-only import error:
    `GenerationConfig` was imported from the generation schema rather than the existing central
    config module. The API was not contacted and no run directory was created. The import was
    corrected before rerunning the immutable preflight, and entrypoint import/execution is now an
    explicit validation step rather than relying on bytecode compilation alone.
16. A post-format combined adjacent-regression command reached its 184-second command limit
    without returning a pytest result. It is not counted as a pass or failure. The already-passing
    62-test transport/Judge/canary group remains valid; the remaining outcome/effect, preflight,
    packaging, prompt-freeze, and run-all groups are rerun separately to obtain terminal results.
17. The first split outcome/effect group also reached its 124-second limit. Process inspection
    found both the wrapper and child Python processes still running the exact timed-out pytest
    command. Only those verified orphan processes were terminated before switching to per-file
    verbose runs; no unrelated Python process was stopped.
18. The first real Bailian canary attempt stopped before any HTTP request because the fixed Python
    environment did not contain the repository's declared `api` optional dependency (`openai`).
    The transport correctly returned a typed configuration error, but its construction happened
    just outside the canary's persistence boundary, leaving the immutable `-01` run with startup
    artifacts but no terminal report. Client construction was moved inside the persisted boundary,
    a regression test was added, and the missing declared dependency is installed before a new
    `-02` run; `-01` is retained as failure history and never reused.
19. The `-02` canary authenticated and received a model response, but the first functional pass
    failed the strict response/evidence validator before any case completed. The production
    transport intentionally exposes only response bytes and the Judge persists only hashes, so the
    canary now wraps the unchanged transport with validation-only raw request/response capture.
    This trace contains no credential and is used only to diagnose provider-schema compatibility in
    a new immutable `-03` run; it is not a production or paper outcome artifact.
20. The `-03` trace isolated the incompatibility: the model's decision, requirement ID, rationale,
    and evidence text were correct, but it emitted the single `code_evidence` value as a JSON
    string rather than the required array of strings. The strict parser is intentionally not
    relaxed. The system template now states the array invariant with valid and invalid JSON forms;
    its content hash changes accordingly before a new immutable `-04` compatibility run.
21. All four `-04` model judgments completed and passed their strict validators, but final report
    hashing rejected the in-memory tuple of case inputs because the canonical JSON hasher accepts
    lists. The four pass records, two outcomes, four traces, and PASS terminal event were already
    persisted and scanned clean. Case inputs are now held as a JSON list, a complete offline success
    test covers final hashing, and `--finalize-existing` can add only the missing report after
    validating all persisted cardinalities, A/B coverage, statuses, request/response hashes, and
    evaluator provenance. It performs no API call and refuses to overwrite an existing report.
22. The final wheel isolation gate found that the Judge prompt was included in the wheel but loaded
    through a filesystem-only `Path`, which fails for direct zip/wheel imports. The loader now uses
    `importlib.resources`, matching the existing extractor template loaders; prompt bytes and policy
    hash remain unchanged. The wheel test now requires this prompt to be packaged, hash-matched,
    secret-scanned, and loadable from an isolated wheel.
23. Direct process creation with the worktree as `cwd` was denied by the Windows sandbox. Commands
    now start from the repository root and explicitly enter the worktree; this environment failure
    is not counted as a code-test result.
24. A combined preflight invocation was initially started from the main repository root, so 28
    Oracle policy-relative-path cases reported `POLICY_MISMATCH`. The Judge tests in that command
    passed; preflight is rerun from the worktree before release and the wrong-directory failures are
    retained as operator error rather than product failures.
25. External canary cases initially used `case_id` as the assignment task ID, which conflicts with
    the frozen contract task ID. The loop now preserves the contract task ID and records case ID
    only as a calibration label; an offline regression test covers the distinction.
26. Research calibration v1 completed all ten calls but matched 8/10. One supposed pass fixture had
    undeclared GUI collaborators and was corrected through explicit dependency injection. The
    second false negative invented missing-key and shape-validation obligations absent from the
    contract; the prompt now evaluates contract-satisfying inputs without adding robustness duties.
27. Runs `-02`, `-03`, and `-04` showed three forms of unstable evidence copying: an inserted
    ellipsis, removed indentation, and reformatted multi-line source. Each was rejected by strict
    validation and preserved. Rather than stacking copy rules, the response schema now uses source
    line numbers with deterministic local evidence resolution. The two-case and 10-case line-number
    runs both passed.
