# Five-CWE Main-Prompt Gate C Canary v1

## Purpose

This stage carries the five passed Gate B Prompt blocks into separate Qwen2.5-Coder-7B and
Phi-4-14B outcome-pipeline canaries. It is an engineering validation with one task per CWE, not a
powered effect estimate. Code generation remains pilot-first and each model is analyzed as a
separate stratum.

## Frozen inputs

- Prompt tasks and one-pass functional contracts:
  `data/e2e-pilot/five-cwe-main-prompt-canary-inputs-20260818-09`.
- Qwen assignment stratum:
  `data/e2e-pilot/five-cwe-main-prompt-canary-gate-a-20260818-10`.
- Phi assignment stratum:
  `data/e2e-pilot/five-cwe-main-prompt-canary-gate-a-phi4-14b-20260818-11`.
- Model-independent LLM Prompt variants:
  `data/e2e-pilot/five-cwe-main-prompt-canary-gate-b-control-blind-20260818-03`.

The Qwen and Phi Gate A `variants.jsonl` and `candidates.jsonl` files have identical SHA-256
digests. Their assignment ledgers differ by registered model stratum, as required.

## Append-suffix provenance adapter

The historical direct Gate B adapter authenticated raw responses containing a complete
`candidate_text`. The current Gate B stores only `append_suffix`. The updated adapter accepts both
explicit envelopes. For the suffix envelope it requires the mode to agree in the variant and raw
request, requires the raw response to contain exactly the single suffix key, rejects empty or
source-repeating suffixes, reconstructs `source_prompt + append_suffix`, and then applies the
existing Prompt hash and closed-manifest checks.

## Execution order

1. Build both zero-provider Gate C plans and validate all 20 assignments per model.
2. Observe GPU, service port, network, and Oracle-tool readiness.
3. Start Qwen 7B, run one pilot unit, inspect the complete generation/Judge/Oracle trace, then run
   the remaining 19 only after an explicit saved authorization delta.
4. Stop Qwen, restore GPU readiness, and repeat for Phi 14B.
5. Preserve every run directory and download closed artifacts before any scale-up decision.

## Error log

- The first local targeted-test command reached collection but did not run tests because a new
  parametrized test used `request`, a name reserved by pytest. No provider call, experiment output,
  or external process was involved. The parameter was renamed to `request_payload`; the complete
  targeted set must be rerun before planning.
- A read-only PowerShell command intended to summarize artifact directory sizes had an invalid
  pipeline placement and stopped at parse time. It created or changed no file. The corrected command
  reported 181 frozen files across the two plans, two preflights, Phi Gate A, and Gate B bundle;
  133 of those files belong to the downloaded Gate B bundle.
- The first Qwen pilot generated code and obtained a one-pass functional judgment, but the integrated
  Oracle invocation reported `ANALYZER_FAILED`. The failed run is preserved at
  `gate-c-main-prompt-canary-qwen7b-live-20260818-01`. Running the same frozen Semgrep and Bandit
  versions directly on the preserved code returned exit status zero, so this was diagnosed as an
  execution-path failure rather than an unsafe/unknown scientific outcome.
- An Oracle-only recovery proved that the analyzer batch could complete without another generation
  or Judge call, but exposed a recovery-path defect: it persisted `oracle-analysis.json` without
  applying the profile-scoped decision, so all three security-label counts remained zero. That
  incomplete recovery is preserved at
  `gate-c-main-prompt-canary-qwen7b-live-oracle-recovered-20260818-02` and is not an approved pilot
  prerequisite. Live and recovery execution now share one profile-decision serializer; preserved
  analyses are strictly reconstructed and validated before reuse. A new immutable recovery must
  produce one decision and exactly one counted security label before the remaining 19 units run.
- The corrected Qwen recovery produced one secure CWE-338 decision with zero new provider calls;
  its remaining phase then closed all 20 units with zero errors. Counts are 15 secure, 5 insecure,
  0 unknown, 12 functional passes, and 12 secure-and-functional outcomes. With one task per CWE,
  these values validate measurement variation but are not an effect estimate. The complete server
  run is archived under its original long name and the manifest-verified local copy uses the shorter
  Windows-safe path `data/e2e-pilot/q7b-gc-20260818-03`.
- Phi completed its pilot and three remaining units before one CWE-89 placebo unit failed closed on
  `ANALYZER_INVALID_OUTPUT` from the Bandit adapter. Generation and the one-pass Judge for that unit
  are preserved. The live Oracle runner previously retained neither analyzer stdout nor a recovery
  route for a failure after the pilot. Analyzer output is now persisted before parsing with a digest,
  and Oracle-only recovery accepts exactly one failed unit when the pilot is already complete. This
  permits diagnosis and repair without regenerating successful or failed code and without repeating
  Judge calls.
- The recorded Bandit 1.9.4 output made the rejection deterministic: B106 reported the password
  argument on line 10 while its legitimate multi-line call range was `[7, 8, 9, 10, 11]`. The
  adapter had incorrectly required the reported issue line to be the first range element. It now
  requires the issue line to occur inside a strictly increasing range, retains that issue line as
  the start coordinate, and retains the final range line as the end coordinate. All authenticated
  rule, CWE, severity, confidence, filename, return-code, and source-boundary checks remain active.
- Resuming after an intermediate-unit Oracle repair also preserves the first failed remaining-phase
  metadata. Continuations allocate monotonically numbered command, configuration, provenance,
  phase, and report artifacts; gaps or unexpected historical names fail validation instead of being
  overwritten.
- A later Phi response was valid JSON but violated the frozen Judge schema by returning more than
  eight evidence lines for two requirements. The original request and sole response remain the
  measurement evidence; no second Judge call is allowed. A provenance-bound invalid-response path
  records the functional outcome as `unknown`, then permits blind Oracle execution. This conservative
  outcome contributes zero to secure-and-functional ITT while remaining separately countable as a
  Judge protocol failure.
- One Phi response contained a complete Python fence whose closing marker had a trailing space,
  followed by explanatory text. The provider already permits one fenced Python block plus trailing
  prose, but rejected harmless trailing whitespace on the closing marker. The bounded decoder now
  strips only trailing spaces and tabs from that marker. Recovery replays the exact persisted Chat
  Completions object through the same provider and confirmation adapters, performs no new generation
  call, and then executes the still-pending single Judge pass and Oracle stages.
- A local regression command initially included the broad confirmation-generation stage file and
  was stopped after it continued beyond the intended targeted-validation window. It made no provider
  calls or experiment changes. The narrowed provider and Gate C set completed with 176 passing tests;
  no full-suite result is claimed.
- The first local cross-model summary checker compared the accumulated count after its first model
  against the frozen two-model total because the final assertion was placed inside the model loop.
  It changed no artifact. Moving that assertion after both per-model validations produced 40 matched
  assignments and exact agreement for every model-by-CWE-by-arm outcome and aggregate count.
- The first pre-commit artifact-check command had an unmatched PowerShell parenthesis in its
  read-only byte-count expression and stopped during parsing, before any check or write ran. The
  simplified command validated 901 JSON/JSONL artifacts, found no credential pattern, and passed the
  diff-format check.

## Completed canary

Both model strata are closed with 20/20 completed assignments, no failed assignment, and no pending
assignment. Project-native completion validation was rerun against the downloaded directories rather
than inferred from filenames. Qwen has 15 secure, 5 insecure, 12 functional-pass, 8 functional-fail,
and 12 secure-and-functional outcomes. Phi has 16 secure, 4 insecure, 13 functional-pass,
5 functional-fail, 2 functional-unknown, and 11 secure-and-functional outcomes. The two functional
unknowns preserve their only Judge responses and count as zero for the joint outcome.

The Qwen archive SHA-256 is
`1c25811a67f2d75f9b035704cd26cfc599daced64d196f52913e594981627525`; its verified local copy is
`data/e2e-pilot/q7b-gc-20260818-03`, and its cumulative terminal report is
`report-remaining.json`. The Phi archive SHA-256 is
`85b7c0cf9479cf324dd6a7d1535ab43f7cc9d9d2f98c1ff861352858c0d600f0`; its verified local copy is
`data/e2e-pilot/p14-gc-20260818-08`, and its cumulative terminal report is
`report-remaining-004.json`. The complete machine-readable cross-model summary is frozen at
`data/e2e-pilot/two-model-main-prompt-gate-c-canary-summary-20260818-09/summary.json`.

The Phi service was stopped after archive verification; port 18101 was closed and no GPU compute
process remained. Because this canary contains only one task per CWE and model stratum, no arm
effect, confidence interval, significance result, or cross-model pooled scientific claim is allowed.
