# Full functional-contract quality review

## Evidence boundary

This is an outcome-blind dataset-preparation audit. It does not establish an
experimental effect or final experiment eligibility. The reviewer received only
the source prompt, recorded language, and proposed functional contract. It did
not receive CWE, arm, generated code, Security Oracle output, Functional Judge
output, or experiment outcome.

Evidence types:

- `preexisting_artifact`: 2,165 content-addressed contracts in
  `.codex-runtime/gate-c-contracts-complete/contracts-full/final`;
- `newly_run`: the 433-batch full blind review in
  `.codex-runtime/contract-quality-triage-37acead-20260831-03-r6-closed`;
- `newly_run`: the deterministic response-format repair bundle in
  `.codex-runtime/contract-repair-7c9dc1c-20260831-05`;
- `newly_run`: the diagnostic case audit recorded in
  `data/dataset-curation/contract-quality-case-audit-v1.json`.

The full review used `qwen3.7-max-2026-05-20`, five contracts per request,
strict structured output, and the policy frozen at commit `37acead`. The final
bundle SHA-256 is
`137f94f6b629585f60308d927496b4ae980bd4b8e1efcadc50ebbb71478623cc`.
The complete transported archive has matching local and server SHA-256
`469b17d5d6b20fd0f3c49337d2d43d1772273c8a211337633d3e2e3e59d158e0`.

## Closure checks

- 433/433 batch bundles are `COMPLETE` in the final run.
- 2,165/2,165 contracts have exactly one review.
- Contract task-unit IDs and review task-unit IDs are unique.
- Every review binds the exact contract ID and record ID.
- Every contract prompt hash matches its prepared source record.
- The binding-error count is zero.

Two intermediate runs closed provider failures with no returned model text. A
third run closed one structurally complete response because its diagnostic
reason exceeded the old 2,000-character parser bound. These failures remain in
their original run roots. Only complete batches were reused. The overlength
batch was re-requested in a new run rather than silently truncated. This output
instability is a protocol risk and is one reason the LLM review is triage rather
than an automatic admission authority.

## Full-population findings

| Result | Count |
|---|---:|
| contracts reviewed | 2,165 |
| LLM `faithful` | 1,667 |
| LLM `faulty` | 498 |
| functionality `sufficient` | 1,378 |
| functionality `limited` | 769 |
| functionality `insufficient` | 18 |
| deterministic response-format leaks | 71 |
| strict reviewer-qualified candidates | 1,203 |

`reviewer-qualified` means only: no deterministic leak, LLM `faithful`, and
LLM `sufficient`. It does not mean independently verified semantic quality.
The earlier 25-contract development pilot measured only 4/6 fault precision
and 4/6 fault recall, so the 1,203 count cannot be used as an automatic final
sample.

The 71 response-format leaks were repaired in a successor bundle at commit
`7c9dc1c`. All 2,165 task units were retained, the 71 corrected contracts were
given new content IDs, and the remaining marker count is zero. The repair
bundle SHA-256 is
`1b081f1f693fdd68ab1cf14c1caf42f91afa35372f844d8addae64860111e894`.
This deterministic repair does not resolve other semantic defects.

## Intersection with the active Python candidate census

The currently frozen Python census contains 373 task units in ten CWE scopes.
Its intersection with the full review is:

| CWE | Total | Reviewer-qualified | Faithful | Sufficient | Limited | Insufficient | Format leak |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-22 | 33 | 26 | 28 | 29 | 4 | 0 | 0 |
| CWE-328 | 25 | 13 | 18 | 15 | 10 | 0 | 2 |
| CWE-338 | 36 | 22 | 30 | 25 | 11 | 0 | 0 |
| CWE-502 | 68 | 45 | 61 | 48 | 19 | 1 | 1 |
| CWE-611 | 13 | 9 | 10 | 11 | 2 | 0 | 0 |
| CWE-732 | 10 | 9 | 10 | 9 | 1 | 0 | 0 |
| CWE-78 | 95 | 52 | 73 | 63 | 32 | 0 | 3 |
| CWE-798 | 39 | 11 | 32 | 13 | 26 | 0 | 1 |
| CWE-89 | 49 | 24 | 32 | 26 | 23 | 0 | 7 |
| CWE-918 | 5 | 5 | 5 | 5 | 0 | 0 | 0 |
| **Total** | **373** | **216** | **299** | **244** | **128** | **1** | **14** |

Four of these 373 task units were exposed while the review policy was being
developed and require independent adjudication or exclusion from confirmation.

## Diagnostic case audit

All 18 `insufficient` cases were inspected. The diagnostic disposition was:

- 7 language or framework metadata defects that should be repaired and then
  reassessed;
- 6 prompts that are contradictory or incoherent as written and should not be
  admitted unchanged;
- 5 prompts that remain semantically judgeable and are candidates for
  calibration of the frozen Functional Judge rather than automatic exclusion.

A second diagnostic sample selected three reviewer-qualified, non-development
task units from each active CWE, for 30 cases total. It found one clear material
contract omission: the explicit username character constraint in
`semantic_cluster_1368d95f672e7e63088129ac60e0fa9d6b474ac3344ba97b8fac4c617dccdaa4`.
It also found multiple distinct evaluability and CWE/mechanism-scope concerns.
The sample is stratified and diagnostic, not a population precision estimate.
Its exact rules and decisions are in
`data/dataset-curation/contract-quality-case-audit-v1.json`.

## Admission consequence

The correct three-level interpretation is:

1. all 2,165 tasks have now been processed and remain in the reviewed master
   inventory;
2. quality-cleared tasks may enter a study-specific candidate pool after
   independent adjudication, with contract defects repaired rather than source
   tasks silently deleted;
3. final experiment membership still separately requires the frozen language,
   Prompt TSG, MechanismSpec, Security Oracle, positivity, lineage, development
   exclusion, and sampling gates.

Therefore neither 1,203 nor 216 is a final experiment sample size. The current
claim readiness for “all retained tasks have verified functional contracts” is
`blocked`. The supported claim is narrower: every contract was reviewed, the
known deterministic defect class was repaired, and the remaining adjudication
queue is explicit and outcome-blind.
