# Five-CWE Gate C outcome pilot v1

## Boundary

This stage is a bounded outcome-pipeline pilot, not a main-effect estimate. It carries the five
validated Gate B task blocks into one local Qwen 2.5 Coder 7B generation per arm. Each of the five
CWE strata contributes one complete four-arm block, for 20 code-generation requests, 20 single-pass
functional-Judge opportunities, and at most 20 profile-scoped Oracle executions.

The planner now supports two explicit Gate B artifact schemas. The historical
`revalidation_v1` adapter remains the default. `direct_exploratory_v1` accepts the new completed
Gate B directory only after authenticating its closed manifest, all 20 intervention request/response
pairs, exact candidate Prompt text, source Prompt hashes, 20 passed validation records, and exact
Gate A variant identities. No schema is inferred automatically.

Task selection is bounded to two through five independent tasks and still requires a complete
four-arm block per task. The configured block, assignment, generation, and Judge budgets must equal
the derived task count before a plan can be written. The 20 existing audited functional contracts
are treated as a registry; the planner freezes only the five selected contracts into the plan.

## Gate B result and diagnostic audit

`five-cwe-gate-b-balanced-target-format-20260818-05` passed with five tasks, 20 variants, 38 exact
reuses, seven live calls, no errors, and no length-control failures. Its 170 manifest entries all
matched their saved SHA-256 values. Two task-projection drift diagnostics were inspected rather than
attributed to randomness. In both cases the allegedly absent task phrase remains byte-for-byte in
the preserved source prefix; the suffixes add only the intended CWE-502 safety mechanism or the
CWE-328 presentation placebo. The separate drift-audit JSON classifies both as extractor false
negatives on unchanged source text.

## Zero-call plan attempts

The first plan stopped before generation or Oracle execution because the CWE-338 source uses the
feature-catalog task-family spelling `security_random_generation`, while the calibrated profile
registered only the older alias `security_randomness`. The profile contract now registers both
spellings. Its decision backend, analyzer rule, zero-finding policy, and nine calibration fixture
identities are unchanged; the policy lock was updated for the scope metadata change.

The second plan completed with five authenticated blocks, 20 assignments, 20 unique generation
requests, five audited functional contracts, and five profile-scoped Oracle profiles. All 20 units
remain pending and both provider and Oracle execution are disabled in the plan artifact. The next
step is targeted code verification, a real nine-fixture CWE-338 profile recalibration under the new
policy digest, and one live Gate C pilot unit before the remaining 19 units can be considered.
