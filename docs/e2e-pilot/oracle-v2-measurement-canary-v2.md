# Oracle v2 measurement canary

## Scope

This versioned canary replaces the two structurally incompatible v1 tasks without modifying any
historical run. CyberSecEval Instruct v2 record 1658 admits a fixed executable plus argument-vector
implementation for CWE-78. Record 1806 has a fixed `playerinfo` query shape, so CWE-89 can be changed
by value parameterization without introducing a separate identifier intervention.

The canary contains two task clusters, four randomized Prompt arms per cluster, Qwen2.5-Coder-7B as
the first code-generator stratum, one blind Bailian functional-judge pass, and the authenticated
profile-scoped Oracle v2. It is a measurement gate, not a powered causal estimate. The 14B stratum
and main experiment remain blocked until at least one arm yields an evaluable security decision and
the functional contract behaves as intended.

## Oracle decision boundary

The analyzer input contains code identity and code text but no task, arm, assignment, or outcome
coordinate. The finite mechanism trace is extracted first. Only afterward is the pre-treatment
Oracle profile bound by profile ID and CWE. The unit keeps raw analyzer findings, the mechanism
trace, the tri-state profile decision, and the post-analysis assignment binding as separate files.

## Preserved preparation diagnostics

- The first input-build attempt was rejected before output creation because environment dependency
  identifiers were not in the canonical sorted order required by the functional-contract schema.
- The next build completed, but its report reused the legacy assumption that every functional
  contract belonged to a confirm task. The full directory is preserved at
  `runs/e2e-pilot/input-build-measurement-canary-v2-diagnostic-20260818-01`; no prompt, contract, or
  split was wrong. The corrected immutable input bundle reports two discover tasks, zero confirm
  tasks, and two pre-treatment functional contracts.
- The first live Gate B attempt completed eight intervention calls and ten blind extraction calls.
  Both placebo arms copied the source Prompt without adding a suffix, so the frozen length gate
  rejected them; all eight per-record hard validations passed. The failed run is preserved as
  `runs/e2e-pilot/gate-b-measurement-v2-live-20260818-01`. Repair is limited to the two placebo
  variants with the previously reviewed 55-character presentation-only suffix, followed by one
  coherent ten-record blind re-extraction. Accepted non-placebo interventions are not repeated.
- The bounded two-call repair passed 2/2. The subsequent coherent blind re-extraction passed 10/10
  requests and all eight final variant validations, with zero failures and zero pending records.
  Gate C is bound only to the final re-extraction directory; it cannot consume the failed first
  attempt directly.
- The zero-provider Gate C plan closes two blocks, eight unique generation requests, two functional
  contracts, and two calibrated profile-scoped Oracle decisions. The first live unit is the CWE-89
  target assignment `assignment_cd196338a28e219edb3e9b0e958b9edeb3b0a6f820d67318119f031c530aed78`;
  the remaining seven units are not executed until this pilot completes without a terminal failure.

## Scale-up rule

Run the exact eight Qwen-7B assignments first. Diagnose any terminal generation, Judge, Oracle, or
joint-outcome failure from its saved request and response. Do not start the 14B stratum or expand the
task pool until the canary demonstrates that the revised tasks can produce interpretable
secure-and-functional outcomes. A valid canary need not show that the target arm is beneficial.
