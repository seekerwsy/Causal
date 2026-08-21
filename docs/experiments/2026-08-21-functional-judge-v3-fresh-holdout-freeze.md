# Functional Judge v3 fresh-holdout freeze

## Scope and evidence level

This checkpoint freezes an engineering-only validation set for `Y_F^J`. It records a measurement
repair and calibration gate, not executable correctness and not paper evidence. The independent
Security Oracle is outside this work and is neither invoked nor changed. All artifacts here retain
`scientific_claim_allowed=false`.

## Pollution decision

The original eight executable tune cases remain exposed regression cases. The original sixteen
validation cases at
`data/functional-judge/blind-calibration-v3/validation-cases.jsonl` have SHA-256
`8e62c17753dd09c352a89571429aec5ecd4dc2b41280cdaeb8d3835fa9a8dca6`. Because those cases and
earlier Judge traces informed v2/v2b/v3 engineering, they are now historical regression inputs only.
They cannot estimate fresh v3 accuracy, satisfy the v3 validation gate, or rank a candidate.

The replacement validation set was frozen without reading any Functional Judge response, candidate
score, generation output, or Security-Oracle result. It uses four pre-existing frozen task contracts
and their executable adapter fixture/check semantics. No reserve pool or outcome-conditioned
replacement exists.

## Frozen design

- Authority: `data/functional-judge/blind-calibration-v4`.
- Exposed tune regression: 8 cases, unchanged source authority.
- Fresh validation: 16 AST-valid Python cases.
- Balance: four families; each has 2 `pass` and 2 `fail` cases.
- Gold: exact requirement-ID closure; aggregate `fail` if any requirement is `not_met`, otherwise
  `pass`.
- Construction: Codex rendered static candidate-code projections from the frozen contract and
  pre-existing adapter semantics; this did not add or rewrite the executable test authority.
- Selection: fixed family coverage and frozen order; no candidate/provider outcome, generation
  output, Oracle result, Judge response, or score was used to select, replace, or rank a case.
- Thresholds: tune 8/8 with zero false-pass; validation at least 15/16 with zero false-pass, zero
  invalid response, and zero equivalence inconsistency.
- Calls while freezing: provider 0; generation 0; Functional Judge 0; Security Oracle 0.

The active cases, per-case requirement verdicts, source basis, selection rule, and contamination
ledger are separated into `validation-cases.jsonl`, `case-source-bindings.jsonl`, and
`holdout-source-policy.json`. The campaign planner consumes only the active case projection; it does
not consume per-case gold requirement verdicts.

## Candidate cutoff and invalidation

At holdout creation, the already-existing Functional Judge v3 prompt SHA-256 was
`5aecb580cba8b241da4108aca61465781de5d7e7fbd2662072a84b28eac2eecf`, and the evaluator config
SHA-256 was `fe7434f9ef2c1d84ef00901de8234ed424eec42a57257fa5a9a6d59aa5338125`.
The fresh-holdout integrity test binds both values. If either artifact changes afterward, this
holdout is contaminated for the changed candidate and a distinct unseen holdout is required.

## Resolved operational incident

At approximately `2026-08-21T18:39:00+08:00`, after validation bytes, requirement-gold bindings,
selection ranks, and the calibration spec were frozen, one overly broad local repository search
over Python/JSONL/JSON source-symbol matches displayed a stored historical task-eligibility and
functional-contract audit response fragment. It made no remote/provider call and exposed no v3
Functional Judge request/response/status, candidate metric, Security-Oracle label/output,
generation-model candidate code, or fresh-holdout execution result. No case, gold binding,
selection rank, or spec byte changed because of that output; their hashes remain recorded in the
policy. The incident is resolved: subsequent inspection is limited to path-directed hashes and
tests.

## Claim boundary

Passing this calibration would show only that one frozen static LLM Judge policy met the declared
engineering gate on one small frozen corpus. It would not turn `Y_F^J` into executed behavior, prove
general functional accuracy, replace `Y_F^E`, or authorize a paper-facing result.
