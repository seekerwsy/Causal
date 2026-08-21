# Functional Judge v3 fresh holdout

This directory is a distinct engineering-calibration authority. It does not replace or mutate
`../blind-calibration-v3`, and it cannot support a scientific claim.

The active campaign contains the same eight exposed executable tune cases as a regression gate and
sixteen new static validation cases. The validation set is balanced across the four frozen
functional families, with two `pass` and two `fail` cases per family. The old sixteen-case
validation file is an exposed historical regression set only; it is not an accuracy denominator or
ranking input for Functional Judge v3.

The new cases are Codex-rendered deterministic projections of the already-frozen task contracts and
executable adapter fixture/check semantics. They do not introduce new per-task runtime tests. No
candidate/provider outcome, generation output, security-Oracle result, Judge response, or candidate
score was used to select, replace, or rank a case. The exact requirement closure and source basis
for every case are recorded in
`case-source-bindings.jsonl`. `holdout-source-policy.json` records the selection policy, pollution
audit, source hashes, and the pre-holdout candidate prompt/config cutoff.

Any later byte change to the bound Functional Judge v3 prompt or evaluator config invalidates this
set as a fresh holdout for that changed candidate. A changed candidate needs another previously
unseen holdout; it may not tune against this one and then reuse it as validation.

Active thresholds remain: tune `8/8`, zero tune false-pass, zero tune equivalence inconsistency;
validation at least `15/16`, zero validation false-pass, zero invalid responses, and zero validation
equivalence inconsistency. Baseline results, when retained, are descriptive and never selectable.
