# Test suite

The maintained suite has two layers.

Default reviewer layer:

    python -m pytest -q

Each test owns a scientific invariant:

- discover/confirm and task-unit separation;
- conservative outcome-blind merge authority for semantic task-unit curation;
- explicit ready/calibration/replication/out-of-scope eligibility accounting;
- exact shared candidate-universe, score, rank, Top-K, and empty-slot freeze;
- semantic replay of selector, bridge, and interaction-selection artifacts;
- positivity-gated FCI, association, prediction, blinded-expert, and seeded-random selectors;
- fixed-reference, two-level request-slot, multi-slot, and typed-BK/PAG selector audits;
- strict ConfirmedYield@K and independently replayed nested task-unit inference;
- end-to-end direct versus direct-plus-context representation comparison replay;
- operation-specific successor Target/No-op/Placebo/Generic instructions;
- outcome-blind semantic validation before randomization;
- representative-prompt Prompt-TSG and relation-evidence recomputation;
- replayable four-role and `2 x 2` complete-block randomization;
- persistent pre-outcome variant and execution-order materialization before provider calls;
- frozen adapter identities;
- provider-call closure and raw-response-to-Measurement replay;
- code/Oracle/functionality outcome decomposition;
- terminal and infrastructure failure semantics;
- equal task-unit weighting and per-model estimates;
- unknown bounds and simultaneous task-unit bootstrap replay;
- global-union, replicate-studentized factorial resampling with partial pair
  support, minimum-valid-draw enforcement, and fail-closed zero-standard-error
  behavior;
- separation of security-interaction permission from a separately powered
  functionality non-inferiority gate;
- multi-pair/multi-model factorial dispatch and independent recomputation;
- selector/bridge and pair-selection provenance binding into confirmatory runs;
- exact-byte artifact closure.

Structural milestone layer:

    python -m pytest -q -m milestone

Milestone tests exercise optional backend capabilities and the smallest linear
artifact reproductions. They are not run for mechanical edits and do not stand
in for a frozen provider experiment.

`test_factorial_reviewer_smoke.py` is the zero-network active-path reproduction:
two task units, one pair, two application orders, four cells, and one offline
fixture model (16 assignments). It uses the real local Security Oracle but
fixture provider responses, writes no tracked result, disables scientific
claims and functionality-power claims, and protects implementation closure
only. The offline Functional Judge qualification is
`STRUCTURAL_SMOKE_ONLY` and is accepted only for this non-claiming development
canary boundary.

There is no active historical full suite. Add a test only when it protects a
distinct method invariant or an end-to-end reproduction boundary.
