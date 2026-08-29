# Test suite

The maintained suite has three layers.

Default reviewer layer:

    python -m pytest -q

The default layer is intentionally limited to about thirty paper-facing
scientific invariants:

- exact-byte artifact closure and rejection of unlisted evidence;
- conservative semantic task-unit merge authority and discover/confirm separation;
- explicit ready/calibration/replication/out-of-scope eligibility accounting;
- outcome-blind positivity and source-overlap gates;
- Prompt-TSG evidence spans, four-valued context, catalog-bound patches, and
  evidence-bound local text;
- selector gate failure and independently replayed ConfirmedYield results;
- requirement-bound Functional Judge failures;
- operation-specific source gates plus replayable task/arm/seed binding;
- immutable pre-outcome materialization and one complete four-arm measurement replay;
- independent successor task-unit ITT, unknown bounds, and tamper rejection;
- registry-bound factorial pair selection, complete-block randomization, total
  assignment accounting, and independent result reconstruction;
- valid-code-conditioned unknown gates and replay of frozen historical factorial evidence.

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

Extended audit layer:

    python -m pytest -q -m "not reviewer and not milestone"

This retains mechanism calibration variants, selector sensitivities, schema
rejection cases, and adversarial tamper checks without charging them to every
reviewer run. There is no active historical full suite. Add a test only when it
protects a distinct method invariant, calibration boundary, or end-to-end
reproduction boundary.
