# Test suite

The maintained suite has three layers.

Default reviewer layer:

    python -m pytest -q

The default layer is intentionally limited to the paper-facing scientific
invariants (67 tests at the 2026-08-31 implementation checkpoint):

- exact-byte artifact closure and rejection of unlisted evidence;
- conservative semantic task-unit merge authority and discover/confirm separation;
- explicit ready/calibration/replication/out-of-scope eligibility accounting;
- outcome-blind positivity and source-overlap gates;
- five-role task/near-duplicate firewalls, one-shot acceptance plans, and the
  separate discovery-design/confirmation freeze moments;
- exact qualification-to-power-to-budget lineage, token-tier-derived per-call
  cost bounds, actual call/cost preflight, and complete unique
  request-randomness slots;
- Prompt-TSG evidence spans, four-valued context, catalog-bound patches, and
  evidence-bound local text;
- selector support-gate closure without retaining the superseded five-selector,
  expected-direction, or rank-pair RQ2 contracts;
- Atomic Full/RD-only and Pair Full/No-Relation sole-difference selectors,
  explicit pre-outcome Atomic fold and Pair support/fold freezes with mutation
  replay,
  both-track blinded Expert and seeded Random shared-universe baselines with
  typed candidate cards, fixed-slot/union replay, and per-selector/model
  qualification coverage,
  fixed K slots, shared policy protocolization/task bundles, deterministic
  complete-block arm/variant/provider-seed replay, unique model-effect dispatch,
  separate max-|T| families, five statuses, fixed-denominator RQ tables, formal
  report authorization, and the exact schema-3.0 result-package/legacy firewall;
- requirement-bound Functional Judge failures;
- operation-specific source gates plus replayable task/arm/seed binding;
- immutable pre-outcome materialization and one complete four-arm measurement replay;
- independent successor task-unit ITT, unknown bounds, and tamper rejection;
- registry-bound factorial pair selection, complete-block randomization, total
  assignment accounting, and independent result reconstruction;
- valid-code-conditioned unknown gates and active-schema outcome decomposition.

Structural milestone layer:

    python -m pytest -q -m milestone

Milestone tests exercise optional backend capabilities and the smallest linear
artifact reproductions. They are not run for mechanical edits and do not stand
in for a frozen provider experiment.

The target v3 zero-network closure is the production CLI smoke:

    prompt-mechanism-study target-study smoke REVIEWER_SMOKE_RESULT
    prompt-mechanism-study target-study verify-result REVIEWER_SMOKE_RESULT

It exercises deterministic synthetic inputs through all seven target stages,
including shared measurement/outcome closure for 80 assignments, both timed
freezes, assigned-arm ITT, exact bundle writing, and independent replay. It
makes zero provider calls and is hard-bound to `tested` non-claim evidence.
The retained historical
factorial smoke remains in `test_factorial_reviewer_smoke.py`:
two task units, one pair, two application orders, four cells, and one offline
fixture model (16 assignments). It uses the real local Security Oracle but
fixture provider responses, writes no tracked result, disables scientific
claims and functionality-power claims, and protects implementation closure
only. The offline Functional Judge qualification is
`STRUCTURAL_SMOKE_ONLY` and is accepted only for this non-claiming development
canary boundary.

Extended audit layer:

    python -m pytest -q -m "not reviewer and not milestone"

This retains current mechanism calibration, selector/FCI qualification,
active-schema boundary cases, one explicit legacy-verification boundary, and
adversarial tamper checks without charging them to every reviewer run. There is
no historical full-suite track. Deleted tests remain recoverable through Git;
do not restore an old protocol generation merely to preserve its former test.
Add a test only when it protects a distinct method invariant, qualification
boundary, or end-to-end reproduction boundary.
