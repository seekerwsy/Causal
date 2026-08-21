# Test suite

The suite is deliberately small. Each scientific invariant has one primary
reviewer-facing test; operational history remains available in Git rather than
being shipped as an active test matrix.

Default review:

    python -m pytest -q

This runs 24 tests covering frozen inputs, deterministic prioritization,
four-arm intervention construction, replayable complete-block randomization,
independent security and functionality labels, explicit unknown states, total
assignment accounting, hand-calculated ITT estimates, uncertainty bounds, and
exact artifact closure.

After a structural change, run the two end-to-end checks:

    python -m pytest -q -m milestone

No larger default suite exists. Add a test only when it owns a distinct
scientific invariant or a minimal reproduction boundary.
