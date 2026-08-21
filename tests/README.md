# Test layers

The test suite is organized by review value rather than by historical feature count.

## Reviewer suite

Run after ordinary implementation changes:

```bash
python -m pytest -q -m reviewer
```

This suite contains 15–25 focused tests and should finish within two minutes. Each
scientific invariant has one primary test: frozen-input separation, replayable
randomization, task/arm/seed binding, independent security and functionality,
explicit unknown states, total assignment accounting, hand-calculated ITT, and the
shared content-addressing mechanism.

## Milestone suite

Run after changes to the experiment structure or before a review checkpoint:

```bash
python -m pytest -q -m milestone
```

It contains the minimal end-to-end replay, synchronized root tampering, missing or
replaced assignment evidence, and run-level evidence verification. Some tests take
several minutes; they are deliberately excluded from the reviewer suite.

## Extended and archival suite

Run only for releases, migrations, or targeted audits:

```bash
python -m pytest -q
```

Unmarked tests preserve field-level tampering, historical protocol compatibility,
deployment/recovery behavior, platform isolation, and incident regressions. New
tests should enter this layer only when they protect a distinct failure mode; do not
duplicate a scientific invariant already owned by the reviewer suite.
