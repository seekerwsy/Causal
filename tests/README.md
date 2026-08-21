# Test suite

The checked-in tests cover the scientific artifact, not every historical runtime
implementation. Git history preserves retired deployment, migration, provider, and
incident-regression tests when a specialized audit needs them.

Ordinary review uses the default command:

```bash
python -m pytest -q
```

It checks frozen-input separation, replayable randomization, exact task/arm/seed
binding, independent security and functionality, explicit unknown states, total
assignment accounting, hand-calculated ITT, simultaneous inference, and shared
content-addressing mechanics.

After a structural change, run the small end-to-end and tamper-resistance layer:

```bash
python -m pytest -q -m milestone
```

To inspect every retained adjacent contract test, override the default marker:

```bash
python -m pytest -q -o addopts=""
```

Add a test only when it owns a distinct scientific invariant or a minimal
reproduction boundary. Field-by-field mutation matrices and historical operational
incidents belong in version history, not in the reviewer-facing suite.
