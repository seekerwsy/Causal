# Test suite

The maintained suite has two layers.

Default reviewer layer:

    python -m pytest -q

Its 24 tests each own a scientific invariant:

- discover/confirm and semantic-cluster separation;
- exact candidate-universe, score, rank, and top-K freeze;
- operation-specific four-arm semantics;
- complete multi-realization task support and validation;
- replayable complete-block randomization;
- frozen adapter identities;
- code/Oracle/functionality outcome decomposition;
- terminal and infrastructure failure semantics;
- equal semantic-cluster weighting and per-model estimates;
- simultaneous cluster bootstrap replay;
- exact-byte artifact closure.

Structural milestone layer:

    python -m pytest -q -m milestone

The two milestone tests run freeze, external measurement import, analysis, and
independent verification, including rejection of cross-study measurements.

There is no active historical full suite. Add a test only when it protects a
distinct method invariant or an end-to-end reproduction boundary.
