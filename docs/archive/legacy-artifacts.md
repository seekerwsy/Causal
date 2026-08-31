# Legacy artifact boundary

This directory records the interpretation and recovery boundary for artifacts
that predate the active schema-3 method.

## Immutable retained artifacts

The following tracked bundles remain historical evidence and must not be
rewritten, migrated in place, or cited as schema-3 results:

- `data/formal/results/factorial-sql-confirm-qwen35-v3`
- `data/formal/results/factorial-sql-scaffold-repair-qwen35-v1`
- `data/method/archive/legacy-v5`

Their matching historical configurations are under
`configs/archive/schema1`. Result notes are under
`docs/archive/experiments`, and
superseded migration/readiness material is under
`docs/archive/development`. These paths are outside the default schema-3
reviewer path.

Generic exact-byte bundle verification can still be performed with
`prompt-mechanism-study verify BUNDLE`. Scientific replay of a historical
schema requires its historical source environment.

## Source recovery

The last repository checkpoint before removal of the live schema-1/2
selector, successor, factorial and intervention implementations is Git commit
`674391f`. Recover a historical verifier or runner from that commit in a
separate checkout. Do not copy it into the active package or import it from the
schema-3 CLI.

Git history, this boundary document, and the immutable bundles are the
preservation mechanism. The active code and default tests intentionally contain
no parallel legacy execution path.
