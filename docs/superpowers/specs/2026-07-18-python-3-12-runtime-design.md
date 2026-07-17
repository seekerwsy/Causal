# Python 3.12 Runtime Baseline Design

**Date:** 2026-07-18
**Status:** Approved
**Scope:** SecAware runtime metadata, compatibility dependencies, tests, and final verification

## Decision

SecAware supports one Python minor line: Python 3.12. Package metadata must declare
`requires-python = ">=3.12,<3.13"`. Patch releases within that minor line remain supported so the
project does not depend on one patch build being available on every supported platform.

This decision supersedes the Python 3.10/3.12 matrix in the Prompt-only FCI/JCI rollout plans. It
does not change the statistical design, Prompt TSG, Oracle boundary, stage contracts, or the rule
that the minimum causal-learn backend must import and run without Java or py-tetrad.

## Dependency and Source Boundary

Python 3.12 standard-library APIs are the baseline:

- production code imports `Self` from `typing`;
- tests import `tomllib` from the standard library;
- `typing-extensions` is not a direct runtime dependency solely for Python 3.10 compatibility;
- `tomli` is not a development dependency solely for Python 3.10 compatibility.

Optional dependency boundaries remain unchanged:

- `oracle` pins the exact Semgrep and Bandit versions;
- `rfci` pins JPype and py-tetrad and remains optional;
- importing the base package and CLI must not start Java or import the RFCI runtime.

## Tests and Verification

Architecture and packaging tests must prove:

1. package metadata permits Python 3.12 and excludes Python 3.11 and 3.13;
2. the Python 3.10-only compatibility dependencies and fallback imports are absent;
3. the base package and CLI import without Java or py-tetrad;
4. `uv.lock` is absent;
5. the wheel advertises the same Python 3.12 range.

The final version matrix contains one isolated Python 3.12 environment with the declared `dev` and
`api` extras. The normal full suite, Ruff, format, compile, CLI-help, and whitespace gates also run
under Python 3.12. The exact Oracle-tool gate runs under Python 3.12 with the `oracle` extra. The real
RFCI gate runs separately under Python 3.12 with the `rfci` extra when a compatible JDK is available;
its absence cannot change minimum-backend results.

## Migration and Failure Semantics

Installing SecAware on Python outside the 3.12 minor line must fail during dependency resolution,
before package execution. Documentation and migration notes must state the Python 3.12-only
baseline. No runtime compatibility shim or best-effort fallback is added for unsupported Python
versions.

The ongoing Task 8 quality fix for completed-run report validation is independent of this runtime
decision. A completed `run-all` invocation must still perform non-mutating semantic validation and
transaction-state checks before returning success.

## Non-Goals

- Supporting Python 3.10, 3.11, or 3.13 in this milestone.
- Pinning one exact Python 3.12 patch release.
- Making Java mandatory for the minimum causal-learn backend.
- Changing any causal estimand, intervention arm, provenance boundary, or artifact schema solely due
  to the runtime baseline.
