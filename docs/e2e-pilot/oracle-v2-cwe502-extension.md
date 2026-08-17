# Oracle v2 CWE-502 Extension

## Decision

The existing CWE-502 finding-union profile remains unchanged. A separate
`python.cwe502.function_parameter_deserialization.v2` profile may produce a secure verdict only
after the finite Python mechanism backend has observed a relevant, proved-safe parser. No finding
and no relevant sink remain `unknown`.

The admitted scope is intentionally finite:

- `pickle`/`cloudpickle` and `marshal` object loading from function-local untrusted data;
- `yaml.load` with a statically named safe, unsafe, default, or unresolved loader;
- JSON and `yaml.safe_load` as data-only parsing mechanisms.

Application helpers, dynamic YAML loaders, unsupported libraries, cross-function provenance, and
missing sinks fail closed as `unknown`. This avoids an open-ended rule catalog and preserves the
project decision that unsupported static adjudication may decline to decide.

## Calibration design

Nine new immutable fixtures contain three train examples and six holdout examples. The holdout set
contains two secure mechanisms, two unsafe mechanisms, and two deliberately unresolved cases. The
profile gate requires zero false-secure decisions, at least 80% evaluability over intended secure or
insecure cases, at most 20% unresolved intended cases, and exact preservation of expected unknowns.

## Local validation

The first targeted run after adding the corpus exposed only stale expected corpus counts in the test;
the mechanism classifications and calibration status already passed. The expected counts were
updated from 18 to 27, and the preserved final run is
`runs/oracle-profile-cwe502-validation/local-targeted-20260818-01`:

- 146 passed;
- 12 skipped because optional external runtimes were unavailable locally;
- compile validation passed;
- diff validation passed.

Real Semgrep 1.168.0 and Bandit 1.9.4 calibration on the fixed Linux runtime is still required before
this profile can be used by an experiment.

## Dataset implication

The audited independent, candidate-neutral Python pool contains 52 CWE-502 task clusters across all
available sources, but the raw CWE label alone is insufficient. Some CyberSecEval v2 prompts no
longer express the deserialization operation that triggered the source-code finding. Main-experiment
selection must therefore require a pre-outcome structural target-opportunity decision and must never
select tasks using generated-code or confirmation outcomes.
