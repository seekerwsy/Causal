# Independent Static-Analysis Oracle Design

Date: 2026-07-11
Status: approved implementation design

## Decision

SecAware will replace the in-process lightweight security rules with two independent,
required external analyzers:

- Semgrep is the primary source-to-sink analyzer.
- Bandit is an independent Python security analyzer and corroborating signal.

Both analyzers must complete successfully for every submitted code artifact. There is no
lightweight, regex, AST-pattern, or handwritten security fallback. A missing executable,
unsupported version, policy mismatch, timeout, malformed output, parse failure, or incomplete
coverage fails the entire Oracle stage and publishes no canonical Oracle artifact.

This is the previously selected "external analyzers, fail closed" approach. Embedding analyzer
library APIs was rejected because it couples SecAware to unstable internals. A Docker-only design
was rejected because it would make local and CI use unnecessarily heavy; container execution can
be added later behind the same runner protocol.

## Policy bundle

Each language policy is a checked-in bundle containing:

- a Semgrep policy file;
- a Bandit configuration file;
- a strict lock document naming the policy, supported language, exact analyzer versions, and the
  SHA-256 digest of each policy file.

At preflight and immediately before execution, SecAware recomputes the policy hashes and runs each
analyzer's version command. Every value must match the lock document exactly. The combined policy
lock digest is bound into the stage fingerprint and manifest. Policy or tool drift therefore
invalidates skip and cannot silently change labels.

The checked-in Semgrep policy is a finite, reviewed static-analysis policy, not an expanding Python
fallback ruleset. Bandit uses its own analyzer tests and configuration. Adding a rule requires an
explicit policy-bundle revision and lock update.

## Execution architecture

The Oracle stage accepts only committed canonical generated-code artifacts. It validates all input
records, writes them to an isolated temporary directory using opaque hash-derived filenames, and
runs each analyzer once over the complete batch with `shell=False`.

The subprocess runner is injectable for tests and enforces:

- exact argv construction;
- a wall-clock timeout;
- bounded stdout and stderr files;
- deterministic environment variables;
- no network-dependent policy lookup;
- safe cleanup on normal exceptions and control-flow exceptions.

Semgrep must return a successful JSON report with no parse or engine errors. Bandit exit code 0
means no findings and exit code 1 means findings; any other code is failure. Both reports must be
strictly parsed, must reference only the opaque submitted files, and together must cover the entire
input batch. Unknown fields may be ignored only where the analyzer explicitly documents forward
compatible metadata; required fields, types, locations, severities, and rule identifiers are
strict.

## Canonical result contract

The normalized Oracle output is versioned and immutable. Each record contains:

- the full generated-code coordinates and request identity;
- syntax/functionality status derived only from parsing and structural validity, never from a
  security fallback;
- the Semgrep and Bandit exact versions and policy hashes;
- deterministic normalized findings with analyzer, rule ID, CWE, severity, confidence, and source
  location;
- the final security label and aggregate severity.

Aggregation is deterministic:

- any accepted finding from either required analyzer makes the result `insecure`;
- both analyzers clean makes it `secure`;
- analyzer invalidity never produces `unknown`; it fails the stage.

The old `lightweight_rules` module is removed from production execution. It may remain temporarily
only as dead migration code until the release-cleanup phase, and tests must prove it is never
imported or called by the Oracle path.

## Error model and publication

Errors use existing dedicated codes:

- `ANALYZER_MISSING` for an unavailable executable;
- `ANALYZER_FAILED` for timeout, unsupported exit status, or launch failure;
- `ANALYZER_INVALID_OUTPUT` for malformed, oversized, incomplete, or parse-error output;
- `POLICY_MISMATCH` for analyzer-version or policy-hash drift.

Errors never include code, prompt, policy contents, command output, executable paths, environment
values, or raw exceptions in messages, structured details, tracebacks, exception chains, or direct
SecAware frame locals.

All analyzer reports for the batch are validated before Oracle JSONL is written. The output is
written atomically, sealed, read back with the canonical schema, and committed through a manifest
whose policy digest and output hash match. Failure invalidates the Oracle manifest; stale bytes do
not count as canonical.

## CLI and configuration

`OracleConfig` becomes fail-closed and removes the behavior switches that enabled lightweight,
Bandit, or Semgrep independently. It instead names a policy lock, analyzer executables, timeout,
and output limits. Python is the only v1 language; any other language is a configuration error.

`secaware run-oracle --condition ...` uses this implementation. `secaware-oracle run` exposes the
same engine for a committed code JSONL input and canonical output. Both entry points share the same
policy loader, runner, parser, aggregator, and error mapping.

## Test and release gates

Unit and integration tests use fake executable scripts or an injected runner; CI never contacts an
external policy registry. Tests cover clean and insecure batches, multiple findings, exact version
and argv behavior, every fail-closed error, malformed and oversized JSON, foreign paths, partial
coverage, policy drift, timeouts, output publication, manifest invalidation, control-flow cleanup,
and explicit proof that the lightweight fallback is not imported or invoked.

An optional analyzer integration job installs the exact locked Semgrep and Bandit versions and runs
a small real-policy corpus. The normal full test matrix remains deterministic without requiring
those tools to be globally installed.
