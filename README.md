# SecAware

SecAware is a reproducible Python CLI prototype for TSG-driven prompt-side
security mechanism discovery and confirmation.

Install the core development environment and run the unit suite with:

```bash
pip install -e ".[dev]"
pytest
```

Generation can use offline results without an external LLM API. Oracle stages are intentionally
different: they require the exact external analyzers described below. `run-all` includes those
stages and therefore has the same Oracle requirements.

## Install and run the Oracle

The Oracle extra pins the only supported analyzer versions:

```bash
uv sync --extra oracle
# Equivalent editable pip install: pip install -e ".[oracle]"
```

The finite Semgrep rules, Bandit configuration, Bandit metadata, and their authenticated lock are
checked into `policies/oracle/python/`. Semgrep metrics and version checks are disabled, and no
remote rule registry or network policy lookup participates in a run.

Validate the general experiment inputs, then run the observed Oracle stage:

```bash
secaware preflight --config configs/demo.yaml
secaware run-oracle --config configs/demo.yaml --condition observed
```

`preflight` validates the general pipeline configuration. `run-oracle` additionally performs the
Oracle capability check, authenticates the policy bundle, resolves both executables, requires
Semgrep 1.168.0 and Bandit 1.9.4, and reruns the capability check immediately before analysis.

The same engine is available as a standalone command for canonical generated-code JSONL:

```bash
secaware-oracle run \
  --input runs/demo/generation/observed_code.jsonl \
  --output runs/demo/oracle/observed_oracle.jsonl \
  --policy-lock policies/oracle/python/policy.lock.json \
  --semgrep semgrep \
  --bandit bandit
```

Run the checked-in real-tool release gate with:

```bash
pytest -m oracle_tools
```

Without the exact optional dependencies and executable commands, this marked integration test is
explicitly skipped; it never passes via an internal substitute. Production Oracle commands do not
skip: a missing or mismatched analyzer, invalid or incomplete report, policy mismatch, timeout, or
unsupported runtime capability returns an error and publishes no Oracle result.

## Oracle execution support

The independent external-analyzer Oracle is fail-closed and has a narrower runtime support matrix
than the rest of the Python package:

| Runtime | Oracle execution |
| --- | --- |
| Windows | Supported when a suspended helper completes Job assignment, Toolhelp thread discovery, resume, wait, and reap during preflight. |
| Linux | Supported when sealed memfd/proc-fd checks, unprivileged user, PID, and mount namespaces, and a private `/proc` mount pass preflight. |
| macOS, BSD, other POSIX systems | Unsupported; Oracle preflight fails with `ANALYZER_FAILED`. |
| Linux with namespaces disabled or blocked | Unsupported; Oracle preflight fails with `ANALYZER_FAILED`. |

`validate_analyzer_runtime()` performs this capability preflight with only a fixed, short-lived
helper; it never resolves or starts an analyzer.
Oracle entry points must call it before analyzer validation and again before starting the Oracle
stage. The general SecAware preflight and non-Oracle package components remain available on other
platforms; there is no reduced-security Oracle fallback.

The `oracle` configuration block selects the locked policy, analyzer executables, timeout, and
output bounds. It has no switch for an internal security analyzer and changing it cannot bypass the
runtime capability check. Security labels come only from successful, complete reports from both
locked analyzers; there is no handwritten-rule or reduced-security fallback.
