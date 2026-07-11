# SecAware

SecAware is a reproducible Python CLI prototype for TSG-driven prompt-side
security mechanism discovery and confirmation.

The demo pipeline runs without external LLM APIs or external static analyzers:

```bash
pip install -e ".[dev]"
secaware run-all --config configs/demo.yaml --run-dir runs/demo --force
pytest
```

## Oracle execution support

The independent external-analyzer Oracle is fail-closed and has a narrower runtime support matrix
than the rest of the Python package:

| Runtime | Oracle execution |
| --- | --- |
| Windows | Supported when Job Object and Toolhelp process-control capabilities pass preflight. |
| Linux | Supported when unprivileged user, PID, and mount namespaces and a private `/proc` mount pass preflight. |
| macOS, BSD, other POSIX systems | Unsupported; Oracle preflight fails with `ANALYZER_FAILED`. |
| Linux with namespaces disabled or blocked | Unsupported; Oracle preflight fails with `ANALYZER_FAILED`. |

`validate_analyzer_runtime()` performs this capability preflight without starting an analyzer.
Oracle entry points must call it before analyzer validation and again before starting the Oracle
stage. The general SecAware preflight and non-Oracle package components remain available on other
platforms; there is no reduced-security Oracle fallback.

The `oracle` configuration block selects the locked policy, analyzer executables, timeout, and
output bounds. It does not opt into a lightweight analyzer mode, and changing it cannot bypass the
runtime capability check.
