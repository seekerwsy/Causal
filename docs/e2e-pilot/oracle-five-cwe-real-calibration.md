# Five-CWE Oracle Real-Tool Calibration

## Scope

This engineering gate calibrates the bounded Python Oracle profiles for CWE-78, CWE-89,
CWE-502, CWE-328, and CWE-338. It is not a main-experiment result. The source deployment is
commit `0d7f35b` and the fixed Linux runtime uses Python 3.12.13, Semgrep 1.168.0, and Bandit
1.9.4.

## Immutable artifacts

- deployment: `/home/ubuntu/secaware-deployments/oracle-five-cwe-20260818-12`;
- successful output: `/home/ubuntu/secaware-experiments/oracle-profile-calibration/five-cwe-extension-20260818-02`;
- preserved setup failure: `/home/ubuntu/secaware-experiments/oracle-profile-calibration/five-cwe-extension-20260818-01`;
- policy SHA-256: `8ced5d5894d2634f87402f12d3eab1fc64dd8dd88d29dc811cc7d58929f441a66`.

The `-01` attempt evaluated no fixture. It failed before calibration because the runner requires a
new output directory while environment metadata had already created that directory. The corrected
`-02` run lets the runner create its immutable directory and moves the command, environment, and
console records into it afterward.

## Result

All 45 fixtures completed with zero execution errors and zero expected-label mismatches: 15 secure,
16 insecure, and 14 unknown. Every profile passed its holdout gate.

| Profile | Intended holdout | Evaluable | False secure | False insecure | Expected unknown preserved |
| --- | ---: | ---: | ---: | ---: | ---: |
| CWE-78 | 4 | 4 | 0 | 0 | 2/2 |
| CWE-89 | 5 | 5 | 0 | 0 | 1/1 |
| CWE-502 | 4 | 4 | 0 | 0 | 2/2 |
| CWE-328 | 4 | 4 | 0 | 0 | 2/2 |
| CWE-338 | 4 | 4 | 0 | 0 | 2/2 |

This gate authorizes the five bounded profiles for the small pilot. It does not authorize silently
classifying code outside a profile: dynamic algorithms, application wrappers, and missing target
operations continue to return `unknown`.
