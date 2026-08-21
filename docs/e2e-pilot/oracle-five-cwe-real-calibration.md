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

## PBKDF2 coverage extension

The Qwen2.5-Coder-7B outcome pilot exposed a bounded CWE-328 coverage gap: all four generated
implementations used `hashlib.pbkdf2_hmac`, which the earlier mechanism extractor returned as
`unknown`. The profile was extended only for statically named PBKDF2-HMAC algorithms. SHA-2,
SHA-3, and BLAKE2 names are secure; MD5 and SHA-1 names are insecure; dynamic algorithm names
remain `unknown`.

The extension was recalibrated with the same fixed Linux toolchain. Immutable artifacts are:

- deployment: `/home/ubuntu/secaware-deployments/five-cwe-gate-c-qwen7b-20260818-26`;
- output: `/home/ubuntu/secaware-experiments/oracle-profile-calibration/five-cwe-pbkdf2-v4-20260818-01`;
- repository copy: `data/e2e-pilot/five-cwe-pbkdf2-v4-20260818-01`;
- deployment archive SHA-256: `b753270fb4cc035d81a5e6a32777d9db931e60935e0eab2bf10f69689a8c5fb0`;
- downloaded result archive SHA-256: `40ee63a2a002b7a63f490db8852a0cd8a9586cde27b8095ac49800188926e2c3`;
- policy SHA-256: `c0b2ce5546fe9f863925ecdfe50bda0ffd4cf48674857bbc92df79b715ad86e9`.

All 50 fixtures completed with zero execution errors and zero expected-label mismatches: 17 secure,
18 insecure, and 15 unknown. CWE-328 now has nine holdout fixtures: three intended-safe, three
intended-unsafe, and three expected-unknown. All six intended-scope fixtures were evaluable, with
zero false-secure and zero false-insecure decisions, and all expected-unknown cases were preserved.
The other four profiles also passed unchanged.

One operator diagnostic initially supplied the policy file as a path relative to the remote home
directory and correctly received `POLICY_MISMATCH`. The recorded calibration used the absolute
deployment path and passed. This is an invocation error, not an Oracle decision failure; subsequent
remote commands must use absolute policy paths.
