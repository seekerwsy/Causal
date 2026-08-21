# Five-CWE Engineering Pilot

## Frozen task pool

The pre-generation pool contains 20 candidate-neutral CyberSecEval Instruct v2 Python task
clusters. Each CWE contributes two discovery and two held-out confirmation tasks. Selection used
only source prompts, source CWE metadata, cluster identities, and the 50/50 split simulation with
seed 20260810; generated code and Oracle outcomes were unavailable.

| CWE | Discovery records | Confirmation records | Oracle profile |
| --- | --- | --- | --- |
| CWE-78 | 1658, 1733 | 1616, 1749 | `python.cwe78.function_parameter_subprocess.v2` |
| CWE-89 | 1603, 1695 | 1635, 1688 | `python.cwe89.function_parameter_sqlite_query.v2` |
| CWE-502 | 1642, 1762 | 1820, 1872 | `python.cwe502.function_parameter_deserialization.v2` |
| CWE-328 | 1638, 1768 | 1670, 1907 | `python.cwe328.message_hashing.v1` |
| CWE-338 | 1572, 1580 | 1586, 1621 | `python.cwe338.security_randomness.v1` |

All 20 source prompts retain a target-operation opportunity and have a source-bound semantic
functional contract. The selected prompts do not explicitly request a vulnerable implementation or
state an expected security label. This is an engineering pilot and is not powered for paper claims.

## Versioned input history

- `data/e2e-pilot/five-cwe-engineering-pilot-v1` is preserved but withdrawn before provider calls:
  its original CWE-502 target clause did not match the calibrated data-only Oracle scope.
- `data/e2e-pilot/five-cwe-engineering-pilot-v2` is preserved but withdrawn before provider calls:
  Gate A detected a CWE-338 task-family vocabulary mismatch.
- `data/e2e-pilot/five-cwe-engineering-pilot-v3` is the current input bundle. It contains 20
  contracts, 40 blinded manual-audit records, 30 prompt records, and no failed or pending task.

The corrected CWE-502 target asks for a data-only parser such as JSON or YAML `safe_load`. The
Prompt feature catalog is version 1.7 with SHA-256
`8342deaf274abc37364b603070e26cd6a0c1c77a25b4b058292bbea41b448f3c`.

## Gate A result

The first Gate A attempt is retained at
`data/e2e-pilot/five-cwe-discovery-gate-a-qwen7b-v1`. It stopped before variant rendering because
the CWE-338 task-family value was outside the feature vocabulary. It made zero provider and code
generation calls.

The corrected zero-provider run is
`data/e2e-pilot/five-cwe-discovery-gate-a-qwen7b-v2`. It passed with:

- 5 preregistered engineering candidates;
- 10 independent discovery task blocks;
- 40 balanced four-arm assignments and 40 Prompt-TSGs;
- 10 held-out confirmation task IDs excluded from discovery;
- zero errors or pending assignments.

The deterministic extractor recognized the target feature in only 1 of 10 target arms. This is a
recorded diagnostic, not an outcome filter: the deterministic backend misses task wording outside
its finite terms. The next gate therefore uses the already implemented blind LLM fact extractor and
validates its structured output against the frozen AllowedDelta rather than expanding a handwritten
phrase catalog.
