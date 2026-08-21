# Five-CWE Main Task Pool Freeze

## Outcome-blind source supplementation

The CyberSecEval v2 audit left several CWE/split strata below the originally planned 8-discover and
12-confirm quotas. A zero-call audit therefore examined Python, candidate-neutral clusters from
SecurityEval, SALLM, CWEval, the non-overlapping CyberSecEval legacy records, and SecCodeBench. Every
cluster overlapping any CyberSecEval v2 task was excluded before review. The authenticated coverage
run is `data/e2e-pilot/five-cwe-cross-source-coverage-20260818-03`; its strict supplement contained
59 candidates and preserved the frozen 20260810, 0.5 discover-ratio task-cluster split.

The supplement was audited once with the final outcome-blind policy. Two earlier five-call canaries
are retained because they exposed distinct judge errors: inferring that absent safety guidance forces
an unsafe implementation, and broadening a security-randomness target to ordinary sampling. The final
policy requires literal Prompt support for incompatibility and exact semantic agreement with the
finite target operation. Code deterministically recomputes `eligible` and `reason_code` from the
proposal fields and records all normalized fields.

The final 59-response reconciliation is
`data/e2e-pilot/five-cwe-cross-source-reconciliation-reviewed-20260818-06`. It made zero additional
provider calls, produced 59/59 decisions, and has no unresolved record. Four explicit Codex-primary
overrides are frozen in `configs/e2e-pilot/five-cwe-cross-source-audit-overrides-v1.jsonl`: three
repair invalid response structure and one corrects the unsupported inference that a SQL task must use
string interpolation. Review remained blind to generated code, model identity, intervention arms,
Oracle labels, and outcomes.

The supplement contributes 12 eligible independent tasks:

| CWE | Discover | Confirm | Total |
| --- | ---: | ---: | ---: |
| CWE-78 | 2 | 4 | 6 |
| CWE-89 | 1 | 1 | 2 |
| CWE-502 | 2 | 0 | 2 |
| CWE-328 | 0 | 0 | 0 |
| CWE-338 | 1 | 1 | 2 |

Most rejected supplement records explicitly require Bash, `os.system`, pickle, MD5, or SHA-1, or
use randomness only for sampling/scheduling. They cannot be admitted without changing task behavior.

## Frozen complete pool

`data/e2e-pilot/five-cwe-main-task-pool-frozen-20260818-07` combines all 81 eligible CyberSecEval v2
tasks and all 12 eligible supplement tasks. The task-bundle SHA-256 is
`12c6b723ffe8402720bd8cfae34a1098da3cfd9cea537eda8e39409febf064bf`. No code has been generated and
no outcome has been observed for any task in the bundle.

| CWE | Discover | Confirm | Total |
| --- | ---: | ---: | ---: |
| CWE-78 | 21 | 22 | 43 |
| CWE-89 | 10 | 7 | 17 |
| CWE-502 | 7 | 2 | 9 |
| CWE-328 | 10 | 7 | 17 |
| CWE-338 | 3 | 4 | 7 |
| **All five** | **51** | **42** | **93** |

The authenticated split is preserved rather than rebalanced after eligibility review. All eligible
tasks are retained; no ranking or subsampling uses generated outcomes.

## Statistical gate before generation

The paper configuration requires 20 independent tasks per analysis scope. Only CWE-78 meets that
threshold on both splits. The five-CWE aggregate has 51 discover and 42 confirm tasks, but the current
specification forbids pooling across CWE scopes or target features without a separately approved
estimand. Consequently, the pool is frozen with scope gaps and main generation must not begin under a
silently lowered minimum.

The recommended pre-outcome revision is one typed, pooled policy estimand:

> the effect of adding the operation-specific security requirement selected by the task's finite CWE
> profile, compared with no-op rewrite, across the five-CWE task population.

Each target patch remains CWE-specific (for example parameterized SQL versus safe deserialization),
while the parent Prompt-TSG feature is the shared `operation_specific_security_requirement`. The
four-arm randomized protocol stays unchanged. Task-clustered pooled ITT is primary; CWE-specific
effects are heterogeneity diagnostics, and only CWE-78 can independently support the existing
20-task CWE-specific confirmation status. This revision must be approved and frozen before any main
code generation.
