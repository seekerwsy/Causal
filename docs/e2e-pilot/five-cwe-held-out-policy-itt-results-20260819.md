# Five-CWE Held-out Policy ITT Results — 2026-08-19

## Frozen scope

- Models are analyzed as separate strata: `qwen2.5-coder-7b-instruct` and `phi-4-14b`.
- Each stratum contains 42 held-out task clusters and four randomized arms, for 168 assignments.
- The primary estimand is target patch versus no-op rewrite on secure-and-functional success.
- The two model-specific primary intervals use the frozen Bonferroni family of size two.
- CWE security, mechanism, flip, and CWE-specific rows are secondary or diagnostic.
- Syntax, functionality, target change, semantic validity, and Oracle unknown status never filter an
  assigned row from ITT. There are zero post-randomization exclusions.

## Execution closure

| Model | Complete | Error | Pending | Generated | Judge calls | Oracle rows |
|---|---:|---:|---:|---:|---:|---:|
| Qwen2.5-Coder-7B-Instruct | 168 | 0 | 0 | 168 | 166 | 168 |
| Phi-4-14B | 168 | 0 | 0 | 168 | 167 | 168 |

Qwen contains two syntax-gated programs and Phi contains one. They remain assigned outcome-zero
rows; syntax-invalid code is classified before Semgrep/Bandit and is not sent to either analyzer.

## Arm-level outcomes

All cells are counts out of 42 independently randomized task blocks per arm.

| Model | Arm | Secure & functional | CWE secure | Functional pass | Security unknown | Functional unknown |
|---|---|---:|---:|---:|---:|---:|
| Qwen | Target patch | 18 | 29 | 25 | 7 | 1 |
| Qwen | No-op rewrite | 15 | 22 | 30 | 5 | 1 |
| Qwen | Length-matched placebo | 16 | 23 | 30 | 4 | 0 |
| Qwen | Generic security reminder | 14 | 22 | 28 | 8 | 1 |
| Phi | Target patch | 19 | 29 | 27 | 6 | 2 |
| Phi | No-op rewrite | 20 | 23 | 34 | 5 | 0 |
| Phi | Length-matched placebo | 16 | 22 | 30 | 6 | 2 |
| Phi | Generic security reminder | 18 | 21 | 29 | 10 | 1 |

## Frozen primary result

| Model | Target rate | No-op rate | ITT risk difference | Bonferroni task-bootstrap interval | Status |
|---|---:|---:|---:|---:|---|
| Qwen | 42.86% | 35.71% | +7.14 pp | [-7.14, 25.03] pp | Inconclusive |
| Phi | 45.24% | 47.62% | -2.38 pp | [-19.05, 10.74] pp | Inconclusive |

The intervals are based on 200 deterministic task-cluster bootstrap replicates per registered
contrast. A positive or significant result was not required for validity.

## Secondary safety result and functionality trade-off

| Model | Target CWE-secure | No-op CWE-secure | Security ITT | Unadjusted interval | Target/no-op functional pass |
|---|---:|---:|---:|---:|---:|
| Qwen | 69.05% | 52.38% | +16.67 pp | [4.76, 28.57] pp | 59.52% / 71.43% |
| Phi | 69.05% | 54.76% | +14.29 pp | [0.00, 23.81] pp | 64.29% / 80.95% |

Both target arms reduce proved-unsafe-sink incidence and increase proved-safe-sink evidence relative
to no-op. These mechanism rows and the unadjusted secondary intervals are supportive diagnostics;
they do not replace the inconclusive secure-and-functional primary result. The observed difference
between safety and joint success is explained by lower target-arm functional-pass rates, which the
one-pass LLM Judge measured independently from the static security Oracle.

## CWE heterogeneity boundary

Held-out task counts are uneven: CWE-78 has 22 clusters, CWE-328 and CWE-89 have seven each,
CWE-338 has four, and CWE-502 has two. Per-CWE effects are therefore descriptive. The largest
stratum, CWE-78, has secure-and-functional differences of 0 pp for Qwen and -13.64 pp for Phi;
CWE-338 shows +50 pp in both models but has only four tasks. No per-CWE significance claim is made.

## Reproducibility and provenance

Source archives:

- `qwen7b-gate-c-run.tar.gz`: `88875c8c0b88ddeedb1dc9be8357d11fbf3c19b29add48e8e4fff9ca71063f30`
- `phi14b-gate-c-run.tar.gz`: `29d092480d6e8304d45c33423bd99b35763f7f7c8f7948fc1e33cddc20866afe`
- `model-service-records.tar.gz`: `b07ee7af064c088ef4c00c047fe6ac163fb746df302c861fccf778d052aa39aa`

The first and replayed analysis directories are:

- `data/e2e-pilot/five-cwe-held-out-policy-itt-analysis-20260819-01`
- `data/e2e-pilot/five-cwe-held-out-policy-itt-analysis-replay-20260819-02`

The following core artifacts are byte-identical across both executions:

| Artifact | SHA-256 |
|---|---|
| Assignment outcomes | `449a5da2972d782ac9cd27de7ed61508f2a5980bc608df3f701e825b7d00099d` |
| Bootstrap draws | `aa32158b830762b91f89bdfc6adbdda09490abc053fd2b0a3ec96e6af24d221e` |
| Effects | `dec37480e08779f7491c0d1ece7f3db9c9ebbd762ddc71f5c0410bb2f2fd4d72` |
| Task flips | `2a1c6ac51f5499f219b5de2ce57426a08604845b858edb9a82fead2925eead34` |
| CWE heterogeneity | `eb0488fd22a25133f81a6521fe5c39db096b2e9f58d53ac695e420835074690f` |
| Effective config | `063b90e49931f5f444970fcca0f2ed860d96cd51532689d8950c7aa5f5795485` |
| Input provenance | `2707dea4de5ab3f1044390fee6875654212f5ce6d4feb03fe3ee13bf0d1d8462` |
| Report | `c37e0ebd0f73cb861fd67978b4b92785912b02637f72fe8cbe398317925c84a5` |

The source archives contain neither `.env` files nor a paid-provider credential. All 336 unit
manifests and both frozen plan relations are revalidated before an outcome row is constructed.
