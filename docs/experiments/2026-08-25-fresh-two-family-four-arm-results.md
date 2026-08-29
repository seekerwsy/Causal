# Fresh two-family four-arm study results

## Evidence status

The 60-task, 240-assignment ledger is closed and independently verified. The study tests one
predeclared generator model, `qwen3.5-flash-2026-02-23`, on the frozen injection/interpreter and
file/parser/external-resource Python populations. It does not support claims about the omitted
cryptography or identity families, other languages, other generator models, or executable
functionality.

The accepted result is a protocol-preserving operational repair, not an unqualified clean first
execution. The first complete ledger exposed a deterministic request-encoding defect: 107/240
derived seeds exceeded the provider's signed-positive 31-bit range, and exactly those 107 requests
returned HTTP errors. There were zero false positives and zero false negatives in this diagnosis.
The repair masked the same frozen hash to 31 bits, retained all 133 assignments that had already
returned code, and reran only the 107 requests that had never produced code. Task population, arm,
suffix, generator identity, base seed, execution order, Oracle policies, estimands, and bootstrap
settings did not change. The invalid pre-repair analysis must not be cited as study evidence.

## Confirmatory result

The primary comparison is assigned-arm, semantic-task-clustered `Specific - Placebo` ITT on
Oracle-evaluable secure-code yield:

- Specific: 42/60 secure, point yield 70.0%;
- Placebo: 33/60 secure, point yield 55.0%;
- paired difference: +15.0 percentage points;
- multiplicity-adjusted simultaneous interval: [+3.3, +26.7] percentage points;
- improved/harmed/unchanged clusters: 10/1/49.

The point-estimate primary gate passes. Functionality is 47/60 for Specific and 52/60 for Placebo,
a difference of -8.3 percentage points, inside the frozen -10-point margin. Secure-and-functional
joint success is 32/60 versus 27/60, a +8.3-point difference. This functionality statement is the
frozen point-margin gate; it is not a confidence-interval-based noninferiority test.

Coverage uncertainty materially limits the security claim. Specific has 12 unknown Security
Oracle results and Placebo has 18. The primary effect's identification bounds are [-15.0, +35.0]
percentage points, which include zero. The defensible conclusion is therefore that the frozen
point-coded secure-yield estimand improved significantly, while the conclusion is not robust to all
possible resolutions of Oracle-unknown cases.

## Secondary and exploratory results

- `Specific - Absent` secure yield is +10.0 points, adjusted interval approximately
  [-0.4, +20.4] points; it does not exclude zero.
- `Specific - Generic` secure yield is +5.0 points, adjusted interval approximately
  [-6.2, +16.2] points; it does not exclude zero.
- All 240 repaired assignments contain syntactically valid Python. Two Functional Judge calls are
  retained as `unknown`; there are no remaining generation failures.
- Descriptive heterogeneity, not a separately powered confirmatory claim: injection/interpreter is
  +20.0 secure-yield points and file/parser/external-resource is +10.0. CWE-89 contributes the
  largest descriptive increase (+26.7 points). CWE-918 has only one task and is harmful in that
  task, so it cannot support a family-level conclusion.

## Reproduction identities

- prospective population/configuration freeze commit: `eaf9c0e`;
- final seed-range repair and accepted runner commit: `6c62671`;
- Security Oracle adapter source commit: `aa6f9cf`;
- tracked analysis bundle:
  `data/formal/results/fresh-two-family-four-arm-qwen35-v2-analysis`;
- tracked analysis bundle SHA-256:
  `68f5ddb2f0f953ca5bf6287e3559fe1c24e80936ca358686fd0fb3acf85d00d0`;
- closed raw result archive SHA-256:
  `a08e1746142c106b206eae6f588a3a4568a149c20d3f933f85f31794b678ff41`;
- formal configuration SHA-256:
  `ec382a700996a93c5551dfaf3c5c31937fe706b90f3c12acb3eef0698b372517`;
- prepared tasks SHA-256:
  `a2f6e481138dbe7f149d0b9ed368bf85e1805ce8531851aea5397209dd300551`.

The accepted remote deployment is
`/home/wsy/prompt-mechanism-study-deployments/four-arm-v2-6c62671-20260825-05`; its experiment root
is `/home/wsy/prompt-mechanism-study-experiments/four-arm-v2-6c62671-20260825-05`. The local closed
archive is `.artifacts/four-arm-v2-6c62671-results.tar.gz`. Execution used Ubuntu 22, Python 3.12.13,
Semgrep 1.168.0, Bandit 1.9.4, and the A800 host. The deployment contains no Python bytecode files.

This result is archival evidence. The active package intentionally no longer
exposes the historical four-arm runner or verifier. Reproduce it from the
immutable artifact-closure commit `01e55ee` in a separate checkout or Git
worktree; do not restore that execution path to the active package. From that
checkout, run:

```text
prompt-mechanism-four-arm verify-analysis \
  data/formal/results/fresh-two-family-four-arm-qwen35-v2-analysis \
  --config configs/formal/four-arm-study-fresh-two-family-qwen35-v2.json \
  --tasks data/formal/four-arm-study-fresh-two-family-v2-tasks.jsonl
```
