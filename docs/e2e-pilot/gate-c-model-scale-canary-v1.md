# Gate C 7B/14B model-scale canary v1

## Decision and estimand boundary

The existing 32B Gate C stratum remains unchanged. Two additional local generator strata are admitted
for engineering canaries:

| Stratum | Served model ID | Frozen local weight path | Nominal scale |
|---|---|---|---:|
| Qwen coder | `qwen2.5-coder-7b-instruct` | `/home/ubuntu/model-zoo/Qwen2.5-Coder-7B-Instruct` | 7B |
| Phi | `phi-4-14b` | `/home/ubuntu/model-zoo/phi4-14b` | 14B |

Model size is a producer stratum and provenance coordinate, not a prompt-side causal variable. Gate A
randomization, Gate C assignments, generated code, functional outcomes, Oracle outcomes, and effects
must remain separate by `model_id`. The canary does not pool 7B, 14B, and 32B effects. A later
cross-model comparison may summarize heterogeneity only after each model-specific ITT estimate is
reported.

The same selected tasks, candidate FeatureSpecs, four arm roles, seed set, frozen Gate B Prompt texts,
functional contracts, Oracle policy, generation template, token cap, and single-pass Judge policy are
reused. Gate B is not rerun because its validated Prompt variants are generator-independent. Gate A is
rerun for each model because `model_id` is part of the deterministic randomization block key.

## Target-host read-only audit

The target host `ubuntu@192.168.110.70`, reached through the registered jump host, was inspected on
2026-08-16 without starting a service or making a generation call.

- GPU: one NVIDIA GeForce RTX 5090, 32,607 MiB total, 32,086 MiB free, 0% utilization at audit time.
- Qwen weight directory: 15 GiB, four safetensor shards, BF16, Qwen2 architecture, 32,768 configured
  positions.
- Phi weight directory: 28 GiB, six safetensor shards, BF16, Phi-3 architecture, 16,384 configured
  positions.
- The base Python is 3.14.6. A user-level Python 3.10 vLLM command exists but is not runnable because
  its environment lacks `numpy`; the existing `mmo` environment also fails imports because `idna` is
  absent. These are environment failures, not model failures.
- The 7B BF16 model has comfortable device-memory headroom. The 14B BF16 model is close to the 32 GiB
  device limit and therefore requires a one-request service canary before any Gate C unit is spent.
  No quantization substitution is allowed under these model IDs.

## Frozen zero-call plans

The following model-specific Gate A directories were created with no provider or Oracle calls:

- `runs/e2e-pilot/randomized-exploratory-discovery-canary-qwen25-coder-7b-v1-20260816-01`;
- `runs/e2e-pilot/randomized-exploratory-discovery-canary-phi4-14b-v1-20260816-01`.

Each contains four independent tasks, four blocks, sixteen balanced assignments, sixteen variants,
zero errors, and zero pending units. The deterministic extractor recognized one of four target
features; as in the existing Gate A design, this is diagnostic only and does not filter Gate C.

The corresponding Gate C plans are:

- `runs/e2e-pilot/gate-c-canary-qwen25-coder-7b-v1-plan-20260816-01`;
- `runs/e2e-pilot/gate-c-canary-phi4-14b-v1-plan-20260816-01`.

Each authenticates two tasks, two complete four-arm blocks, eight assignments, eight unique generation
requests, two functional contracts, and two Oracle profiles. Both have zero errors and eight pending
generations. Both preserve `unknown_coverage` for an Oracle zero finding. Local live preflight validated
all eight units in each plan with zero provider, Judge, or Oracle calls.

## Verification record

The targeted configuration and adjacent Gate A tests passed 8/8 in 2.99 seconds after explicitly
binding `PYTHONPATH` to this worktree and using a repository-local pytest base directory. Two earlier
attempts did not reach the affected test logic: the first imported the main-worktree editable package;
the second used an unavailable user temporary directory. A third attempt used a missing parent for the
new base directory. These environment mistakes are recorded here so subsequent worktree tests use the
fixed invocation directly. No full test suite was run.

## Next execution gate

Before an experimental assignment may run on the target host:

1. create a new versioned Python 3.10/3.11 serving environment without modifying either broken
   historical environment;
2. save its package lock, GPU snapshot, model metadata digests, launch command, stdout, and stderr;
3. start the 7B service first and perform only non-experimental health checks plus one separately
   labeled service-format canary;
4. stop the 7B service and repeat for 14B; reject 14B cleanly if BF16 cannot fit without changing the
   registered weight representation;
5. only after service approval, deploy the authenticated plan and run the registered Gate C pilot
   assignment for one model at a time.

No scale-up or scientific effect claim is authorized by this document.

## Target-host serving result

The isolated serving environment was subsequently created at
`/home/ubuntu/secaware-envs/gate-c-vllm-0.16.0-py310-20260816-01`. Its readiness record is
`/home/ubuntu/secaware-experiments/readiness/gate-c-vllm-env-20260816-01`. The authoritative status is
`READY`; imports resolved to Python 3.10.12, vLLM 0.16.0, PyTorch 2.9.1+cu128, Transformers 4.57.6,
NumPy 2.2.6, and idna 3.18. The historical base and `mmo` environments were not modified.

The 7B service reached `READY`, passed one non-security `add_one` service-format canary, and was then
stopped. Its response used one exact Python Markdown fence. This is a supported provider envelope:
the production provider removes that exact envelope, records `source_envelope=python_fence` in
provenance, and returns the decoded source. The authoritative canary correction is
`status-v3.txt=PASS_WITH_SUPPORTED_PYTHON_FENCE`; the decoded program compiled successfully.

Two earlier files in that same canary directory are intentionally retained but superseded. The first
manual check compiled the raw fenced response instead of passing it through the production provider,
then incorrectly wrote `PASS` because the interactive shell did not fail fast. The attempted v2
correction embedded literal backticks in a shell command, which triggered command substitution and
again wrote a status after the decoder failed. `adjudication-v3.txt` marks both statuses invalid. The
v3 check represents the fence without literal shell backticks, gates status creation on both decoding
and compilation, and is authoritative.

The 14B BF16 service also reached `READY` without quantization. At readiness it used 30,938 MiB of the
32,607 MiB GPU and left 1,172 MiB free, so it remains restricted to one sequence and a 4,096-token
context. Its independently saved `add_one` canary passed strict production-envelope decoding and
Python compilation on the first gated attempt. Both services were stopped after validation; a final
GPU check reported 32,086 MiB free and 0% utilization.

These checks establish serving and response-envelope feasibility only. Counts remain: two service
profiles ready, two service-format canaries complete, zero services running, zero Gate C experimental
assignments completed, sixteen model-specific Gate C assignments pending, and zero Bailian Judge or
Oracle calls made for the new model strata.

## Locked Oracle compatibility directory

The Linux Oracle runner intentionally gives each analyzer a minimal `PATH` containing only the
directory of the resolved analyzer executable. Semgrep 1.168.0 also invokes `uname -s` while
constructing its system X.509 authenticator. A plain environment `bin` directory therefore makes
Semgrep exit with code 2 even though the same policy scan succeeds outside the minimal environment.

The first compatibility attempt, `scripts/setup_gate_c_oracle_compat_v1.sh`, recreated the two Python
entry points. Version probes passed, but complete isolated batches were not reliable, so that v1
directory is retained as rejected evidence and is not approved for a live run.

`scripts/setup_gate_c_oracle_compat_v2.sh` instead copies the exact pip-generated Semgrep and Bandit
entry points from the locked source-built Python environment and adds a copied `/usr/bin/uname`.
Live runs prepend this versioned, read-only directory to the parent process `PATH`; resolving Semgrep
from that directory causes the isolated child to retain the same bounded directory as its complete
`PATH`. This preserves the minimal-environment boundary instead of adding general system directories
to analyzer execution. The setup record includes tool versions, source and destination SHA-256
digests, and environment metadata.

The first complete v2 batch passed Semgrep but reported a runner-level Bandit failure. A Bandit-only
reproduction then passed with one expected CWE-89 finding, and two subsequent complete batches both
passed Semgrep and Bandit. This anomaly is not treated as model randomness. The operational gate now
requires two consecutive complete batch passes before an Oracle-only repair or a new provider call.
The repository checkpoint initially applied an executable bit to this Markdown file together with
the shell script; commit `054a7d7` immediately restored the document mode and records that mistake.

## Oracle-only pilot recovery

`scripts/recover_gate_c_live_oracle.py` is the only approved recovery path for a pilot that already
completed generation and the single-pass functional Judge but failed in Oracle execution. It refuses
an in-place repair. The source run must have a closed unit manifest, exactly one failed pilot, an
`oracle` failure stage, one generated-code record, one Judge pass, no Oracle output, and the same
authenticated live configuration, application configuration, and Gate C plan.

The recovery first hashes and copies the complete source run to a new directory. It preserves the old
error, status, and unit manifest under their original bytes, then reruns only the blind Oracle batch.
The new unit manifest covers both the preserved failure evidence and the recovery artifacts. Its
provenance fixes new generation and Judge calls at zero. A second Oracle failure also produces a
closed error unit and report rather than a partially updated run. Only a successful recovered copy
may satisfy the existing pilot prerequisite for the remaining seven assignments.

The first 14B pilot exposed a separate post-analysis status bug: generation, one Judge call, Oracle
analysis, and blind binding all completed, after which the executor read
`AssignmentExecutionRecord.provider_attempt_count`. The schema field is `attempt_count`. The live
executor now uses the schema field. Oracle recovery also recognizes this exact authenticated failure
shape, validates the preserved analysis-to-code binding, and finalizes a copied run with zero new
generation, Judge, or Oracle calls. It does not accept a partial Oracle pair or an unrelated
post-analysis exception.

## Completed model-specific pilots

The 7B source run is retained at
`/home/ubuntu/secaware-experiments/runs/gate-c-live-qwen25-coder-7b-pilot-20260816-01`.
Generation and the one-pass functional Judge both completed, but its first Oracle execution failed
because the initially selected Python runtime lacked the required Linux `memfd_create` capability.
After the source-built Python runner and locked v2 analyzer compatibility directory passed the
batch gate, the Oracle-only recovery copied the run to
`/home/ubuntu/secaware-experiments/runs/gate-c-live-qwen25-coder-7b-pilot-oracle-recovered-20260817-01`.
The recovered unit is complete with one inherited generation call, one inherited Judge call, and one
new Oracle execution. The functional outcome is `pass`; Oracle reports `insecure`, with one Bandit
CWE-89 finding. Post-validation confirmed byte-identical generated code, Judge request and response,
functional outcome, old status, and old manifest, while the source run snapshot remained unchanged.

The 14B source run is retained at
`/home/ubuntu/secaware-experiments/runs/gate-c-live-phi4-14b-pilot-20260817-01`.
Generation, the one-pass Judge, both analyzers, and blind Oracle binding completed before the
post-analysis status-field bug raised. The finalizer copied the run to
`/home/ubuntu/secaware-experiments/runs/gate-c-live-phi4-14b-pilot-oracle-finalized-20260817-01`
and reused the authenticated Oracle analysis byte for byte. The recovered unit is complete with zero
new generation, Judge, or Oracle calls. Its functional outcome is `pass`; Oracle also reports
`insecure`, with one Bandit CWE-89 finding. Post-validation confirmed that the source snapshot,
generated code, Judge response, Oracle analysis, Oracle binding, old status, and old manifest were
unchanged.

Both model services were stopped after their pilots; the final GPU snapshot reported 32,086 MiB free
and 0% utilization. Each model-specific run now has one completed assignment, zero errors, and seven
pending assignments. These two observations are engineering pilots, not effect estimates. The
registered live configurations still set `scale_up_allowed=false`, so the remaining assignments have
not been run and no scientific comparison between 7B and 14B is authorized.

## Bounded remaining-assignment authorization

On 2026-08-17 the user approved completing only the seven pending assignments in each of the two
model-specific canaries. This authorization does not add a model, task, arm, seed, provider attempt,
or scientific claim. The original pilot configurations remain unchanged with
`scale_up_allowed=false`. Two new authorization configurations set `scale_up_allowed=true` and bind
the approval to `user-approved-remaining-20260817-v1` with scope
`remaining_assignments_only`.

The executor accepts those configurations only in `remaining` mode and only when replacing the two
authorization fields and flipping `scale_up_allowed` back to false produces the exact live
configuration stored by the completed pilot. It also re-authenticates the application configuration
and source-plan manifest before making a provider call. The authorized configuration, frozen base
configuration digest, selected pending assignment IDs, command, environment, and input digests are
saved separately in the existing recovered run. Existing pilot and recovery evidence is not
overwritten.

Execution remains sequential: start a new versioned 7B service record, complete and validate its
seven pending assignments, stop the service, and only then repeat for 14B. Any failed unit triggers
fail-fast and blocks the second model until the failure has been diagnosed and repaired. Completion
of these engineering canaries still does not by itself authorize a pooled comparison or a formal
main-experiment claim.
