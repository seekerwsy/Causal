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
