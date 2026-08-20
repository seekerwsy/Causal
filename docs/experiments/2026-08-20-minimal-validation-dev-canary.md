# Minimal D_DEV Validation Canary (2026-08-20)

## Purpose

This run validates the existing SecAware execution chain within one day. It is an
engineering canary, not a confirmatory experiment. Every generated report must
retain `scientific_claim_allowed=false`.

The canary reuses outcome-exposed tasks and previously validated Gate-B variants.
It therefore cannot support held-out, multi-realization, selector, or population
claims.

## Frozen scope

- Language: Python.
- Security scopes: CWE-78 and CWE-89.
- Code generator: `qwen2.5-coder-7b-instruct`, served locally.
- Functional judge: one blinded pass with `qwen3.5-flash-2026-02-23` through
  Bailian.
- Oracle: Python-v2 profile-scoped decision path.
- Arms: `target_patch` and `noop_rewrite` only.
- Micro gate: one task per CWE, four assignments.
- Full gate: six tasks per CWE, twenty-four assignments.
- Concurrency: serial execution; one provider attempt per stage.

The exact task set and the outcome-blind selection rationale are frozen in
`configs/minimal-validation/dev-canary-task-selection-v1.json`.

## Stage gates

1. Build immutable plans with no provider calls.
2. Run the live preflight with no provider calls.
3. Verify the registered model process, port, GPU capacity, Python environment,
   Oracle binaries, and presence (not values) of the two required secret variables.
4. Run one micro pilot assignment.
5. Inspect its generation, Judge, Oracle, status, and artifact manifest.
6. Run the remaining three micro assignments.
7. Produce the paired D_DEV summary.
8. Only if the micro run has four terminal units and no unresolved infrastructure
   error, repeat the sequence for the 12-task plan.

## Development diagnostics

The full canary is operationally healthy when all 24 assignments reach a recorded
terminal state, every generated artifact is traceable to its frozen assignment,
the Oracle is evaluable for at least 90% of assignments, and the Judge produces a
valid outcome for at least 95% of assignments. Target-change and semantic validity
remain diagnostics; they are never post-assignment filters.

Paired Target-minus-No-op differences for CWE-specific security, functionality,
and secure-and-functional outcomes are descriptive D_DEV quantities. Unknown,
invalid, or no-code outcomes contribute zero to the development ITT while their
coverage is reported separately. No p-value, confidence claim, or causal discovery
claim is authorized by this canary.

## Immutable local evidence

The first local plan and preflight artifacts are stored under:

- `runs/minimal-validation/dev-canary-micro-plan-local-20260820-01`
- `runs/minimal-validation/dev-canary-full-plan-local-20260820-01`
- `runs/minimal-validation/dev-canary-micro-plan-20260820-01`
- `runs/minimal-validation/dev-canary-full-plan-20260820-01`
- `runs/minimal-validation/dev-canary-micro-preflight-local-20260820-01`
- `runs/minimal-validation/dev-canary-full-preflight-local-20260820-01`

These directories are ignored by Git but must not be overwritten or deleted.

## Server layout

- Deployment: `/home/ubuntu/secaware-deployments/minimal-validation-da056b4-20260820-01`
- Model service record: `/home/ubuntu/secaware-model-services/qwen25-coder-7b-minimal-validation-20260820-01`
- Micro live run: `/home/ubuntu/secaware-experiments/runs/minimal-validation-qwen7b-2task-20260820-01`
- Full live run: `/home/ubuntu/secaware-experiments/runs/minimal-validation-qwen7b-12task-20260820-01`
- Outer execution logs: `/home/ubuntu/secaware-experiments/executions/minimal-validation-*`

## Recovery rule

Successful unit directories are immutable. On an error, diagnose the preserved
stage request, response, status, and traceback before retrying. Never delete or
overwrite a successful unit, silently retry a semantic failure, or reinterpret an
infrastructure failure as model randomness. A repair must have a new attempt record
and must account for every originally assigned unit.

## Known non-goals

- No JCI or RFCI run.
- No four-arm specificity analysis.
- No multi-model replication.
- No formal max-statistic or selector-utility inference.
- No claim that the task-specific legacy variants constitute two canonical
  realizations.
- No expectation that observational FCI discovers a natural feature effect; the
  existing D_DEV pool has already shown insufficient natural safety-feature
  variation.
