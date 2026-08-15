# Gate C bounded outcome canary v1

## Purpose and interpretation

Gate C is a two-task engineering canary over the exact Prompt variants admitted by Gate B. It checks
the transition from randomized Prompt arms to code-generation requests, one blind functional-judge
pass, and the independent static-analysis Oracle. It is not a powered experiment, a confirmatory ITT
estimate, or authorization to scale the randomized-discovery design.

The selected complete blocks are:

| CWE | Task | Target mechanism |
|---|---|---|
| CWE-78 | `cluster-b80c034159e718b8bbc9` | `safety.safe_subprocess` |
| CWE-89 | `cluster-22d97b466b5d2c737129` | `safety.sql_parameterization` |

Each block retains the Gate A assignment of four arm roles to seed slots 2026081511--2026081514.
Gate C does not re-randomize or edit the Gate B texts. It maps the exploratory identities into the
existing standard `AssignmentRecord`, `PromptVariantRecord`, and `GenerationRequestRecord`
contracts so the existing confirmation generator, functional judge, and Oracle can consume them.

## Frozen execution coordinates

- Code generator: the server-local `qwen2.5-coder-32b-instruct` service previously validated with
  SGLang on port 18101.
- Generation: eight requests, temperature zero, 1,024-token cap, exactly one permitted provider
  attempt per assignment.
- Functional judge: Ali Bailian `qwen3.5-flash-2026-02-23`, single blind pass, seed 73001, exactly one
  permitted provider attempt per generated syntax-valid program. The maximum is eight calls; terminal
  no-code and Python parse failures are classified locally without a judge call.
- Oracle: the authenticated Semgrep 1.168.0 plus Bandit 1.9.4 policy bundle. It receives generated
  code without arm coordinates.
- Live environment: the fixed remote Python 3.12 environment and localhost model service. The local
  Windows worktree is used only for contract construction and zero-provider planning because its
  Oracle executables and generator service are not the frozen live runtime.

The live configuration is
`configs/e2e-pilot/gate-c-qwen25-coder-32b-bailian-v1.yaml`. Credentials remain environment-only.
The checked-in `.env` exclusion remains unchanged, and no credential appears in plan artifacts.

## Functional contracts

`data/e2e-pilot/gate-c-cwe78-cwe89-v1` freezes exactly two pre-generation functional contracts. The
CWE-78 contract is reused byte-for-byte from the earlier 48-task A/B Codex audit because its task ID
and source Prompt digest match Gate B. The CWE-89 task was outside that audit sample, so it received
two consistent Codex passes under the same `functional-contract-audit-v1` rubric. Its contract asks
only whether the code defines the requested Python SQLite query function, uses `sqlite3`, and fetches
one record based on a supplied condition. It contains no security verdict, expected arm effect,
generated code, or Oracle result.

The bundle contains two contracts, one reused contract, one new contract, two new audit decisions,
zero failures, and zero pending items. Its SHA-256 is
`f43aac3f871e76754c23298f5a35bdb29b47a92e06db3eedbaf170419fd3291b`.

## Oracle coverage boundary

Both registered profiles currently have `zero_finding_supported=false`:

- `python.cwe78.closed_mapping_subprocess.v1`;
- `python.cwe89.function_parameter_sqlite_direct_query.v1`.

Consequently, a matched finding may establish an insecure result, while zero findings remain
`unknown_coverage`. Gate C must not relabel such a result as secure. This canary can validate outcome
plumbing, functional evaluation, finding-bearing security outcomes, and failure accounting, but it
cannot by itself establish a positive secure-and-functional effect.

## Zero-provider plan result

The immutable plan is
`runs/e2e-pilot/gate-c-canary-v1-plan-20260815-01`. It completed with:

- two independent tasks and two complete blocks;
- eight assignments, eight Prompt variants, and eight unique generation requests;
- four inherited arm roles and four inherited seed IDs;
- two functional contracts and two authenticated Oracle coverage profiles;
- zero provider calls, zero Oracle executions, zero errors, and eight pending generations.

The plan contains twelve files; the manifest authenticates the other eleven files and is the twelfth.
Seven adjacent request-planner, single-pass judge, and policy-authentication tests passed, followed by
two Gate C-specific configuration and contract-budget tests. No full test suite was run.

## Live authorization boundary

The plan does not authorize live execution. A live run requires separate approval for at most eight
server-local generation calls and at most eight Bailian functional-judge calls. It must use a new
remote run directory, persist every request/response or terminal failure, run the exact Oracle after
generation, and retain all eight assigned units in coverage reporting. A transport failure receives
no silent semantic retry; any incomplete unit must be diagnosed and repaired in a separately recorded
resume attempt.

## Approved live execution protocol

The bounded live authorization is operationalized by
`scripts/run_gate_c_live_canary.py` and
`configs/e2e-pilot/gate-c-live-canary-v1.json`. The dedicated executor consumes the authenticated
Gate C plan directly rather than fabricating the upstream M4 stage manifests required by the formal
confirmation pipeline. It reuses the production confirmation provider, single-pass blind functional
judge, and coordinate-blind Oracle primitives.

Execution is deliberately split into three commands and distinct artifact directories:

1. `validate` authenticates all eight assignments, requests, contracts, coverage records, and config
   budgets with zero provider calls and zero Oracle executions;
2. `pilot` executes the frozen CWE-89 target assignment only and persists its canonical generation
   request/response, exact Judge request/response, functional outcome, blind Oracle result, and unit
   manifest;
3. `remaining` is admitted only after the pilot is complete and executes the other seven assignments.

Every unit is written before moving to the next unit. The executor is fail-fast and never silently
retries a failed generation or Judge request. Oracle findings are generated from `OracleCodeInput`,
which excludes randomized assignment and arm coordinates; the assignment binding is written only
after blind analysis. Zero findings retain `unknown_coverage`.

The local zero-call live preflight is preserved at
`runs/e2e-pilot/gate-c-live-preflight-local-20260815-01`. It validated all eight pending assignments
with zero provider calls. The first remote readiness check on 2026-08-15 could not establish a TCP
connection to the registered SSH endpoint, so no server state, model process, paid call, or Oracle
execution was changed by that attempt.
