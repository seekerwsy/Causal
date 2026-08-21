# SecAware

SecAware is a reproducible Python CLI prototype for TSG-driven prompt-side
security mechanism discovery and confirmation.

For a compact review order, start with the [reviewer guide](docs/reviewer-guide.md).
The routine reviewer test command is documented in [tests/README.md](tests/README.md);
multi-minute evidence-chain tests are reserved for structural milestones.

## Architecture and causal boundary

Prompt TSG supplies semantic task-feature and target-feature relationships for extraction and
intervention validation. Prompt TSG edges are not causal edges and are never passed to FCI, JCI,
or RFCI as causal adjacencies. The `shadow` mapping is a read-only audit projection derived from
the graph. It is never authoritative and is not an input to discovery, intervention, confirmation,
or security labeling.

The only security outcome `Y` comes from the independent Semgrep 1.168.0 plus Bandit 1.9.4
Oracle. Prompt TSG does not classify generated code, and its graph factors cannot create, replace,
filter, or override an Oracle label. Code TSG is no longer a mandatory stage and has been removed
from the production pipeline, CLI, artifacts, manifests, and configuration. There is no Code TSG
compatibility path.

The Oracle is fail closed. An unavailable, mismatched, incomplete, malformed, or otherwise invalid
static analyzer run publishes no security result; SecAware has no handwritten or reduced-security
fallback. A valid run with zero findings is not automatically `secure`: it is
`unknown_coverage` unless the prompt's frozen `oracle_profile_id` names a hash-locked task/CWE
coverage profile whose negative-verdict calibration has been approved. Findings still produce an
`insecure` result. Prompt TSG validation also fails closed: an invalid graph, digest, schema,
catalog, or shadow prevents downstream publication rather than falling back to v1 data or flat
projections.

See [Prompt TSG v2 migration](docs/migrations/prompt-tsg-v2.md) before opening or rerunning an
existing run directory.

## Prompt extraction in M4A

M4A implements Prompt TSG 2.1 extraction. The `extract-prompt-tsg` command reads the configured
prompt input and publishes exactly two run-locked artifacts:

- `tsg/prompt_extraction_proposals.jsonl`, the bounded backend proposal and its provenance;
- `tsg/prompt_tsg.jsonl`, the validated canonical Prompt TSG used by graph queries.

Each input prompt requires `task_id`. Select one extractor explicitly with
`tsg.prompt_extractor`: `llm_facts_v1` (the default), `llm_direct_graph_v1`, or
`deterministic_catalog_v1`. The offline `configs/demo.yaml` deliberately overrides the default
with `deterministic_catalog_v1`, so prompt extraction does not require a network call or API key.
The LLM configuration in `configs/paper_v0.yaml` records an OpenAI-compatible `base_url`,
`model_id`, and the non-secret `api_key_env` environment-variable name; credentials belong only in
that named environment variable.

Run extraction alone with:

```bash
secaware extract-prompt-tsg --config configs/demo.yaml --run-dir runs/demo --force
```

Backend selection is exact and run-wide. There is no per-prompt fallback, ranking, winner, or
automatic selection. Invalid proposals fail closed before either output is committed.

## Prompt-only FCI discovery in M4B

M4B replaces heuristic discovery with the pinned no-Java minimum backend
`causal-learn==0.1.4.7`. `secaware discover` constructs one local categorical table per CWE scope
and model, derives temporal tiers, forbidden directions, and typed two-way adjacency exclusions
from the Prompt TSG contract, and runs FCI with the G-square conditional-independence test. The
background knowledge never requires a candidate edge or a selected path edge, and every returned
PAG is checked against it. PAG circle endpoints are preserved as uncertainty rather than converted
to a DAG.

Reference and task-cluster bootstrap matrices select one seed per task occurrence. Failed replicate
runs remain in the configured denominator and contribute zero path support. Stable possible
Prompt-side paths are frozen as `discovery/hypotheses_frozen.jsonl` before any randomized
confirmation artifact can exist. `NO_STABLE_HYPOTHESIS` and excessive bootstrap failures are
committed terminal diagnostics: discovery artifacts remain inspectable, but the CLI exits nonzero
and M5 cannot begin.

The discovery transaction publishes 11 JSONL artifacts: three local-table artifacts and eight
FCI/bootstrap/path/freeze artifacts. See [FCI discovery migration](docs/migrations/fci-discovery.md)
for their exact names, assumptions, and provenance. This is a Prompt-only causal-variable layer:
there is no Code TSG. Generated code is used only to bind Prompt generation to the independent
Oracle result through provenance metadata; code text, structure, findings, and mechanisms are not
causal variables.

The public discovery entry point is `discover`. The old heuristic and two-arm
intervention/confirmation commands are not CLI-reachable. `run-all` continues from frozen discovery
through the M5 randomized-confirmation commit described below.

## Randomized prompt confirmation in M5

M5 freezes pre-outcome prompt roles, exact positive/neutral counterparts, semantic target and
protocol definitions, task-bound instances, and independently extracted prompt variants before any
assignment. Its public commands are:

```bash
secaware build-confirmation-variants --config configs/demo.yaml --run-dir runs/demo
secaware randomize-confirmation --config configs/demo.yaml --run-dir runs/demo
secaware generate-confirmation --config configs/demo.yaml --run-dir runs/demo
secaware run-oracle --config configs/demo.yaml --run-dir runs/demo --condition confirmation
secaware judge-functionality --config configs/experiment.yaml --run-dir runs/experiment
```

`judge-functionality` is enabled only when `data.task_functional_contracts_path` points to a
pre-treatment contract bundle and `functional_judge` freezes an independent OpenAI-compatible
endpoint, model, two distinct seeds, and an API-key environment variable. The request withholds
arm, CWE, security outcome, and generator identity. Two passes are retained; exact status
disagreement becomes `unknown`. Terminal no-code and invalid Python are local fail-closed gates and
do not call the judge. The stage writes `analysis/functional_judge_passes.jsonl` and
`analysis/program_functional_outcomes.jsonl`; effects consume the latter for
`secure_functional_success`. `unknown` is a conservative zero in the primary assigned-arm ITT and
also expands the registered best/worst-case sensitivity bounds. It never filters an assignment.

The checked-in `configs/paper_v0.yaml` freezes the independent evaluator to Ali Bailian's Beijing
pay-as-you-go OpenAI-compatible endpoint and the dated `qwen3.5-flash-2026-02-23` snapshot, with
thinking disabled and two distinct seeds. The credential is read only from
`ALI_BAILIAN_API_KEY`; it must never be committed or persisted in run artifacts. The stage becomes
runnable only after a derived experiment config enables it and supplies a task-functional-contract
path covering every assigned task. No mock judge result may be reported as a commercial-model
result.

The frozen coordinates passed a real two-case compatibility canary on 2026-08-12: the correct
fixture received two `pass` judgments and the known-wrong fixture received two `fail` judgments.
The strict parser rejected an earlier scalar `code_evidence` response, so the prompt now states the
array invariant explicitly rather than relaxing the schema. This validates provider compatibility,
not research-task accuracy; the full experiment still requires the frozen task contracts and a new
immutable run directory.

`run-all` executes observed generation and Oracle evaluation, local-table assembly, frozen FCI
hypothesis discovery, variant construction, complete-block randomization, confirmation generation,
and the independent confirmation Oracle in that order. It then requires any preregistered
functional outcomes, estimates randomized effects, runs secondary JCI and optional RFCI, and
publishes the report bundle. Once the report and its manifest form a valid completed run, the run
directory is immutable. A later `run-all` validates and reuses it without executing providers or
analyzers; `run-all --force` is rejected as well. Start a new run directory instead of deleting,
rebuilding, or overwriting a completed run.

The migration is intentionally breaking: `intervene` and `generate-counterfactual` are no longer
registered commands, and paired two-arm artifacts are not accepted as randomized-confirmation
inputs. See [Randomized confirmation migration](docs/migrations/randomized-confirmation.md) for the
security-neutral prompt invariant, per-arm deltas, text/graph execution modes, LLM executor
assumption, blind extractor boundary, seed slots, assignment commit point, terminal-no-code
handling, and exact artifact replacements.

## Prompt-only confirmation analysis in M6

Randomized ITT is the primary confirmatory estimate. JCI is secondary and cannot alter the
randomized ITT or frozen hypotheses. RFCI is an optional Java-backed sensitivity analysis; a
disabled or unavailable RFCI runtime is reported as capability provenance and does not redefine
the primary result. PAG circle endpoints remain circles unless a declared, separately recorded
constraint supplies an orientation.

Generated code is used only by the independent Oracle and an explicitly configured functional
evaluator. Unknown functional evidence is a conservative zero in the primary ITT, while
best/worst-case sensitivity bounds retain all randomized assignments. Pre-randomization
exclusions are committed before assignment, while post-assignment generation, Oracle, or evaluator
failures remain in their assigned ITT arms.

## Functional contract pilot

The reproducible 48-task pilot is selected as three cluster-distinct candidate-neutral
CyberSecEval Instruct v2 tasks for each of 16 frozen CWE scopes:

```bash
secaware prepare-functional-audit \
  --config configs/functional-audit/pilot-v1.json \
  --source-record-audit runs/dataset-audit/stage0-combined-20260810-08/record-audit.jsonl \
  --run-dir runs/functional-audit/a-new-run-id
```

The published audit retains 48 packets, 96 Codex A/B decisions, 48 consistent task contracts, the
exact command, environment, configuration, source digest, and bundle digests under the immutable
run `runs/functional-audit/pilot-contracts-20260812-01` and the versioned snapshot
`data/functional-audit/pilot-v1`. The selector refuses to overwrite an existing run directory. All
48 contracts are currently `semantic_only`; 30 record explicit external
environment dependencies. This supports code-level semantic judging but does not claim 48 local
executable test harnesses.

See the [Prompt-only FCI/JCI migration](docs/migrations/prompt-only-fci-jci.md) for the exact
artifact inventory, digest bindings, regeneration procedure, and upgrade boundary.

SecAware supports Python 3.12 patch releases only (`>=3.12,<3.13`). Install the core development
environment and run the unit suite with:

```bash
pip install -e ".[dev]"
pytest
```

Generation can use offline results without an external LLM API. Oracle stages are intentionally
different: they require the exact external analyzers described below. `run-all` includes those
stages and therefore has the same Oracle requirements.

## Install and run the Oracle

The Oracle extra pins the only supported analyzer versions:

```bash
uv sync --extra dev --extra oracle
# Equivalent editable pip install: pip install -e ".[dev,oracle]"
```

The finite Semgrep rules, Bandit configuration, Bandit metadata, task/CWE coverage contract, and
their authenticated lock are checked into `policies/oracle/python/`. Semgrep metrics and version
checks are disabled, and no remote rule registry or network policy lookup participates in a run.
Every prompt must bind one coverage profile before generation. `preflight` authenticates that
profile against the prompt CWE and task family without invoking either analyzer.

Validate the general experiment inputs, then run the observed Oracle stage:

```bash
secaware preflight --config configs/demo.yaml
secaware run-oracle --config configs/demo.yaml --condition observed
```

`preflight` validates the general pipeline configuration and the locked prompt-to-coverage-profile
binding. `run-oracle` additionally performs the Oracle capability check, authenticates the policy
bundle, resolves both executables, requires Semgrep 1.168.0 and Bandit 1.9.4, and reruns the
capability check immediately before analysis.

The same engine is available as a standalone command for canonical generated-code JSONL:

```bash
secaware-oracle run \
  --input runs/demo/generation/observed_code.jsonl \
  --output runs/demo/oracle/observed_oracle.jsonl \
  --policy-lock policies/oracle/python/policy.lock.json \
  --semgrep semgrep \
  --bandit bandit
```

Because this standalone interface has no prompt artifact, a parseable zero-finding program is
reported as `unknown_coverage`; it cannot publish a task-scoped `secure` verdict. Use the pipeline
Oracle stage when authenticated negative-verdict coverage is required.

Run the checked-in real-tool release gate with:

```bash
uv run pytest -m oracle_tools
```

Without the exact optional dependencies and executable commands, this marked integration test is
explicitly skipped; it never passes via an internal substitute. Production Oracle commands do not
skip: a missing or mismatched analyzer, invalid or incomplete report, policy mismatch, timeout, or
unsupported runtime capability returns an error and publishes no Oracle result.

## Oracle execution support

The independent external-analyzer Oracle is fail-closed and has a narrower runtime support matrix
than the rest of the Python package:

| Runtime | Oracle execution |
| --- | --- |
| Windows | Supported when a suspended helper completes Job assignment, Toolhelp thread discovery, resume, wait, and reap during preflight. |
| Linux | Supported when sealed memfd/proc-fd checks, unprivileged user, PID, and mount namespaces, and a private `/proc` mount pass preflight. |
| macOS, BSD, other POSIX systems | Unsupported; Oracle preflight fails with `ANALYZER_FAILED`. |
| Linux with namespaces disabled or blocked | Unsupported; Oracle preflight fails with `ANALYZER_FAILED`. |

`validate_analyzer_runtime()` performs this capability preflight with only a fixed, short-lived
helper; it never resolves or starts an analyzer.
Oracle entry points must call it before analyzer validation and again before starting the Oracle
stage. The general SecAware preflight and non-Oracle package components remain available on other
platforms; there is no reduced-security Oracle fallback.

The `oracle` configuration block selects the locked policy, analyzer executables, timeout, and
output bounds. It has no switch for an internal security analyzer and changing it cannot bypass the
runtime capability check. Security labels come only from successful, complete reports from both
locked analyzers; there is no handwritten-rule or reduced-security fallback.
