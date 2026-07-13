# SecAware

SecAware is a reproducible Python CLI prototype for TSG-driven prompt-side
security mechanism discovery and confirmation.

## Architecture and causal boundary

Prompt TSG v2 supplies pre-treatment graph factors: its canonical graph is the authority for
prompt-side factor and motif queries used in discovery and intervention validation. The `shadow`
mapping is a read-only audit projection derived from that graph. It is never authoritative and is
not an input to discovery, intervention, confirmation, or security labeling.

The only security outcome `Y` comes from the independent Semgrep 1.168.0 plus Bandit 1.9.4
Oracle. Prompt TSG does not classify generated code, and its graph factors cannot create, replace,
filter, or override an Oracle label. Code TSG is no longer a mandatory stage and has been removed
from the production pipeline, CLI, artifacts, manifests, and configuration. There is no Code TSG
compatibility path.

The Oracle is fail closed. An unavailable, mismatched, incomplete, malformed, or otherwise invalid
static analyzer run publishes no security result; SecAware has no handwritten or reduced-security
fallback. Prompt TSG validation also fails closed: an invalid graph, digest, schema, catalog, or
shadow prevents downstream publication rather than falling back to v1 data or flat projections.

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

At the M4B boundary, the public discovery workflow entry points are `discover` and `run-all`; the
old heuristic and two-arm intervention/confirmation commands are not CLI-reachable. `run-all` stops
after the frozen discovery transaction and prints `SecAware discovery complete`. M5 will extend that
boundary with randomized confirmation.

Install the core development environment and run the unit suite with:

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

The finite Semgrep rules, Bandit configuration, Bandit metadata, and their authenticated lock are
checked into `policies/oracle/python/`. Semgrep metrics and version checks are disabled, and no
remote rule registry or network policy lookup participates in a run.

Validate the general experiment inputs, then run the observed Oracle stage:

```bash
secaware preflight --config configs/demo.yaml
secaware run-oracle --config configs/demo.yaml --condition observed
```

`preflight` validates the general pipeline configuration. `run-oracle` additionally performs the
Oracle capability check, authenticates the policy bundle, resolves both executables, requires
Semgrep 1.168.0 and Bandit 1.9.4, and reruns the capability check immediately before analysis.

The same engine is available as a standalone command for canonical generated-code JSONL:

```bash
secaware-oracle run \
  --input runs/demo/generation/observed_code.jsonl \
  --output runs/demo/oracle/observed_oracle.jsonl \
  --policy-lock policies/oracle/python/policy.lock.json \
  --semgrep semgrep \
  --bandit bandit
```

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
