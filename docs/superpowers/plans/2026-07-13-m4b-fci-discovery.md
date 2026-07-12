# M4B Prompt-Only FCI Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace heuristic TSG-QCD discovery with exact Prompt-only local tables, TSG-derived background knowledge, causal-learn FCI/G-square, task-cluster bootstrap, stable path extraction, and frozen hypotheses.

**Architecture:** Assemble bounded discrete tables per CWE/security scope and model from Prompt TSG queries plus committed Oracle outcomes. Run pinned causal-learn FCI through a backend-neutral PAG codec, bootstrap task IDs with one selected seed per sampled occurrence, and freeze only stable Prompt-side paths before any confirmation artifact exists.

**Tech Stack:** Python 3.10+, causal-learn 0.1.4.7, NumPy, Pandas, Pydantic 2, NetworkX 3, multiprocessing spawn supervision, pytest, Ruff.

---

## File responsibility map

- `src/secaware/schema/causal.py`: table, variable, BK, PAG, bootstrap, path, failure, and frozen-hypothesis records.
- `src/secaware/causal/variable_catalog.py`: finite Prompt-side `W/X/Y` variable declarations.
- `src/secaware/causal/table_builder.py`: exact producer joins and categorical row encoding.
- `src/secaware/causal/background.py`: tiers, forbidden directions, typed adjacency exclusions, final PAG validation.
- `src/secaware/causal/pag.py`: backend-neutral endpoint/edge codec and canonical digest.
- `src/secaware/discovery/causal_learn_backend.py`: pinned FCI/G-square adapter only.
- `src/secaware/discovery/fci_supervisor.py`: bounded spawned-process execution.
- `src/secaware/causal/bootstrap.py`: task-cluster draw manifests and support aggregation.
- `src/secaware/causal/paths.py`: endpoint-aware possible-path enumeration and compatibility.
- `src/secaware/causal/freeze.py`: immutable hypothesis construction and downstream freeze gate.
- `src/secaware/randomness.py`: versioned SHA-256 rejection/Fisher-Yates RNG reused by M5/M6.
- `src/secaware/pipeline/stages/causal_tables.py`: transactional local-table stage.
- `src/secaware/pipeline/stages/fci_discovery.py`: BK, FCI, bootstrap, path, and freeze stage.
- `src/secaware/cli.py`: thin `discover` orchestration.

### Task 1: Pin causal-learn and add strict causal schemas/configuration

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/secaware/config.py`
- Create: `src/secaware/schema/causal.py`
- Modify: `src/secaware/schema/__init__.py`
- Modify: `configs/demo.yaml`
- Modify: `configs/paper_v0.yaml`
- Create: `tests/test_causal_schema.py`
- Modify: `tests/test_config_v1.py`
- Modify: `tests/test_packaging.py`

- [ ] **Step 1: Write failing dependency, config, and schema tests**

```python
def test_minimum_backend_is_pinned_causal_learn_gsq() -> None:
    config = FCIDiscoveryConfig()
    assert config.backend == "causal_learn_fci_v1"
    assert config.ci_test == "gsq"
    assert config.depth >= 0
    assert config.max_path_length >= 1


def test_pag_edge_preserves_circle_endpoints_and_canonical_order() -> None:
    edge = PAGEdgeRecord(
        left="x.safety.path_normalization",
        right="y.secure_functional",
        left_mark=EndpointMark.CIRCLE,
        right_mark=EndpointMark.ARROW,
    )
    assert edge.left_mark is EndpointMark.CIRCLE
    assert edge.left < edge.right
```

Add strict tests for ID patterns, duplicate variables/rows/edges, unsorted fields, non-finite
configuration, unbounded depth/path values, more than 64 variables, more than 100,000 rows, invalid
categorical codes, required BK edges, unknown endpoint marks, duplicate bootstrap draw indices,
unsafe repr/error text, and mutation/revalidation of nested records.

- [ ] **Step 2: Install the pinned dependency and verify tests are RED**

Add `causal-learn==0.1.4.7` to the base dependencies, then install without creating a lock file:

```powershell
uv pip install --python .\.venv\Scripts\python.exe -e ".[dev,api]"
.\.venv\Scripts\python.exe -m pytest -q tests/test_causal_schema.py tests/test_config_v1.py tests/test_packaging.py
```

Expected: dependency installation succeeds; tests fail because causal schemas/config do not exist.

- [ ] **Step 3: Implement bounded discovery configuration**

Replace heuristic score configuration with:

```python
class FCIDiscoveryConfig(StrictModel):
    backend: Literal["causal_learn_fci_v1"] = "causal_learn_fci_v1"
    backend_version: Literal["0.1.4.7"] = "0.1.4.7"
    ci_test: Literal["gsq"] = "gsq"
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0, allow_inf_nan=False)
    depth: int = Field(default=3, ge=0, le=8)
    max_path_length: int = Field(default=6, ge=1, le=16)
    timeout_seconds: float = Field(default=120.0, gt=0.0, le=3600.0)
    max_variables: int = Field(default=64, ge=2, le=64)
    max_rows: int = Field(default=100_000, ge=2, le=100_000)
    bootstrap_samples: int = Field(default=200, ge=1, le=10_000)
    stability_threshold: float = Field(default=0.80, gt=0.0, le=1.0)
    max_candidate_paths: int = Field(default=512, ge=1, le=4096)
    min_independent_tasks: int = Field(default=20, ge=2, le=100_000)
    max_failed_bootstrap_fraction: float = Field(default=0.10, ge=0.0, lt=1.0)
```

`AppConfig.discovery` becomes `FCIDiscoveryConfig`. Remove heuristic weights, support-side counts,
and top-k scoring fields from active config and update both YAML files.

- [ ] **Step 4: Implement the persisted causal record vocabulary**

Define these exact enums and core records; all use strict, frozen, hidden-input validation:

```python
class VariableRole(str, Enum):
    W = "w"
    X = "x"
    Y = "y"
    C = "c"


class EndpointMark(str, Enum):
    TAIL = "tail"
    ARROW = "arrow"
    CIRCLE = "circle"


class PAGRunKind(str, Enum):
    OBSERVATIONAL_REFERENCE = "observational_reference"
    OBSERVATIONAL_BOOTSTRAP = "observational_bootstrap"
    JCI_RAW = "jci_raw"
    JCI_CONSTRAINED = "jci_constrained"
    RFCI_SENSITIVITY = "rfci_sensitivity"


class CausalVariableSpec(VersionedModel):
    schema_version: Literal["1.0"]
    variable_id: str
    role: VariableRole
    states: tuple[str, ...]
    source_query_id: str
    scope_id: str
    temporal_tier: int = Field(ge=0, le=2)
    adjacency_type: str
    producer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CausalTableRecord(VersionedModel):
    schema_version: Literal["1.0"]
    table_id: str = Field(pattern=r"^table_[0-9a-f]{64}$")
    scope_id: str
    cwe: str
    model_id: str
    variables: tuple[CausalVariableSpec, ...]
    row_count: int = Field(ge=2, le=100_000)
    independent_task_count: int = Field(ge=2, le=100_000)
    table_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CausalObservationRecord(VersionedModel):
    schema_version: Literal["1.0"]
    table_id: str = Field(pattern=r"^table_[0-9a-f]{64}$")
    row_id: str = Field(pattern=r"^row_[0-9a-f]{64}$")
    task_id: str
    prompt_id: str
    model_id: str
    seed_id: int
    values: tuple[int, ...]


class PAGEdgeRecord(StrictModel):
    left: str
    right: str
    left_mark: EndpointMark
    right_mark: EndpointMark

    def marks_from(self, source: str, target: str) -> tuple[EndpointMark, EndpointMark]:
        if (source, target) == (self.left, self.right):
            return self.left_mark, self.right_mark
        if (source, target) == (self.right, self.left):
            return self.right_mark, self.left_mark
        raise ValueError("edge does not contain the requested ordered pair")


class PAGRecord(VersionedModel):
    schema_version: Literal["1.0"]
    pag_id: str = Field(pattern=r"^pag_[0-9a-f]{64}$")
    run_kind: PAGRunKind
    table_id: str = Field(pattern=r"^table_[0-9a-f]{64}$")
    backend: str
    backend_version: str
    ci_test: Literal["gsq"]
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    background_knowledge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    variable_ids: tuple[str, ...]
    edges: tuple[PAGEdgeRecord, ...]


class BackgroundKnowledgeRecord(VersionedModel):
    schema_version: Literal["1.0"]
    knowledge_id: str = Field(pattern=r"^bk_[0-9a-f]{64}$")
    table_id: str = Field(pattern=r"^table_[0-9a-f]{64}$")
    tiers: tuple[tuple[str, int], ...]
    unconstrained_variable_ids: tuple[str, ...] = ()
    forbidden_directions: tuple[tuple[str, str], ...]
    forbidden_adjacencies: tuple[tuple[str, str], ...]
    required_directions: tuple[tuple[str, str], ...] = ()
    knowledge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
```

Add `CausalExclusionRecord`, `BootstrapDrawRecord`,
`BootstrapFailureRecord`, `DiscoveryFailureRecord`, `PathPatternRecord`, and `PathSupportRecord` in the same file. `DiscoveryFailureRecord` binds `table_id`, `scope_id`, `model_id`, a finite
`reason_code` (including `NO_STABLE_HYPOTHESIS`), the relevant producer/config digests, and a safe
detail digest without raw prompt/code text. Every ID is
derived from canonical content and every tuple is sorted unless order is semantically meaningful.

- [ ] **Step 5: Re-run schema/config/packaging tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_causal_schema.py tests/test_config_v1.py tests/test_packaging.py
```

Expected: PASS and `importlib.metadata.version("causal-learn") == "0.1.4.7"`.

- [ ] **Step 6: Commit**

```powershell
git add pyproject.toml src/secaware/config.py src/secaware/schema/causal.py src/secaware/schema/__init__.py configs tests/test_causal_schema.py tests/test_config_v1.py tests/test_packaging.py
git commit -m "feat: add bounded causal discovery contracts"
```

### Task 2: Build exact local Prompt-only causal tables

**Files:**
- Create: `src/secaware/causal/__init__.py`
- Create: `src/secaware/causal/variable_catalog.py`
- Create: `src/secaware/causal/table_builder.py`
- Modify: `src/secaware/schema/oracle.py`
- Modify: `src/secaware/oracle/aggregator.py`
- Create: `tests/test_causal_table_builder.py`
- Create: `tests/test_causal_provenance_boundary.py`
- Modify: `tests/test_oracle_schema_v1.py`
- Modify: `tests/test_oracle_engine.py`

- [ ] **Step 1: Write failing exact-join and leakage tests**

```python
def test_local_tables_are_per_scope_and_model_and_contain_no_model_column() -> None:
    tables, rows, exclusions = build_local_tables(_prompts(), _graphs(), _oracles(), _catalog())
    assert {(item.cwe, item.model_id) for item in tables} == {
        ("CWE-22", "model-a"),
        ("CWE-22", "model-b"),
    }
    assert all("model" not in {var.variable_id for var in table.variables} for table in tables)
    assert all(len(row.values) == len(_table(rows, tables, row.table_id).variables) for row in rows)
    assert exclusions == ()


@pytest.mark.parametrize("mutation", [_duplicate_oracle, _omit_oracle, _extra_oracle, _swap_seed])
def test_table_builder_rejects_inexact_oracle_coverage(mutation) -> None:
    with pytest.raises(SecAwareError):
        _build_with_mutated_oracles(mutation)
```

Add tests that inspect module imports/AST and reject generated-code schemas, AST helpers, Oracle
finding messages, code text, raw prompts, arm/target diagnostics, graph shadow, and model ID as a
table variable. Cover PRESENT/ABSENT codes, pre-outcome UNRESOLVED exclusion, NOT_APPLICABLE scope
exclusion, duplicate discover prompts for one `task_id`, security unknown mapped to primary zero,
missing producers as stage errors, and deterministic row/variable ordering.

Add Oracle contract tests proving that a completed parse failure can produce a legal typed UNKNOWN,
while a parseable no-finding result remains SECURE and analyzer absence/error can never become UNKNOWN.

- [ ] **Step 2: Run table tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_causal_table_builder.py tests/test_causal_provenance_boundary.py tests/test_oracle_schema_v1.py tests/test_oracle_engine.py
```

Expected: FAIL because the causal table layer does not exist.

- [ ] **Step 3: Implement the finite variable catalog**

```python
@dataclass(frozen=True, slots=True)
class VariableDeclaration:
    variable_id: str
    role: VariableRole
    states: tuple[str, ...]
    query_id: str
    applicable_cwes: tuple[str, ...]
    tier: int
    adjacency_type: str


PRIMARY_OUTCOME = VariableDeclaration(
    variable_id="y.secure_functional",
    role=VariableRole.Y,
    states=("no_success", "success"),
    query_id="outcome.secure_functional_v1",
    applicable_cwes=("*",),
    tier=2,
    adjacency_type="outcome",
)

CWE_SECURITY_OUTCOME = VariableDeclaration(
    variable_id="y.cwe_security",
    role=VariableRole.Y,
    states=("secure", "insecure", "unknown"),
    query_id="outcome.cwe_security_v1",
    applicable_cwes=("*",),
    tier=2,
    adjacency_type="outcome",
)
```

Generate `X` declarations only from immutable intervenable Prompt feature specs and reviewed motif
queries. `W` declarations are finite pre-treatment task metadata queries and are included only when
configured for the scope. Include both the primary binary outcome and the finite CWE-specific
categorical outcome; parse/functional/evaluability variables are optional finite declarations, never
inferred from finding text. Do not generate variables dynamically from arbitrary graph nodes.

- [ ] **Step 4: Add typed Oracle UNKNOWN/evaluability and exact table assembly**

Bump observed `OracleRecord` to schema 1.1 and add:

```python
class OracleEvaluability(str, Enum):
    EVALUABLE = "evaluable"
    UNKNOWN_PARSE_FAILURE = "unknown_parse_failure"
```

Require SECURE/INSECURE to be `EVALUABLE`. Permit UNKNOWN only when parsing failed, functional success
is false, both locked analyzers completed, severity is `none`, and findings are empty. The aggregator
emits that record only for this completed parse-failure path; missing analyzer executables, nonzero
tool failures outside the locked parse-failure mapping, malformed output, and missing provenance remain
hard infrastructure failures. Migrate valid schema-1.0 observed records to 1.1 during readback.

```python
def secure_functional_value(oracle: OracleRecord) -> int:
    return int(
        oracle.parse_ok
        and oracle.functional_ok
        and oracle.security_label is SecurityLabel.SECURE
    )


def build_local_tables(
    prompts: Sequence[PromptRecord],
    prompt_tsgs: Sequence[PromptTSGRecord],
    oracles: Sequence[OracleRecord],
    declarations: Sequence[VariableDeclaration],
) -> tuple[
    tuple[CausalTableRecord, ...],
    tuple[CausalObservationRecord, ...],
    tuple[CausalExclusionRecord, ...],
]:
    prompt_by_id = require_unique_prompt_coordinates(prompts, split="discover")
    graph_by_id = require_exact_graph_coverage(prompt_by_id, prompt_tsgs)
    oracle_by_coordinate = require_exact_oracle_coordinates(prompt_by_id, oracles)
    return assemble_scope_model_tables(
        prompt_by_id,
        graph_by_id,
        oracle_by_coordinate,
        tuple(declarations),
    )
```

For each `(scope_id, model_id)`, encode categorical states by their declared tuple index. Exclude
UNRESOLVED/NOT_APPLICABLE rows before requesting the outcome value, emit a typed exclusion, and fail
without publishing when independent task support is below the configured minimum. A missing/corrupt
Oracle producer is never encoded as zero. `table_sha256` covers table coordinates, ordered variable
specs, and the complete sorted `(row_id, task_id, prompt_id, seed_id, values)` observation payload;
changing a row cannot leave the table digest unchanged.

- [ ] **Step 5: Re-run table and provenance tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_causal_table_builder.py tests/test_causal_provenance_boundary.py tests/test_prompt_feature_queries.py tests/test_oracle_schema_v1.py tests/test_oracle_engine.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/causal src/secaware/schema/oracle.py src/secaware/oracle/aggregator.py tests/test_causal_table_builder.py tests/test_causal_provenance_boundary.py tests/test_oracle_schema_v1.py tests/test_oracle_engine.py
git commit -m "feat: assemble prompt-only causal tables"
```

### Task 3: Derive background knowledge and validate every resulting PAG

**Files:**
- Create: `src/secaware/causal/background.py`
- Create: `tests/test_causal_background_knowledge.py`
- Create: `tests/test_pag_background_validation.py`

- [ ] **Step 1: Write failing tier/direction/adjacency tests**

```python
def test_background_knowledge_has_no_required_edges() -> None:
    record = build_background_knowledge(_table())
    assert record.required_directions == ()
    assert record.unconstrained_variable_ids == ()
    assert ("y.secure_functional", "x.safety.path_normalization") in record.forbidden_directions


def test_two_way_forbidden_pair_is_a_typed_adjacency_exclusion() -> None:
    record = build_background_knowledge(_table_with_incompatible_types())
    pair = ("w.language", "x.safety.sql_parameterization")
    assert canonical_pair(*pair) in record.forbidden_adjacencies
    backend = to_causal_learn_background(record)
    assert backend.is_forbidden(GraphNode(pair[0]), GraphNode(pair[1]))
    assert backend.is_forbidden(GraphNode(pair[1]), GraphNode(pair[0]))
```

Add final-PAG mutations for forbidden definite and possible directions, forbidden adjacency,
reversed tiers, unknown variables, missing BK coverage, accidental required X-Y edges, and digest
tampering. Reject overlap between tiered/unconstrained variables and any unconstrained variable whose
role is not `C`.

- [ ] **Step 2: Run BK tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_causal_background_knowledge.py tests/test_pag_background_validation.py
```

Expected: FAIL because background derivation and PAG validation are absent.

- [ ] **Step 3: Implement deterministic TSG-derived BK**

```python
def build_background_knowledge(table: CausalTableRecord) -> BackgroundKnowledgeRecord:
    tiers = tuple((variable.variable_id, variable.temporal_tier) for variable in table.variables)
    forbidden = {
        (later.variable_id, earlier.variable_id)
        for later in table.variables
        for earlier in table.variables
        if later.temporal_tier > earlier.temporal_tier
    }
    adjacencies = typed_adjacency_exclusions(table.variables)
    return BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        tiers=tiers,
        unconstrained_variable_ids=(),
        forbidden_directions=tuple(sorted(forbidden)),
        forbidden_adjacencies=tuple(sorted(adjacencies)),
        required_directions=(),
    )
```

Require `tier variable IDs ∪ unconstrained_variable_ids` to equal the table variable set, with the two
parts disjoint, and allow only variables whose role is `C` to be unconstrained. Observational M4B
knowledge has no unconstrained variables; the explicit escape hatch exists for M6 raw JCI context
only. Build causal-learn `GraphNode` objects using exact `variable_id`
names, add only the listed tiers, add each
one-way prohibition, and add both directions for every forbidden adjacency. Never call
`add_required_by_node`.

- [ ] **Step 4: Implement fail-closed PAG validation**

```python
def pag_permits_direction(edge: PAGEdgeRecord, source: str, target: str) -> bool:
    source_mark, target_mark = edge.marks_from(source, target)
    return source_mark in {EndpointMark.TAIL, EndpointMark.CIRCLE} and target_mark in {
        EndpointMark.ARROW,
        EndpointMark.CIRCLE,
    }


def validate_pag_against_background(
    pag: PAGRecord,
    knowledge: BackgroundKnowledgeRecord,
) -> None:
    edges = {canonical_pair(edge.left, edge.right): edge for edge in pag.edges}
    for left, right in knowledge.forbidden_adjacencies:
        if canonical_pair(left, right) in edges:
            raise background_violation(pag.pag_id)
    for source, target in knowledge.forbidden_directions:
        edge = edges.get(canonical_pair(source, target))
        if edge is not None and pag_permits_direction(edge, source, target):
            raise background_violation(pag.pag_id)
```

Validate the BK digest, exact tier/unconstrained variable partition, and no required edge before
checking endpoints.

- [ ] **Step 5: Re-run BK/PAG validation tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_causal_background_knowledge.py tests/test_pag_background_validation.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/causal/background.py tests/test_causal_background_knowledge.py tests/test_pag_background_validation.py
git commit -m "feat: derive and enforce causal background knowledge"
```

### Task 4: Add the pinned causal-learn FCI/G-square adapter and bounded supervisor

**Files:**
- Create: `src/secaware/causal/pag.py`
- Create: `src/secaware/discovery/causal_learn_backend.py`
- Create: `src/secaware/discovery/fci_supervisor.py`
- Modify: `src/secaware/discovery/__init__.py`
- Create: `tests/test_pag_codec.py`
- Create: `tests/test_causal_learn_fci_backend.py`
- Create: `tests/test_fci_supervisor.py`

- [ ] **Step 1: Write failing adapter, endpoint, and timeout tests**

```python
def test_fci_adapter_calls_exact_gsq_configuration(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr("secaware.discovery.causal_learn_backend.fci", _capturing_fci(calls))
    pag = run_causal_learn_fci(_matrix(), _table(), _knowledge(), _config())
    assert calls[0]["independence_test_method"] == "gsq"
    assert calls[0]["show_progress"] is False
    assert calls[0]["node_names"] == [item.variable_id for item in _table().variables]
    assert pag.run_kind is PAGRunKind.OBSERVATIONAL_REFERENCE


def test_supervisor_terminates_a_hung_worker() -> None:
    started = time.monotonic()
    with pytest.raises(SecAwareError, match="timed out"):
        SpawnedFCIRunner(timeout_seconds=0.1, worker=_never_returns).run(
            _matrix(),
            _table(),
            _knowledge(),
            _config(),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )
    assert time.monotonic() - started < 2.0
```

Add codec tests for all tail/arrow/circle pairs, swapped backend node order, composite/STAR/NULL
endpoint rejection, duplicate edges, library version drift, unexpected warnings/output, child crash,
oversized child payload, and post-run BK violation.

- [ ] **Step 2: Run adapter tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_pag_codec.py tests/test_causal_learn_fci_backend.py tests/test_fci_supervisor.py
```

Expected: FAIL because adapter, codec, and supervisor do not exist.

- [ ] **Step 3: Implement the exact causal-learn call and PAG codec**

```python
CAUSAL_LEARN_VERSION = "0.1.4.7"
_ENDPOINT_MAP = {
    Endpoint.TAIL: EndpointMark.TAIL,
    Endpoint.ARROW: EndpointMark.ARROW,
    Endpoint.CIRCLE: EndpointMark.CIRCLE,
}


def _assert_backend_version() -> None:
    if importlib.metadata.version("causal-learn") != CAUSAL_LEARN_VERSION:
        raise backend_capability_error("causal-learn version mismatch")


def run_causal_learn_fci(
    matrix: np.ndarray,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    *,
    run_kind: PAGRunKind = PAGRunKind.OBSERVATIONAL_REFERENCE,
) -> PAGRecord:
    _assert_backend_version()
    backend_bk = to_causal_learn_background(knowledge)
    graph, _edge_properties = fci(
        np.asarray(matrix, dtype=np.int64),
        independence_test_method="gsq",
        alpha=config.alpha,
        depth=config.depth,
        max_path_length=config.max_path_length,
        verbose=False,
        background_knowledge=backend_bk,
        show_progress=False,
        node_names=[item.variable_id for item in table.variables],
    )
    pag = pag_from_causal_learn(graph, table, knowledge, config, run_kind)
    validate_pag_against_background(pag, knowledge)
    return pag
```

`pag_from_causal_learn` iterates `graph.get_graph_edges()`, maps endpoints through `_ENDPOINT_MAP`,
sorts node names lexicographically while swapping endpoint marks with them, sorts all edges, and
derives `pag_id` from complete canonical content. Never infer an arrow from a circle.

- [ ] **Step 4: Implement spawn supervision**

Expose one backend-neutral boundary used by observational, bootstrap, JCI, and injected test runners:

```python
class FCIRunner(Protocol):
    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        raise NotImplementedError
```

Use `multiprocessing.get_context("spawn")`. Pass only a validated JSON job plus an integer matrix to
a top-level worker. The child returns one canonical `PAGRecord` JSON byte string through a bounded
pipe. The parent joins for `timeout_seconds`, terminates then joins a live child, rejects nonzero exit,
rejects payloads above 4 MiB, revalidates the record, and runs BK validation again. Tests inject the
worker callable; production always selects the real top-level FCI worker.

- [ ] **Step 5: Re-run adapter/supervisor and BK tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_pag_codec.py tests/test_causal_learn_fci_backend.py tests/test_fci_supervisor.py tests/test_pag_background_validation.py
```

Expected: PASS on Windows spawn semantics and on POSIX spawn semantics.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/causal/pag.py src/secaware/discovery/causal_learn_backend.py src/secaware/discovery/fci_supervisor.py src/secaware/discovery/__init__.py tests/test_pag_codec.py tests/test_causal_learn_fci_backend.py tests/test_fci_supervisor.py
git commit -m "feat: add supervised causal-learn fci backend"
```

### Task 5: Add deterministic reference draws and task-cluster bootstrap

**Files:**
- Create: `src/secaware/randomness.py`
- Create: `src/secaware/causal/bootstrap.py`
- Create: `tests/test_deterministic_randomness.py`
- Create: `tests/test_task_cluster_fci_bootstrap.py`

- [ ] **Step 1: Write failing task/seed draw tests**

```python
def test_bootstrap_selects_one_seed_per_sampled_task_occurrence() -> None:
    draw = build_bootstrap_draw(_table(), _rows_three_seeds(), global_seed=7, replicate=3)
    assert len(draw.items) == _table().independent_task_count
    assert [item.draw_index for item in draw.items] == list(range(len(draw.items)))
    assert all(item.row_id in _row_ids_for_task(item.task_id) for item in draw.items)


def test_cluster_bootstrap_differs_from_invalid_row_bootstrap() -> None:
    valid = build_bootstrap_draw(_adversarial_table(), _adversarial_rows(), 11, 0)
    invalid = _row_wise_bootstrap(_adversarial_rows(), 11)
    assert valid.selected_row_ids != invalid
```

Cover duplicate task occurrences, seed choice per occurrence, reference draw one seed per task,
input-order invariance, Python-version independence, exact replicate count, failed replicate counted
in the denominator, timeout failure typing, and bounds on tasks/seeds/replicates.

- [ ] **Step 2: Run randomness/bootstrap tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_deterministic_randomness.py tests/test_task_cluster_fci_bootstrap.py
```

Expected: FAIL because deterministic RNG and cluster bootstrap do not exist.

- [ ] **Step 3: Implement a versioned deterministic RNG**

```python
RNG_VERSION = "sha256-rejection-fisher-yates-v1"


class DeterministicRNG:
    def __init__(self, seed_material: bytes) -> None:
        self._seed = hashlib.sha256(seed_material).digest()
        self._counter = 0

    def randbelow(self, upper: int) -> int:
        if type(upper) is not int or upper <= 0:
            raise ValueError("upper bound must be a positive integer")
        limit = (1 << 256) - ((1 << 256) % upper)
        while True:
            block = hashlib.sha256(self._seed + self._counter.to_bytes(16, "big")).digest()
            self._counter += 1
            value = int.from_bytes(block, "big")
            if value < limit:
                return value % upper

    def choice(self, values: Sequence[T]) -> T:
        if not values:
            raise ValueError("cannot choose from an empty sequence")
        return values[self.randbelow(len(values))]
```

Add `shuffle` using Fisher-Yates from the last index to one. Never use Python's `random` module for
manifested draws.

- [ ] **Step 4: Implement reference and bootstrap draw manifests**

Reference seed material is canonical JSON of `(global_seed, table_id, "reference")`. Bootstrap seed
material adds the replicate index. Sample sorted task IDs with replacement exactly `n_tasks` times;
for each sampled occurrence choose one sorted row/seed belonging to that task. Persist every
`draw_index`, source task, prompt, seed, row ID, RNG version, and draw digest before invoking FCI.

Run each replicate through the supervised adapter. Emit either one bootstrap PAG or one
`BootstrapFailureRecord`; never silently shorten the configured denominator.

- [ ] **Step 5: Re-run bootstrap and adapter tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_deterministic_randomness.py tests/test_task_cluster_fci_bootstrap.py tests/test_fci_supervisor.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/randomness.py src/secaware/causal/bootstrap.py tests/test_deterministic_randomness.py tests/test_task_cluster_fci_bootstrap.py
git commit -m "feat: add task-cluster fci bootstrap"
```

### Task 6: Extract stable possible Prompt-side paths and freeze hypotheses

**Files:**
- Create: `src/secaware/causal/paths.py`
- Create: `src/secaware/causal/freeze.py`
- Modify: `src/secaware/schema/causal.py`
- Create: `tests/test_possible_pag_paths.py`
- Create: `tests/test_hypothesis_freeze.py`

- [ ] **Step 1: Write failing endpoint/path/freeze tests**

```python
def test_possible_path_accepts_circle_uncertainty_but_not_reverse_arrow() -> None:
    assert edge_allows_possible_direction(_edge("x", "z", "circle", "arrow"), "x", "z")
    assert edge_allows_possible_direction(_edge("x", "z", "tail", "circle"), "x", "z")
    assert not edge_allows_possible_direction(_edge("x", "z", "arrow", "tail"), "x", "z")


def test_freeze_rejects_confirmation_artifacts_and_unstable_paths(tmp_path) -> None:
    store = _store_with_committed_confirmation_artifact(tmp_path)
    with pytest.raises(SecAwareError):
        freeze_hypotheses(_reference_pag(), _supports_below_threshold(), _catalog(), store)
```

Cover direct X-Y, Prompt-side X-Z-Y, longer bounded paths, code-like variable rejection, repeated
nodes, path count/hop bounds, exact sequence canonicalization, circle compatibility, tail/arrow
incompatibility, failed-bootstrap zero support, threshold boundary, same forward/reverse target pair,
digest mutation, and JCI/confirm data being unable to mutate frozen hypotheses.

- [ ] **Step 2: Run path/freeze tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_possible_pag_paths.py tests/test_hypothesis_freeze.py
```

Expected: FAIL because path and freeze modules do not exist.

- [ ] **Step 3: Implement endpoint-aware path enumeration and compatibility**

```python
def edge_allows_possible_direction(
    edge: PAGEdgeRecord,
    source: str,
    target: str,
) -> bool:
    source_mark, target_mark = edge.marks_from(source, target)
    return source_mark in {EndpointMark.TAIL, EndpointMark.CIRCLE} and target_mark in {
        EndpointMark.ARROW,
        EndpointMark.CIRCLE,
    }


def endpoint_marks_compatible(reference: EndpointMark, replicate: EndpointMark) -> bool:
    return reference is replicate or EndpointMark.CIRCLE in {reference, replicate}
```

Enumerate simple paths from intervenable catalog-bound `X` variables to pre-registered `Y` variables
with at most `max_path_length` edges and `max_candidate_paths` total paths. `Z`, when present, must be
a `W` or Prompt-side `X` variable. Match bootstrap support by exact variable sequence and the
endpoint compatibility function above. The denominator is the configured bootstrap count; a failure
contributes no supporting path.

- [ ] **Step 4: Implement immutable hypothesis freeze records**

```python
class ExpectedOperationContrast(StrictModel):
    operation: FeatureOperation
    contrast_id: Literal["target_minus_noop"] = "target_minus_noop"
    outcome_estimand_id: str
    expected_sign: Literal["positive", "negative", "null", "two_sided"]


class FrozenHypothesisRecord(VersionedModel):
    schema_version: Literal["1.0"]
    hypothesis_id: str = Field(pattern=r"^hypothesis_[0-9a-f]{64}$")
    hypothesis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_feature_id: str
    feature_family: FeatureFamily
    permitted_operations: tuple[FeatureOperation, ...]
    scope_id: str
    cwe: str
    model_id: str
    outcome_variable_id: str
    reference_pag_id: str = Field(pattern=r"^pag_[0-9a-f]{64}$")
    path: PathPatternRecord
    support_numerator: int = Field(ge=0)
    support_denominator: int = Field(gt=0)
    table_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    extractor_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fci_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    background_knowledge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_contrasts: tuple[ExpectedOperationContrast, ...]
    freeze_batch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen_at_utc: datetime
```

Before writing any record, check that no committed M5/M6 stage manifest exists. Freeze every path
meeting the threshold; do not rank by confirmation data and do not apply an arbitrary top-k. If no
path qualifies, publish the valid PAG/path artifacts and an empty hypothesis artifact with a typed
`NO_STABLE_HYPOTHESIS` failure; the CLI exits nonzero before M5 begins.

`ExpectedOperationContrast` binds one permitted operation to `target_minus_noop`, a versioned
randomized `outcome_estimand_id`, and an expected sign in
`positive | negative | null | two_sided`. The estimand catalog maps a categorical discovery outcome
to an explicit confirmation indicator (for example `y.cwe_security` to `y_cwe_secure`) rather than
silently choosing a level after discovery. Safety ADD is positive and safety REMOVE is
negative for secure-and-functional success; presentation controls are null; any family lacking a
reviewed directional contract is two-sided. The freeze batch digest excludes wall-clock time, while
`frozen_at_utc` is provenance only and cannot change `hypothesis_id`. `hypothesis_sha256` covers the
complete semantic content excluding derived ID and wall-clock fields and must equal the hash encoded
by `hypothesis_id`.

- [ ] **Step 5: Re-run path/freeze tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_possible_pag_paths.py tests/test_hypothesis_freeze.py tests/test_causal_schema.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/causal/paths.py src/secaware/causal/freeze.py src/secaware/schema/causal.py tests/test_possible_pag_paths.py tests/test_hypothesis_freeze.py
git commit -m "feat: freeze stable prompt-side hypotheses"
```

### Task 7: Publish the causal-table and FCI discovery stages and retire heuristic discovery

**Files:**
- Create: `src/secaware/pipeline/stages/causal_tables.py`
- Create: `src/secaware/pipeline/stages/fci_discovery.py`
- Modify: `src/secaware/pipeline/stages/__init__.py`
- Modify: `src/secaware/discovery/__init__.py`
- Modify: `src/secaware/io/run_store.py`
- Modify: `src/secaware/cli.py`
- Replace: `tests/test_discovery.py`
- Create: `tests/test_causal_table_stage.py`
- Create: `tests/test_fci_discovery_stage.py`
- Modify: `tests/test_stage_orchestration.py`
- Modify: `tests/test_run_all_demo.py`

- [ ] **Step 1: Write failing stage/artifact/retirement tests**

```python
def test_discover_command_publishes_complete_causal_artifact_set(tmp_path) -> None:
    config, store = _run_through_observed_oracle(tmp_path)
    assemble_causal_tables_stage(config, store, force=False)
    fci_discovery_stage(config, store, force=False, runner=DeterministicFakeFCIRunner())
    expected = {
        "causal_tables.jsonl",
        "causal_observations.jsonl",
        "causal_exclusions.jsonl",
        "background_knowledge.jsonl",
        "reference_pags.jsonl",
        "bootstrap_draws.jsonl",
        "bootstrap_pags.jsonl",
        "bootstrap_failures.jsonl",
        "path_support.jsonl",
        "hypotheses_frozen.jsonl",
        "discovery_failures.jsonl",
    }
    assert expected <= {path.name for path in store.path("discovery").iterdir()}


def test_heuristic_discovery_is_not_cli_reachable() -> None:
    cli_source = Path("src/secaware/cli.py").read_text(encoding="utf-8")
    assert "discover_hypotheses" not in cli_source
    result = runner.invoke(app, ["--help"])
    assert "tsg-qcd" not in result.stdout.casefold()
```

Add exact producer-lease tests, proposal/graph/oracle mismatch mutations, split contamination,
partial output install, force-run rollback, concurrent dependency replacement, backend timeout,
empty table/hypothesis behavior, committed `NO_STABLE_HYPOTHESIS` followed by a nonzero CLI exit, and
skip invalidation on catalog/extractor/FCI/config/library drift.

- [ ] **Step 2: Run stage tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_causal_table_stage.py tests/test_fci_discovery_stage.py tests/test_stage_orchestration.py tests/test_run_all_demo.py
```

Expected: FAIL because new stages and artifact set are absent.

- [ ] **Step 3: Implement the causal-table stage**

Inputs are committed source prompts, both committed extraction outputs, and committed observed Oracle
records. Hold producer leases in sorted stage-name order. Publish tables, observations, and exclusions
in one `execute_jsonl_stage_transaction` call, then independently read back and re-run exact coverage
validation.

```python
CAUSAL_TABLE_OUTPUTS = (
    ("causal_tables.jsonl", CausalTableRecord),
    ("causal_observations.jsonl", CausalObservationRecord),
    ("causal_exclusions.jsonl", CausalExclusionRecord),
)
```

- [ ] **Step 4: Implement the FCI discovery stage and CLI orchestration**

Read only committed causal-table outputs plus the extraction policy/catalog provenance needed for
freeze records. Build one BK and reference draw per table, run the reference PAG, persist every
bootstrap draw before its PAG/failure result, compute supports, then freeze hypotheses. Publish the
eight discovery outputs atomically, including `discovery_failures.jsonl` even when it is empty.

If no stable hypothesis exists, the stage commits the valid PAG/path artifacts, an empty frozen
hypothesis artifact, and a typed `NO_STABLE_HYPOTHESIS` failure in the same transaction. It returns a
typed terminal status; only after commit/readback does the CLI map that status to a nonzero exit, so
M5 cannot start and the diagnostic artifacts are not rolled back.

Keep `secaware discover` as the user-facing command; it invokes `assemble_causal_tables_stage` then
`fci_discovery_stage`. At the M4B boundary, `run-all` ends after frozen discovery artifacts and prints
`SecAware discovery complete`; M5 extends it with randomized confirmation. Remove the old two-arm
commands from Typer registration so they cannot consume incompatible frozen hypotheses. Keep the
legacy Python modules temporarily for direct regression tests and old report imports; M6 deletes them
after all consumers have migrated. Add every new stage to `RunStore`'s seal-required set and
directory creation.

- [ ] **Step 5: Verify heuristic CLI retirement and re-run focused pipeline tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_causal_table_stage.py tests/test_fci_discovery_stage.py tests/test_causal_table_builder.py tests/test_task_cluster_fci_bootstrap.py tests/test_possible_pag_paths.py tests/test_hypothesis_freeze.py tests/test_stage_orchestration.py tests/test_run_all_demo.py
```

Expected: PASS and no CLI/stage import references to heuristic discovery.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/pipeline/stages src/secaware/io/run_store.py src/secaware/cli.py src/secaware/discovery/__init__.py tests/test_discovery.py tests/test_causal_table_stage.py tests/test_fci_discovery_stage.py tests/test_stage_orchestration.py tests/test_run_all_demo.py
git commit -m "feat: replace heuristic discovery with fci pipeline"
```

### Task 8: Synthetic SCM gates, documentation, and M4B verification

**Files:**
- Create: `tests/synthetic/__init__.py`
- Create: `tests/synthetic/scm_fixtures.py`
- Create: `tests/test_synthetic_fci_scm.py`
- Create: `tests/test_m4b_architecture.py`
- Modify: `README.md`
- Create: `docs/migrations/fci-discovery.md`

- [ ] **Step 1: Add deterministic discrete SCM fixtures**

Use seeded NumPy generators and fixed category domains:

```python
def true_chain_scm(n: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 2, size=n)
    z = np.bitwise_xor(x, rng.binomial(1, 0.10, size=n))
    y = np.bitwise_xor(z, rng.binomial(1, 0.10, size=n))
    return pd.DataFrame({"x.feature": x, "x.prompt_motif": z, "y.secure_functional": y})


def latent_confounding_scm(n: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    u = rng.integers(0, 2, size=n)
    x = np.bitwise_xor(u, rng.binomial(1, 0.10, size=n))
    y = np.bitwise_xor(u, rng.binomial(1, 0.10, size=n))
    return pd.DataFrame({"x.feature": x, "y.secure_functional": y})


def null_factor_scm(n: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    return pd.DataFrame(
        {
            "x.null": rng.integers(0, 2, size=n),
            "y.secure_functional": rng.integers(0, 2, size=n),
        }
    )
```

- [ ] **Step 2: Add real-backend acceptance assertions**

For the true chain, assert a possible X-Z-Y path is recovered and survives the configured small
bootstrap threshold. For latent confounding, assert the adapter preserves non-definite PAG endpoint
marks rather than forcing a DAG. For the null factor, assert no stable hypothesis is frozen. Run each
fixture twice and require identical canonical artifacts. Use sufficient fixed sample sizes and do not
assert a stronger unique orientation than FCI identifies.

- [ ] **Step 3: Add static Prompt-only and minimum-runtime gates**

```python
def test_causal_package_cannot_import_code_side_or_confirmation_modules() -> None:
    forbidden = {"schema.records.GeneratedCodeRecord", "python_ast_utils", "intervention", "jci"}
    imports = imported_symbols_under(Path("src/secaware/causal"))
    assert imports.isdisjoint(forbidden)


def test_minimum_discovery_has_no_java_dependency() -> None:
    metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    dependencies = "\n".join(metadata["project"]["dependencies"]).casefold()
    assert "jpype" not in dependencies
    assert "py-tetrad" not in dependencies
```

- [ ] **Step 4: Document artifacts, assumptions, and migration**

Document causal-learn 0.1.4.7, G-square, tier semantics, two-way adjacency exclusion, final BK
validation, one-seed task bootstrap, path compatibility, failed-replicate denominator, no required
candidate edges, no Code TSG, and the replacement of `hypotheses_all/selected` with frozen FCI
hypotheses.

- [ ] **Step 5: Run focused and full M4B gates**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_synthetic_fci_scm.py tests/test_causal_schema.py tests/test_causal_table_builder.py tests/test_causal_background_knowledge.py tests/test_pag_codec.py tests/test_causal_learn_fci_backend.py tests/test_fci_supervisor.py tests/test_task_cluster_fci_bootstrap.py tests/test_possible_pag_paths.py tests/test_hypothesis_freeze.py tests/test_causal_table_stage.py tests/test_fci_discovery_stage.py tests/test_m4b_architecture.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m secaware discover --help
git diff --check
if (Test-Path uv.lock) { throw 'uv.lock must not exist' }
```

Expected: all commands exit zero; real causal-learn synthetic tests pass without Java.

- [ ] **Step 6: Commit**

```powershell
git add tests/synthetic tests/test_synthetic_fci_scm.py tests/test_m4b_architecture.py README.md docs/migrations/fci-discovery.md
git commit -m "test: gate prompt-only fci discovery"
```

## M4B self-review checklist

- Local tables are split by scope and model; `model_id` is not a minimum causal variable.
- Table construction reads Prompt TSG queries and committed outcomes, never code structure or finding
  text.
- BK contains no required candidate/path edges and is checked after every FCI run.
- Every reference/bootstrap matrix has exactly one seed row per task occurrence.
- Stable paths preserve circle uncertainty and contain Prompt-side variables only.
- Frozen hypotheses predate and cannot be changed by M5/M6 artifacts.
- causal-learn is the required no-Java backend; RFCI remains absent until M6.
