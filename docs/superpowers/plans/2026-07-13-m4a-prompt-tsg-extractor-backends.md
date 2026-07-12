# M4A Prompt TSG 2.1 and Extractor Backends Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade Prompt TSG to a catalog-bound feature graph and implement the three run-locked extraction backends, with `LLM_FACTS_V1` as the default and no benchmark or fallback logic.

**Architecture:** Every backend emits one strict `PromptExtractionProposalRecord`; deterministic validation and construction then produce the same canonical Prompt TSG 2.1 record. LLM backends are blind to arm, target, outcome, code, and Oracle data, while the current finite matcher becomes the explicit `DETERMINISTIC_CATALOG_V1` backend.

**Tech Stack:** Python 3.10+, Pydantic 2, NetworkX 3, OpenAI-compatible chat-completions transport, Typer, existing RunStore transactions, pytest, Ruff.

---

## File responsibility map

- `src/secaware/schema/features.py`: feature-family, operation, state, and graph-query enums.
- `src/secaware/schema/prompt_extraction.py`: strict proposal, evidence, policy, and attempt records.
- `src/secaware/schema/tsg.py`: Prompt TSG 2.1 graph record and feature-state node attributes.
- `src/secaware/schema/records.py`: required stable `task_id` on source prompts.
- `src/secaware/tsg/feature_catalog.py`: immutable `FeatureSpec` catalog and digest.
- `src/secaware/tsg/builder.py`: semantic facts/direct graph proposals to canonical graph.
- `src/secaware/tsg/proposal_validator.py`: shared evidence/catalog/type validation.
- `src/secaware/tsg/queries.py`: graph-authoritative feature-state and projection queries.
- `src/secaware/extractors/base.py`: backend protocol and extraction context.
- `src/secaware/extractors/deterministic_catalog.py`: current finite matcher as backend C.
- `src/secaware/extractors/llm_facts.py`: backend A, structured facts only.
- `src/secaware/extractors/llm_direct_graph.py`: backend B, typed nodes/edges only.
- `src/secaware/extractors/factory.py`: finite backend selection with no fallback.
- `src/secaware/llm/structured_transport.py`: locked one-response JSON transport shared later by M5.
- `src/secaware/pipeline/jsonl_stage.py`: reusable transactional JSONL-stage boundary extracted from CLI.
- `src/secaware/pipeline/stages/prompt_extraction.py`: proposal plus graph stage orchestration.
- `src/secaware/cli.py`: thin `extract-prompt-tsg` delegation.

### Task 1: Extract the reusable transactional JSONL stage boundary

**Files:**
- Create: `src/secaware/pipeline/jsonl_stage.py`
- Modify: `src/secaware/cli.py`
- Create: `tests/test_jsonl_stage_transaction.py`
- Modify: `tests/test_stage_orchestration.py`

- [ ] **Step 1: Write failing extraction and rollback tests**

Add tests that require a public output specification and prove byte-for-byte rollback:

```python
def test_jsonl_stage_restores_all_outputs_when_second_install_fails(tmp_path, monkeypatch):
    store = _prepared_store(tmp_path)
    one = store.path("tsg", "one.jsonl")
    two = store.path("tsg", "two.jsonl")
    one.write_bytes(b'{"old":1}\n')
    two.write_bytes(b'{"old":2}\n')
    monkeypatch.setattr(ArtifactTransaction, "install", _fail_on_second_install)

    with pytest.raises(SecAwareError):
        execute_jsonl_stage_transaction(
            store,
            stage="transaction-test",
            inputs=(store.path("inputs", "prompts.jsonl"),),
            outputs=(
                JsonlOutputSpec(one, ProbeRecord, require_nonempty=True),
                JsonlOutputSpec(two, ProbeRecord, require_nonempty=True),
            ),
            force=True,
            build=lambda: ((ProbeRecord(value=10),), (ProbeRecord(value=20),)),
        )

    assert one.read_bytes() == b'{"old":1}\n'
    assert two.read_bytes() == b'{"old":2}\n'
```

Also assert that `cli.py` no longer defines `_execute_jsonl_stage_transaction`, every candidate is
read back through its declared model, output count must equal record-group count, interrupts restore
the prior commit, and manifest commit occurs only after output sealing.

- [ ] **Step 2: Run the focused tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_jsonl_stage_transaction.py tests/test_stage_orchestration.py
```

Expected: FAIL because `secaware.pipeline.jsonl_stage` and `JsonlOutputSpec` do not exist.

- [ ] **Step 3: Move the existing transaction logic behind a focused API**

Create the public contract below and move the current CLI transaction body without changing its
lease, candidate, seal, readback, manifest, rollback, or interrupt order:

```python
@dataclass(frozen=True, slots=True)
class JsonlOutputSpec:
    path: Path
    model: type[BaseModel] | None
    require_nonempty: bool = False
    max_records: int = 100_000
    max_line_chars: int = 4_000_000
    max_total_chars: int = 256_000_000


BuildRecords = Callable[[], Sequence[Sequence[BaseModel | dict[str, object]]]]


def execute_jsonl_stage_transaction(
    store: RunStore,
    *,
    stage: str,
    inputs: Sequence[Path],
    outputs: Sequence[JsonlOutputSpec],
    force: bool,
    build: BuildRecords,
    catalog_sha256: str | None = None,
) -> None:
    if not outputs:
        raise SecAwareError(
            code=ErrorCode.CONTRACT,
            stage=stage,
            message="stage output transaction is invalid",
        )
    _execute_transaction_body(
        store=store,
        stage=stage,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        force=force,
        build=build,
        catalog_sha256=catalog_sha256,
    )
```

Keep `_execute_transaction_body` private in the new module. Replace existing CLI calls with
`JsonlOutputSpec` tuples and remove the duplicated helper from `cli.py`.

- [ ] **Step 4: Re-run transaction and existing orchestration tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_jsonl_stage_transaction.py tests/test_stage_orchestration.py tests/test_prompt_tsg_pipeline.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/secaware/pipeline/jsonl_stage.py src/secaware/cli.py tests/test_jsonl_stage_transaction.py tests/test_stage_orchestration.py
git commit -m "refactor: extract transactional jsonl stage runner"
```

### Task 2: Add task identity, feature enums, Prompt TSG 2.1, and the finite catalog

**Files:**
- Create: `src/secaware/schema/features.py`
- Modify: `src/secaware/schema/records.py`
- Modify: `src/secaware/schema/tsg.py`
- Modify: `src/secaware/schema/__init__.py`
- Create: `src/secaware/tsg/feature_catalog.py`
- Modify: `src/secaware/tsg/catalog.py`
- Modify: `src/secaware/tsg/graph.py`
- Modify: `src/secaware/tsg/motifs.py`
- Create: `tests/test_prompt_feature_catalog.py`
- Modify: `tests/test_prompt_tsg_catalog.py`
- Modify: `tests/test_tsg_schema_v2.py`
- Modify: `tests/test_tsg_motifs.py`
- Modify: `tests/test_tsg_shadow.py`
- Modify: `tests/test_schema.py`
- Modify: `tests/test_artifact_store.py`
- Modify: `tests/test_discovery_graph_scoring.py`
- Modify: `tests/test_discovery.py`
- Modify: `tests/test_generation_cli.py`
- Modify: `tests/test_generation_planner.py`
- Modify: `tests/test_generation_schema_v11.py`
- Modify: `tests/test_intervention_graph_validation.py`
- Modify: `tests/test_intervention.py`
- Modify: `tests/test_openai_compatible_provider.py`
- Modify: `tests/test_oracle_cli.py`
- Modify: `tests/test_preflight.py`
- Modify: `tests/test_prompt_tsg_extractor.py`
- Modify: `tests/test_provider_generation_cli.py`
- Modify: `tests/test_stage_orchestration.py`
- Modify: `data/examples/prompts_demo.jsonl`

- [ ] **Step 1: Write failing feature/catalog/schema tests**

```python
def test_prompt_tsg_21_binds_task_backend_and_feature_states() -> None:
    record = PromptTSGRecord.model_validate(_minimal_prompt_tsg_21())
    assert record.schema_version == "2.1"
    assert record.task_id == "task-path-001"
    assert record.extractor_backend is PromptExtractorBackend.LLM_FACTS_V1
    graph = record_to_multidigraph(record)
    assert feature_state(graph, "safety.path_normalization") is FeatureState.PRESENT


def test_catalog_has_three_families_and_no_runtime_registration() -> None:
    assert {item.feature_family for item in PROMPT_FEATURE_CATALOG} == set(FeatureFamily)
    assert prompt_feature_spec("safety.path_normalization").operations == (
        FeatureOperation.ADD,
        FeatureOperation.REMOVE,
    )
    with pytest.raises(KeyError):
        prompt_feature_spec("runtime.injected_feature")
```

Add rejection tests for missing/blank `task_id`, duplicate feature IDs, invalid family prefixes,
unknown feature-state node attributes, more than one state node for one feature, a PRESENT state
whose required structural node is absent, and forbidden catalog fields named `secure`, `insecure`,
`outcome`, `oracle`, or `code`.

- [ ] **Step 2: Run the schema tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_schema.py tests/test_tsg_schema_v2.py tests/test_prompt_feature_catalog.py tests/test_prompt_tsg_catalog.py tests/test_tsg_motifs.py tests/test_tsg_shadow.py
```

Expected: FAIL because Prompt TSG 2.1, `task_id`, and feature contracts do not exist.

- [ ] **Step 3: Implement exact enums and immutable catalog entries**

Create these enums:

```python
class FeatureFamily(str, Enum):
    TASK_FUNCTION = "task_function"
    SAFETY_CONTROL = "safety_control"
    PRESENTATION_CONTROL = "presentation_control"


class FeatureOperation(str, Enum):
    ADD = "add"
    REMOVE = "remove"


class FeatureState(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    NOT_APPLICABLE = "not_applicable"
    UNRESOLVED = "unresolved"


class PromptExtractorBackend(str, Enum):
    LLM_FACTS_V1 = "llm_facts_v1"
    LLM_DIRECT_GRAPH_V1 = "llm_direct_graph_v1"
    DETERMINISTIC_CATALOG_V1 = "deterministic_catalog_v1"
```

Add `task_id: str` to `PromptRecord`. Upgrade `PromptTSGRecord` to schema 2.1 with required
`task_id`, `task_family`, `cwe`, `extractor_backend`, `extractor_policy_sha256`, and `proposal_id`.
Add `NodeType.FEATURE` and `NodeType.PRESENTATION_FEATURE`; allow only finite `feature_id`,
`feature_family`, and `feature_state` attributes on feature nodes.

Implement the immutable entry shape:

```python
@dataclass(frozen=True, slots=True)
class FeatureSpec:
    feature_id: str
    feature_family: FeatureFamily
    applicable_cwes: tuple[str, ...]
    applicable_task_families: tuple[str, ...]
    intervenable: bool
    operations: tuple[FeatureOperation, ...]
    structural_node_types: tuple[NodeType, ...]
    structural_edge_types: tuple[EdgeType, ...]
    deterministic_terms: tuple[str, ...]
```

The initial catalog must contain these exact IDs:

```text
task.input_consumption
task.file_read
task.database_query
task.process_launch
task.privileged_action
task.object_deserialization
safety.input_validation
safety.path_normalization
safety.sql_parameterization
safety.safe_subprocess
safety.authorization_check
safety.safe_deserialization
safety.generic_security_reminder
safety.prohibited_unsafe_request
safety.vulnerability_disclosure
safety.expected_outcome_leakage
presentation.noop_rewrite
presentation.length_matched_placebo
presentation.sham_edit
presentation.matched_control
```

The last three safety IDs are non-intervenable protocol-sentinel features. Validate the catalog at
import, compute `PROMPT_FEATURE_CATALOG_SHA256` from canonical JSON, and make the existing
`PROMPT_TSG_CATALOG_SHA256` a compatibility alias to the new digest.

- [ ] **Step 4: Update demo/task fixtures and re-run schema tests**

Add an explicit `task_id` to every demo JSONL row and every `PromptRecord` test helper. Source prompt
IDs remain unique; generated variants introduced by M5 will reuse the source `task_id`.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_schema.py tests/test_tsg_schema_v2.py tests/test_prompt_feature_catalog.py tests/test_prompt_tsg_catalog.py tests/test_tsg_graph.py tests/test_tsg_motifs.py tests/test_tsg_shadow.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/secaware/schema/features.py src/secaware/schema/records.py src/secaware/schema/tsg.py src/secaware/schema/__init__.py src/secaware/tsg/feature_catalog.py src/secaware/tsg/catalog.py src/secaware/tsg/graph.py src/secaware/tsg/motifs.py tests data/examples/prompts_demo.jsonl
git commit -m "feat: add prompt feature catalog and tsg 2.1"
```

### Task 3: Add strict proposal contracts, shared validation, builder, and graph queries

**Files:**
- Create: `src/secaware/schema/prompt_extraction.py`
- Create: `src/secaware/tsg/proposal_validator.py`
- Create: `src/secaware/tsg/builder.py`
- Create: `src/secaware/tsg/queries.py`
- Modify: `src/secaware/tsg/features.py`
- Modify: `src/secaware/tsg/__init__.py`
- Create: `tests/test_prompt_extraction_contract.py`
- Create: `tests/test_prompt_tsg_builder.py`
- Create: `tests/test_prompt_feature_queries.py`

- [ ] **Step 1: Write failing proposal and builder tests**

```python
def test_fact_proposal_builds_canonical_graph_independent_of_fact_order() -> None:
    one = validate_and_build(_facts_proposal(order="forward"), _prompt())
    two = validate_and_build(_facts_proposal(order="reverse"), _prompt())
    assert one.graph_sha256 == two.graph_sha256
    assert one.model_dump_json() == two.model_dump_json()


def test_proposal_rejects_fabricated_evidence_and_forbidden_fields() -> None:
    payload = _facts_proposal().model_dump(mode="json")
    payload["facts"][0]["evidence"]["text"] = "not in the prompt"
    payload["expected_outcome"] = "secure"
    with pytest.raises((ValidationError, SecAwareError)):
        PromptExtractionProposalRecord.model_validate(payload)
```

Cover exact UTF-8 character offsets, evidence SHA-256, prompt SHA mismatch, duplicate/conflicting
facts, direct-edge dangling aliases, unknown catalog IDs, illegal family/type combinations, mixed
fact/direct-graph payloads, more than one semantic candidate, oversized response, and graph
round-trip equality.

- [ ] **Step 2: Run the contract tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_prompt_extraction_contract.py tests/test_prompt_tsg_builder.py tests/test_prompt_feature_queries.py
```

Expected: FAIL because proposal and builder modules do not exist.

- [ ] **Step 3: Implement strict immutable records**

Use this persisted shape:

```python
class EvidenceSpan(StrictModel):
    start: int = Field(ge=0, le=2**31 - 1)
    end: int = Field(gt=0, le=2**31 - 1)
    text: str = Field(min_length=1, max_length=4096, repr=False)
    text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)


class SemanticFact(StrictModel):
    feature_id: str
    state: FeatureState
    semantic_role: str
    evidence: tuple[EvidenceSpan, ...]
    relation_feature_ids: tuple[str, ...] = ()


class DirectNodeProposal(StrictModel):
    local_id: str = Field(pattern=r"^v[0-9]{1,4}$")
    node_type: NodeType
    label: str
    feature_id: str
    evidence: tuple[EvidenceSpan, ...]


class DirectEdgeProposal(StrictModel):
    src_local_id: str = Field(pattern=r"^v[0-9]{1,4}$")
    dst_local_id: str = Field(pattern=r"^v[0-9]{1,4}$")
    edge_type: EdgeType
    evidence: tuple[EvidenceSpan, ...]


class PromptExtractionProposalRecord(VersionedModel):
    schema_version: Literal["1.0"]
    proposal_id: str = Field(pattern=r"^proposal_[0-9a-f]{64}$")
    prompt_id: str
    task_id: str
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    backend: PromptExtractorBackend
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_response: str | None = Field(default=None, max_length=262_144, repr=False)
    facts: tuple[SemanticFact, ...] = ()
    direct_nodes: tuple[DirectNodeProposal, ...] = ()
    direct_edges: tuple[DirectEdgeProposal, ...] = ()
```

The model validator enforces facts-only payloads for `LLM_FACTS_V1` and
`DETERMINISTIC_CATALOG_V1`, graph-only payloads for `LLM_DIRECT_GRAPH_V1`, canonical ordering,
catalog closure, exact response hash, and a digest-derived `proposal_id`.

- [ ] **Step 4: Implement validation, deterministic construction, and feature queries**

Expose these exact boundaries:

```python
def validate_proposal(
    proposal: PromptExtractionProposalRecord,
    prompt: PromptRecord,
) -> PromptExtractionProposalRecord:
    snapshot = PromptExtractionProposalRecord.model_validate(
        proposal.model_dump(mode="python", round_trip=True, warnings=False)
    )
    validate_prompt_binding(snapshot, prompt)
    validate_evidence_spans(snapshot, prompt.prompt)
    validate_catalog_closure(snapshot)
    return snapshot


def build_prompt_tsg(
    proposal: PromptExtractionProposalRecord,
    prompt: PromptRecord,
) -> PromptTSGRecord:
    trusted = validate_proposal(proposal, prompt)
    graph = build_structural_graph(trusted, prompt)
    add_complete_feature_state_nodes(graph, trusted, prompt)
    validate_feature_state_consistency(graph, prompt)
    return multidigraph_to_record(
        graph,
        prompt_id=prompt.prompt_id,
        task_id=prompt.task_id,
        task_family=prompt.task_family,
        cwe=prompt.cwe,
        extractor_backend=trusted.backend,
        extractor_policy_sha256=trusted.policy_sha256,
        proposal_id=trusted.proposal_id,
    )


def feature_state(graph: nx.MultiDiGraph, feature_id: str) -> FeatureState:
    nodes = feature_state_nodes(graph, feature_id)
    if len(nodes) != 1:
        raise _query_contract_error(feature_id)
    return FeatureState(nodes[0]["attributes"]["feature_state"])
```

`derive_shadow` may retain counts and catalog feature states for audit, but all consumers must call
`feature_state` or projection queries on the live graph.

- [ ] **Step 5: Re-run proposal, builder, query, graph, and shadow tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_prompt_extraction_contract.py tests/test_prompt_tsg_builder.py tests/test_prompt_feature_queries.py tests/test_tsg_graph.py tests/test_tsg_shadow.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/schema/prompt_extraction.py src/secaware/tsg/proposal_validator.py src/secaware/tsg/builder.py src/secaware/tsg/queries.py src/secaware/tsg/features.py src/secaware/tsg/__init__.py tests/test_prompt_extraction_contract.py tests/test_prompt_tsg_builder.py tests/test_prompt_feature_queries.py
git commit -m "feat: add canonical prompt extraction boundary"
```

### Task 4: Migrate the current matcher into `DETERMINISTIC_CATALOG_V1`

**Files:**
- Create: `src/secaware/extractors/base.py`
- Create: `src/secaware/extractors/deterministic_catalog.py`
- Modify: `src/secaware/extractors/prompt_tsg_extractor.py`
- Modify: `src/secaware/extractors/__init__.py`
- Modify: `tests/test_prompt_tsg_extractor.py`
- Create: `tests/test_deterministic_catalog_backend.py`

- [ ] **Step 1: Write failing backend-contract tests**

```python
def test_deterministic_backend_returns_facts_not_graph_or_outcome() -> None:
    proposal = DeterministicCatalogExtractor().extract(_path_prompt(), _policy())
    assert proposal.backend is PromptExtractorBackend.DETERMINISTIC_CATALOG_V1
    assert proposal.facts
    assert proposal.direct_nodes == ()
    assert proposal.direct_edges == ()
    assert "secure" not in proposal.model_dump_json().casefold()


def test_deterministic_backend_is_order_and_locale_independent() -> None:
    first = DeterministicCatalogExtractor().extract(_sql_prompt(), _policy())
    second = DeterministicCatalogExtractor().extract(_sql_prompt(), _policy())
    assert first.model_dump_json() == second.model_dump_json()
```

Retain mutation tests for each existing CWE phrase, overlapping evidence, case folding, term
boundaries, unresolved applicability, injected non-string fields, and sanitized error surfaces.

- [ ] **Step 2: Run deterministic backend tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_deterministic_catalog_backend.py tests/test_prompt_tsg_extractor.py
```

Expected: FAIL because the explicit backend class and protocol do not exist.

- [ ] **Step 3: Implement the backend protocol and migrate the matcher**

```python
@dataclass(frozen=True, slots=True)
class ExtractionPolicy:
    backend: PromptExtractorBackend
    policy_sha256: str
    catalog_sha256: str
    max_response_chars: int


class PromptExtractor(Protocol):
    def extract(
        self,
        prompt: PromptRecord,
        policy: ExtractionPolicy,
    ) -> PromptExtractionProposalRecord:
        raise NotImplementedError
```

The protocol method body is never called; concrete classes implement it. Move the term/evidence
logic from `prompt_tsg_extractor.py` into `DeterministicCatalogExtractor.extract`. Produce one state
fact for every catalog feature: PRESENT/ABSENT for applicable resolved entries, NOT_APPLICABLE for
out-of-scope entries, and UNRESOLVED when the finite backend cannot satisfy the evidence contract.
Build `raw_response` from the canonical JSON facts payload so deterministic and LLM proposals share
the same response-hash semantics.

Keep `extract_prompt_tsg(prompt)` temporarily as a compatibility wrapper that explicitly constructs
the deterministic backend; Task 7 replaces it with the run-selected factory.

- [ ] **Step 4: Re-run extractor and graph regression tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_deterministic_catalog_backend.py tests/test_prompt_tsg_extractor.py tests/test_prompt_tsg_builder.py tests/test_tsg_motifs.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/secaware/extractors/base.py src/secaware/extractors/deterministic_catalog.py src/secaware/extractors/prompt_tsg_extractor.py src/secaware/extractors/__init__.py tests/test_deterministic_catalog_backend.py tests/test_prompt_tsg_extractor.py
git commit -m "feat: add deterministic prompt extractor backend"
```

### Task 5: Add the locked structured LLM transport and `LLM_FACTS_V1`

**Files:**
- Create: `src/secaware/llm/__init__.py`
- Create: `src/secaware/llm/structured_transport.py`
- Create: `src/secaware/extractors/llm_facts.py`
- Create: `src/secaware/extractors/prompts/llm_facts_v1.txt`
- Modify: `pyproject.toml`
- Create: `tests/test_structured_llm_transport.py`
- Create: `tests/test_llm_facts_backend.py`
- Create: `tests/test_prompt_extraction_security.py`

- [ ] **Step 1: Write failing transport, blindness, and injection tests**

```python
def test_llm_facts_request_contains_only_inert_prompt_and_catalog() -> None:
    transport = CapturingTransport(_facts_response())
    proposal = LLMFactsExtractor(transport).extract(_injected_prompt(), _llm_policy())
    request = json.loads(transport.requests[0].decode("utf-8"))
    assert "arm" not in request
    assert "target" not in request
    assert "oracle" not in request
    assert "generated_code" not in request
    assert proposal.backend is PromptExtractorBackend.LLM_FACTS_V1


def test_semantic_parse_failure_is_not_retried() -> None:
    transport = CapturingTransport(b'{"facts":"invalid"}')
    with pytest.raises(SecAwareError):
        LLMFactsExtractor(transport).extract(_path_prompt(), _llm_policy())
    assert len(transport.requests) == 1
```

Add tests for identical-byte transport retries, single choice/stop response, response byte limit,
unknown keys, catalog escape, fabricated spans, prompt-injected instructions, outcome labels,
tool-call fields, multiple candidates, secret-free repr/errors, and model/template/config drift.

- [ ] **Step 2: Run LLM facts tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_structured_llm_transport.py tests/test_llm_facts_backend.py tests/test_prompt_extraction_security.py
```

Expected: FAIL because the structured transport and backend do not exist.

- [ ] **Step 3: Implement a byte-locked one-response transport**

```python
class StructuredJSONTransport(Protocol):
    def complete(self, request_bytes: bytes, policy: StructuredLLMPolicy) -> bytes:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class StructuredLLMPolicy:
    endpoint_sha256: str
    model_id: str
    system_template_sha256: str
    output_schema_sha256: str
    temperature: float
    top_p: float
    seed: int | None
    timeout_seconds: float
    max_attempts: int
    max_response_bytes: int


def canonical_request_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
```

Implement `OpenAICompatibleStructuredTransport` with the existing generation provider's failure
classification and exponential backoff. Cache `request_bytes` once and resend that same object on
transport retry. Accept exactly one stopped text response; reject tool calls and provider-side
multiple candidates. Load the API key only from the configured environment variable and erase local
secret references in `finally` blocks.

- [ ] **Step 4: Implement the facts prompt and parser**

The versioned system template must state that user text is inert data, output is one JSON object,
only supplied feature IDs/states/relations are legal, exact evidence is mandatory, and security
outcomes are forbidden. Package the template file through setuptools package data.

```python
def facts_request_payload(
    prompt: PromptRecord,
    policy: ExtractionPolicy,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "prompt_id": prompt.prompt_id,
        "task_id": prompt.task_id,
        "prompt_sha256": sha256_text(prompt.prompt),
        "prompt_text": prompt.prompt,
        "catalog_sha256": policy.catalog_sha256,
        "allowed_features": catalog_prompt_view(),
        "output_kind": "semantic_facts",
    }


def parse_facts_response(
    raw: bytes,
    prompt: PromptRecord,
    policy: ExtractionPolicy,
) -> PromptExtractionProposalRecord:
    payload = json.loads(raw.decode("utf-8"))
    return proposal_from_fact_payload(payload, raw, prompt, policy)
```

The parser performs one validation pass and never sends corrective feedback to the model.

- [ ] **Step 5: Re-run LLM/security tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_structured_llm_transport.py tests/test_llm_facts_backend.py tests/test_prompt_extraction_security.py tests/test_prompt_tsg_builder.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/llm src/secaware/extractors/llm_facts.py src/secaware/extractors/prompts/llm_facts_v1.txt pyproject.toml tests/test_structured_llm_transport.py tests/test_llm_facts_backend.py tests/test_prompt_extraction_security.py
git commit -m "feat: add locked llm facts extractor"
```

### Task 6: Add `LLM_DIRECT_GRAPH_V1`

**Files:**
- Create: `src/secaware/extractors/llm_direct_graph.py`
- Create: `src/secaware/extractors/prompts/llm_direct_graph_v1.txt`
- Create: `tests/test_llm_direct_graph_backend.py`
- Modify: `tests/test_prompt_extraction_security.py`

- [ ] **Step 1: Write failing direct-graph tests**

```python
def test_direct_graph_backend_uses_catalog_aliases_then_canonicalizes() -> None:
    proposal = LLMDirectGraphExtractor(FakeTransport(_graph_response())).extract(
        _path_prompt(),
        _direct_policy(),
    )
    record = build_prompt_tsg(proposal, _path_prompt())
    assert proposal.facts == ()
    assert proposal.direct_nodes
    assert record.nodes == tuple(sorted(record.nodes, key=lambda item: item.node_id))


@pytest.mark.parametrize(
    "mutation",
    [
        _unknown_node_type,
        _unknown_edge_type,
        _dangling_endpoint,
        _duplicate_local_id,
        _illegal_cross_family_edge,
        _outcome_attribute,
    ],
)
def test_direct_graph_rejects_non_catalog_graphs(mutation) -> None:
    with pytest.raises(SecAwareError):
        _extract_mutated_direct_graph(mutation)
```

- [ ] **Step 2: Run direct-graph tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_llm_direct_graph_backend.py tests/test_prompt_extraction_security.py
```

Expected: FAIL because backend B does not exist.

- [ ] **Step 3: Implement direct graph request/parsing through the shared boundary**

```python
def direct_graph_request_payload(
    prompt: PromptRecord,
    policy: ExtractionPolicy,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "prompt_id": prompt.prompt_id,
        "task_id": prompt.task_id,
        "prompt_sha256": sha256_text(prompt.prompt),
        "prompt_text": prompt.prompt,
        "catalog_sha256": policy.catalog_sha256,
        "allowed_node_templates": catalog_node_template_view(),
        "allowed_edge_templates": catalog_edge_template_view(),
        "output_kind": "typed_graph",
    }
```

Use local aliases only in the LLM response. `proposal_validator` resolves aliases, enforces evidence
and type compatibility, and `builder` creates full SHA-256 canonical node/edge IDs. Do not accept
LLM-provided canonical IDs, graph digests, feature identities outside the catalog, shadow values, or
causal edge labels.

- [ ] **Step 4: Re-run both LLM backends and shared builder tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_llm_direct_graph_backend.py tests/test_llm_facts_backend.py tests/test_prompt_extraction_security.py tests/test_prompt_tsg_builder.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/secaware/extractors/llm_direct_graph.py src/secaware/extractors/prompts/llm_direct_graph_v1.txt tests/test_llm_direct_graph_backend.py tests/test_prompt_extraction_security.py
git commit -m "feat: add direct graph llm extractor"
```

### Task 7: Lock backend selection in config and publish proposals plus graphs transactionally

**Files:**
- Create: `src/secaware/extractors/factory.py`
- Create: `src/secaware/pipeline/stages/__init__.py`
- Create: `src/secaware/pipeline/stages/prompt_extraction.py`
- Modify: `src/secaware/config.py`
- Modify: `src/secaware/tsg/contract.py`
- Modify: `src/secaware/io/run_store.py`
- Modify: `src/secaware/cli.py`
- Modify: `configs/demo.yaml`
- Modify: `configs/paper_v0.yaml`
- Create: `tests/test_prompt_extractor_factory.py`
- Modify: `tests/test_prompt_tsg_pipeline.py`
- Modify: `tests/test_config_v1.py`

- [ ] **Step 1: Write failing config/factory/stage tests**

```python
def test_default_backend_is_llm_facts_but_demo_is_explicitly_offline() -> None:
    assert TSGConfig.model_fields["prompt_extractor"].default is PromptExtractorBackend.LLM_FACTS_V1
    demo = load_config("configs/demo.yaml")
    assert demo.tsg.prompt_extractor is PromptExtractorBackend.DETERMINISTIC_CATALOG_V1


def test_stage_commits_exact_proposal_and_graph_coverage(tmp_path) -> None:
    config, store = _demo_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)
    proposals = read_jsonl(store.path("tsg", "prompt_extraction_proposals.jsonl"), PromptExtractionProposalRecord)
    graphs = read_jsonl(store.path("tsg", "prompt_tsg.jsonl"), PromptTSGRecord)
    assert {item.prompt_id for item in proposals} == {item.prompt_id for item in graphs}
    assert {item.proposal_id for item in proposals} == {item.proposal_id for item in graphs}
```

Add tests that reject a missing LLM policy, deterministic config carrying LLM secrets, backend drift,
per-prompt fallback, proposal omission/duplication/extra records, mixed backend records, stale catalog
or template digests, concurrent force-runs, interrupted readback, and a backend exception followed by
an attempted fallback.

- [ ] **Step 2: Run factory/pipeline tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_prompt_extractor_factory.py tests/test_prompt_tsg_pipeline.py tests/test_config_v1.py
```

Expected: FAIL because run-locked selection and the proposal artifact are absent.

- [ ] **Step 3: Implement strict backend-specific config**

```python
class PromptExtractorLLMConfig(StrictModel):
    provider: Literal["openai_compatible"] = "openai_compatible"
    model_id: str = Field(min_length=1, max_length=256)
    base_url: str = Field(min_length=1, max_length=2048, repr=False)
    api_key_env: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", repr=False)
    timeout_seconds: float = Field(gt=0.0, le=3600.0)
    max_attempts: int = Field(ge=1, le=10)
    max_response_bytes: int = Field(ge=1024, le=1_048_576)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    top_p: float = Field(default=1.0, gt=0.0, le=1.0)
    seed: int | None = 0


class TSGConfig(StrictModel):
    prompt_extractor: PromptExtractorBackend = PromptExtractorBackend.LLM_FACTS_V1
    llm: PromptExtractorLLMConfig | None = None
```

The `AppConfig` model validator requires `llm` for either LLM backend and forbids it for the
deterministic backend. Keeping this cross-field check at `AppConfig` lets `TSGConfig` expose the
documented default without inventing provider credentials. `extractor_for_config` uses an exhaustive
dictionary keyed by the enum and never catches a backend failure to choose another backend.

- [ ] **Step 4: Implement the stage and CLI delegation**

```python
def run_prompt_extraction_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
    transport: StructuredJSONTransport | None = None,
) -> None:
    backend = extractor_for_config(config.tsg, transport=transport)
    policy = extraction_policy(config.tsg)

    def build() -> tuple[tuple[PromptExtractionProposalRecord, ...], tuple[PromptTSGRecord, ...]]:
        prompts = tuple(read_source_prompts(store))
        proposals = tuple(backend.extract(prompt, policy) for prompt in prompts)
        graphs = tuple(build_prompt_tsg(proposal, prompt) for proposal, prompt in zip(proposals, prompts, strict=True))
        validate_exact_extraction_coverage(prompts, proposals, graphs, policy)
        return proposals, graphs

    execute_jsonl_stage_transaction(
        store,
        stage="extract-prompt-tsg",
        inputs=(store.path("inputs", "prompts.jsonl"),),
        outputs=(
            JsonlOutputSpec(store.path("tsg", "prompt_extraction_proposals.jsonl"), PromptExtractionProposalRecord, True),
            JsonlOutputSpec(store.path("tsg", "prompt_tsg.jsonl"), PromptTSGRecord, True),
        ),
        force=force,
        build=build,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )
```

Bind backend, model, endpoint identity hash, system-template hash, output-schema hash, catalog hash,
and decoding values into `PROMPT_TSG_STAGE_CONTRACT_SHA256`. Update `RunStore` committed-stage
verification to expect both outputs. Keep the Typer command name `extract-prompt-tsg`.

- [ ] **Step 5: Re-run config, factory, pipeline, and CLI tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_config_v1.py tests/test_prompt_extractor_factory.py tests/test_prompt_tsg_pipeline.py tests/test_stage_orchestration.py tests/test_run_all_demo.py
```

Expected: PASS with demo using only the explicit deterministic backend.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/extractors/factory.py src/secaware/pipeline/stages src/secaware/config.py src/secaware/tsg/contract.py src/secaware/io/run_store.py src/secaware/cli.py configs tests/test_prompt_extractor_factory.py tests/test_prompt_tsg_pipeline.py tests/test_config_v1.py
git commit -m "feat: publish run-locked prompt extraction artifacts"
```

### Task 8: Migration, security gates, and M4A verification

**Files:**
- Delete: `src/secaware/extractors/python_ast_utils.py`
- Modify: `docs/migrations/prompt-tsg-v2.md`
- Modify: `README.md`
- Create: `tests/test_m4a_architecture.py`
- Modify: `tests/test_packaging.py`
- Modify: `tests/test_run_all_demo.py`

- [ ] **Step 1: Write failing migration, architecture, and packaging gates**

```python
def test_m4a_has_no_code_or_outcome_imports_in_prompt_extraction() -> None:
    roots = [Path("src/secaware/tsg"), Path("src/secaware/extractors")]
    forbidden = (
        "code_tsg",
        "python_ast_utils",
        "GeneratedCodeRecord",
        "OracleRecord",
        "security_label",
    )
    text = "\n".join(path.read_text(encoding="utf-8") for root in roots for path in root.glob("*.py"))
    assert not any(token in text for token in forbidden)
    assert not Path("src/secaware/extractors/python_ast_utils.py").exists()


def test_m4a_contains_no_benchmark_or_backend_ranking_surface() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in Path("src/secaware").rglob("*.py"))
    assert "extractor_benchmark" not in source
    assert "backend_ranking" not in source
    assert "select_best_backend" not in source
```

Also assert the packaged wheel contains both extractor prompt templates and that `secaware --help`
has no benchmark command. Add migration-document assertions for Prompt TSG 2.1, regeneration, all
three backend names, no automatic selection, and no fallback.

- [ ] **Step 2: Run the new final gates and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_m4a_architecture.py tests/test_packaging.py tests/test_run_all_demo.py
```

Expected: FAIL because the obsolete AST helper still exists and migration/backend policy docs are
incomplete.

- [ ] **Step 3: Remove the obsolete helper and document the breaking policy**

Delete `python_ast_utils.py`. Document Prompt TSG 2.1, required `task_id`, two extraction outputs,
exact backend selection, LLM environment variables, deterministic demo override, proposal provenance,
and the fact that existing TSG/discovery/intervention/analysis artifacts must be regenerated. State
explicitly that this milestone does not implement a gold corpus, fairness score, ranking, backend
winner, automatic selection, or fallback.

- [ ] **Step 4: Run the focused M4A suite**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_prompt_feature_catalog.py tests/test_prompt_extraction_contract.py tests/test_prompt_tsg_builder.py tests/test_prompt_feature_queries.py tests/test_deterministic_catalog_backend.py tests/test_structured_llm_transport.py tests/test_llm_facts_backend.py tests/test_llm_direct_graph_backend.py tests/test_prompt_extraction_security.py tests/test_prompt_extractor_factory.py tests/test_prompt_tsg_pipeline.py tests/test_m4a_architecture.py
```

Expected: PASS.

- [ ] **Step 5: Run full regression and static gates**

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m secaware --help
git diff --check
if (Test-Path uv.lock) { throw 'uv.lock must not exist' }
```

Expected: all commands exit zero; only explicit capability tests skip.

- [ ] **Step 6: Commit documentation and final gates**

```powershell
git add src/secaware/extractors/python_ast_utils.py docs/migrations/prompt-tsg-v2.md README.md tests/test_m4a_architecture.py tests/test_packaging.py tests/test_run_all_demo.py
git commit -m "docs: complete prompt extractor backend migration"
```

## M4A self-review checklist

- The default enum is `LLM_FACTS_V1`; offline demo explicitly selects `DETERMINISTIC_CATALOG_V1`.
- All backends emit one proposal and use the same validator, builder, graph codec, and query layer.
- LLM request payloads contain no arm, target, expected delta, code, Oracle, or outcome.
- Transport retries replay identical bytes; semantic retries are absent.
- Prompt TSG, not proposal fields or shadow, is the feature authority.
- No benchmark/ranking implementation is introduced.
- M4A finishes with a working `extract-prompt-tsg` command and leaves discovery behavior unchanged
  until M4B.
