# Prompt TSG Graph-First Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace feature-driven Prompt/Code TSG handling with a strict Prompt-only NetworkX `MultiDiGraph` whose graph queries drive motifs, discovery, and intervention validation while the independent Oracle remains the sole security outcome.

**Architecture:** Persist a strict Prompt TSG schema 2.0 as canonical node/edge tuples, reconstruct and validate it as a bounded `MultiDiGraph`, and derive motifs plus a read-only shadow projection from live graph queries. Remove mandatory Code TSG and migrate discovery, intervention, manifests, CLI stages, and run-all to committed Prompt TSG snapshots.

**Tech Stack:** Python 3.10+, Pydantic 2, NetworkX 3, Typer, pytest, existing RunStore manifest/seal/transaction machinery.

---

## File responsibility map

- `src/secaware/schema/tsg.py`: strict immutable Prompt TSG v2, node/edge/motif evidence contracts.
- `src/secaware/tsg/graph.py`: canonical IDs, graph digest, record ↔ `MultiDiGraph` codec.
- `src/secaware/tsg/catalog.py`: finite prompt ontology and combined catalog digest.
- `src/secaware/tsg/motifs.py`: bounded typed motif traversal and factor queries.
- `src/secaware/tsg/features.py`: graph-derived shadow projection only.
- `src/secaware/extractors/prompt_tsg_extractor.py`: prompt evidence → graph facts; no feature decisions.
- `src/secaware/discovery/candidate_enum.py`: typed factor-to-graph-query declarations.
- `src/secaware/discovery/scoring.py`: graph-query association/path/stability scoring.
- `src/secaware/discovery/tsg_qcd.py`: Prompt TSG-only discovery orchestration and evidence.
- `src/secaware/intervention/validator.py`: live graph target/side-effect validation.
- `src/secaware/cli.py`: committed Prompt TSG stage, removal of Code TSG stages and dependencies.
- `src/secaware/pipeline/manifest.py`, `src/secaware/io/run_store.py`: catalog-bound Prompt TSG manifest/skip/consumer verification.

### Task 1: Strict Prompt TSG schema 2.0

**Files:**
- Modify: `src/secaware/schema/tsg.py`
- Modify: `src/secaware/schema/__init__.py`
- Modify: `tests/test_schema.py`
- Create: `tests/test_tsg_schema_v2.py`

- [ ] **Step 1: Write failing strict-schema tests**

Add tests that construct a minimal valid prompt record and reject old or malformed records:

```python
def test_prompt_tsg_v2_is_frozen_and_rejects_code_shape() -> None:
    record = PromptTSGRecord.model_validate(_minimal_prompt_tsg())
    assert record.schema_version == "2.0"
    with pytest.raises((TypeError, ValidationError)):
        record.nodes = ()
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate({**_minimal_prompt_tsg(), "source_type": "code"})


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["nodes"].append(value["nodes"][0]),
        lambda value: value["edges"][0].update(dst="n_" + "f" * 64),
        lambda value: value["nodes"][0].update(attributes={"nested": {"x": 1}}),
        lambda value: value.update(schema_version="1.0"),
    ],
)
def test_prompt_tsg_v2_rejects_duplicate_dangling_nested_and_old(mutation) -> None:
    payload = _minimal_prompt_tsg()
    mutation(payload)
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate(payload)
```

Add exact boundary tests for 512/513 nodes, 2,048/2,049 edges, 32/33 attributes, UTF-8 string byte limits, non-finite floats, blank identifiers, mutable aliasing, and safe validation/repr surfaces.

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```text
pytest -q tests/test_schema.py tests/test_tsg_schema_v2.py
```

Expected: collection or assertions fail because `PromptTSGRecord`, strict IDs, immutable attributes, and schema 2.0 do not exist.

- [ ] **Step 3: Implement strict immutable models**

Replace the permissive models with strict versioned contracts:

```python
class PromptTSGRecord(SafeValidationMixin, VersionedModel):
    schema_version: Literal["2.0"]
    graph_id: str
    source_type: Literal["prompt"]
    prompt_id: str
    ontology_version: str
    motif_version: str
    graph_sha256: str
    nodes: tuple[TSGNode, ...]
    edges: tuple[TSGEdge, ...]
    shadow: FrozenTSGAttributes


class MotifMatch(SafeValidationMixin, VersionedModel):
    schema_version: Literal["1.0"]
    motif_id: MotifId
    node_path: tuple[str, ...]
    edge_path: tuple[str, ...]
    guarded: StrictBool
    guard_nodes: tuple[str, ...]
```

Use full lowercase SHA-256 node/edge ID patterns, exact enums, bounded tuple snapshot validators,
frozen scalar maps, `repr=False` for evidence attributes, and the existing
`ErrorCode.TSG_INVALID`. Remove `source_type="code"`, `code_id`, permissive `features`, and `Any`
attributes from the schema exports.

- [ ] **Step 4: Re-run schema tests**

Run:

```text
pytest -q tests/test_schema.py tests/test_tsg_schema_v2.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secaware/schema/tsg.py src/secaware/schema/__init__.py tests/test_schema.py tests/test_tsg_schema_v2.py
git commit -m "feat: add strict prompt tsg v2 schema"
```

### Task 2: Canonical MultiDiGraph codec and digest

**Files:**
- Replace: `src/secaware/tsg/graph.py`
- Modify: `src/secaware/tsg/__init__.py`
- Create: `tests/test_tsg_graph.py`

- [ ] **Step 1: Write failing graph round-trip tests**

```python
def test_parallel_edges_round_trip_without_order_drift() -> None:
    graph = nx.MultiDiGraph()
    graph.add_node("source", node_type="source", label="user_input", attributes={})
    graph.add_node("data", node_type="data_object", label="user_path", attributes={})
    graph.add_edge("source", "data", key="first", edge_type="source_of", attributes={})
    graph.add_edge("source", "data", key="second", edge_type="related_to", attributes={})

    one = multidigraph_to_record(graph, prompt_id="p001")
    two = multidigraph_to_record(_reverse_insertions(graph), prompt_id="p001")

    assert one.graph_sha256 == two.graph_sha256
    assert one.model_dump_json() == two.model_dump_json()
    rebuilt = record_to_multidigraph(one)
    assert rebuilt.number_of_edges("source", "data") == 2


def test_record_codec_rejects_digest_and_endpoint_tampering() -> None:
    record = multidigraph_to_record(_minimal_graph(), prompt_id="p001")
    with pytest.raises(SecAwareError, match="TSG"):
        record_to_multidigraph(_replace_digest(record, "0" * 64))
```

Add tests for canonical semantic node IDs, parallel-edge ordinals, hash-randomization independence, cycles, self-edge policy, ID collisions, unknown graph attributes, graph mutation after conversion, and direct-frame prompt evidence cleanup.

- [ ] **Step 2: Run codec tests and verify RED**

Run:

```text
pytest -q tests/test_tsg_graph.py
```

Expected: FAIL because the canonical codec does not exist.

- [ ] **Step 3: Implement graph conversion and hashing**

Implement these public boundaries:

```python
def canonical_node_id(node_type: NodeType, label: str, semantic_key: str) -> str: ...
def canonical_edge_id(src: str, dst: str, edge_type: EdgeType,
                      attributes: Mapping[str, TSGScalar], ordinal: int) -> str: ...
def graph_sha256(graph: nx.MultiDiGraph) -> str: ...
def record_to_multidigraph(record: object) -> nx.MultiDiGraph: ...
def multidigraph_to_record(graph: nx.MultiDiGraph, *, prompt_id: str,
                           shadow: Mapping[str, TSGScalar] | None = None) -> PromptTSGRecord: ...
```

Canonical hashing uses sorted JSON for graph identity, ontology/motif versions, nodes, and edges;
it excludes shadow. Conversion copies every attribute and never returns a graph sharing mutable
containers with the record or caller.

- [ ] **Step 4: Re-run graph and schema tests**

Run:

```text
pytest -q tests/test_tsg_graph.py tests/test_tsg_schema_v2.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secaware/tsg/graph.py src/secaware/tsg/__init__.py tests/test_tsg_graph.py
git commit -m "feat: add canonical prompt graph codec"
```

### Task 3: Versioned prompt ontology and graph-first extractor

**Files:**
- Create: `src/secaware/tsg/catalog.py`
- Replace: `src/secaware/extractors/prompt_tsg_extractor.py`
- Modify: `tests/test_prompt_tsg_extractor.py`
- Create: `tests/test_prompt_tsg_catalog.py`

- [ ] **Step 1: Write failing ontology and extractor tests**

```python
def test_path_prompt_emits_flow_facts_without_feature_decisions() -> None:
    record = extract_prompt_tsg(_prompt("Open a user-provided file path."))
    graph = record_to_multidigraph(record)
    assert _typed_edges(graph) >= {
        ("source", "data_object", EdgeType.SOURCE_OF),
        ("data_object", "sink", EdgeType.FLOWS_TO),
    }
    assert not hasattr(record, "features")


def test_guard_requirement_connects_to_the_same_path() -> None:
    record = extract_prompt_tsg(
        _prompt("Open a user path; normalize it and restrict it to a base directory.")
    )
    graph = record_to_multidigraph(record)
    assert has_factor_requirement(graph, FactorType.PATH_NORMALIZATION)
    assert _guard_targets(graph, "path_normalization") == {"user_path", "file_open"}
```

Add one positive, absent, unknown-language, bounded-evidence, and prompt-secret error-surface test for each of the six factor families. Assert the extractor source contains no direct shadow/motif assignment API.

- [ ] **Step 2: Verify RED**

Run:

```text
pytest -q tests/test_prompt_tsg_catalog.py tests/test_prompt_tsg_extractor.py
```

Expected: FAIL because ontology entries and graph-first extraction are missing.

- [ ] **Step 3: Implement the finite catalog**

Define immutable entries such as:

```python
@dataclass(frozen=True, slots=True)
class PromptOntologyEntry:
    factor_type: FactorType
    operation_label: str
    data_label: str
    sink_label: str
    requirement_label: str
    guard_label: str
    domain_terms: tuple[str, ...]
    guard_terms: tuple[str, ...]
    cwe: str
```

Declare exactly six entries, reject duplicate labels/terms and oversized evidence, and compute
`PROMPT_TSG_CATALOG_SHA256` from the canonical entries plus `ONTOLOGY_VERSION="1.0"` and
`MOTIF_VERSION="1.0"`.

- [ ] **Step 4: Rewrite prompt extraction to emit graph facts**

Use a graph builder that creates deterministic semantic node IDs and typed edges. Domain evidence
creates source → data → sink facts. Explicit guard evidence creates requirement → guard plus
same-flow guard relations. The extractor canonicalizes the graph without assigning factor, motif,
or shadow values; Task 4 makes shadow derivation part of the codec boundary after motif queries
exist.

- [ ] **Step 5: Re-run ontology/extractor tests**

Run:

```text
pytest -q tests/test_prompt_tsg_catalog.py tests/test_prompt_tsg_extractor.py tests/test_tsg_graph.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/secaware/tsg/catalog.py src/secaware/extractors/prompt_tsg_extractor.py tests/test_prompt_tsg_catalog.py tests/test_prompt_tsg_extractor.py
git commit -m "feat: extract prompt graph facts"
```

### Task 4: Bounded motif queries and shadow projection

**Files:**
- Replace: `src/secaware/tsg/motifs.py`
- Replace: `src/secaware/tsg/features.py`
- Modify: `src/secaware/tsg/graph.py`
- Modify: `src/secaware/tsg/__init__.py`
- Create: `tests/test_tsg_motifs.py`
- Create: `tests/test_tsg_shadow.py`

- [ ] **Step 1: Write failing motif-path tests**

```python
def test_disconnected_guard_does_not_protect_flow() -> None:
    graph = _unsafe_file_flow()
    graph.add_node("isolated_guard", node_type="guard", label="path_normalization", attributes={})
    matches = find_motif_matches(graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD)
    assert len(matches) == 1
    assert matches[0].guarded is False


def test_same_flow_guard_removes_unguarded_match() -> None:
    graph = _unsafe_file_flow()
    graph.add_edge("user_path", "path_guard", key="guard-edge",
                   edge_type="guarded_by", attributes={})
    assert find_motif_matches(
        graph, MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD
    ) == ()
```

Add wrong-data guard, parallel edge, cycle, exact eight/nine hop, 256/257 match, deterministic evidence, factor requirement, and all six motif tests.

- [ ] **Step 2: Write failing shadow integrity tests**

```python
def test_shadow_is_derived_and_tampering_is_rejected() -> None:
    record = extract_prompt_tsg(_path_prompt())
    assert record.shadow["motif.user_path_to_file_open_without_guard"] is True
    forged = record.model_copy(
        update={"shadow": {**record.shadow, "motif.user_path_to_file_open_without_guard": False}}
    )
    with pytest.raises(SecAwareError) as error:
        record_to_multidigraph(forged)
    assert error.value.code is ErrorCode.TSG_INVALID
```

- [ ] **Step 3: Verify RED**

Run:

```text
pytest -q tests/test_tsg_motifs.py tests/test_tsg_shadow.py
```

Expected: FAIL because bounded graph queries and shadow verification do not exist.

- [ ] **Step 4: Implement typed bounded traversal**

Implement:

```python
def find_motif_matches(graph: nx.MultiDiGraph, motif_id: MotifId,
                       *, max_hops: int = 8, max_matches: int = 256) -> tuple[MotifMatch, ...]: ...
def has_factor_requirement(graph: nx.MultiDiGraph, factor_type: FactorType) -> bool: ...
def factor_query_vector(graph: nx.MultiDiGraph) -> tuple[tuple[FactorType, bool], ...]: ...
def motif_query_vector(graph: nx.MultiDiGraph) -> tuple[tuple[MotifId, bool], ...]: ...
```

Traverse only typed flow edges, preserve multiedge IDs in evidence, bind guards to the same path,
sort results, and raise `TSG_INVALID` when bounds are exceeded.

- [ ] **Step 5: Implement and enforce shadow derivation**

`derive_shadow(graph)` emits the complete finite factor/motif vector and graph counts. Update the
codec so canonicalization derives it and reconstruction rejects any mismatch before returning a
graph.

- [ ] **Step 6: Re-run motif, shadow, codec, and extractor tests**

Run:

```text
pytest -q tests/test_tsg_motifs.py tests/test_tsg_shadow.py tests/test_tsg_graph.py tests/test_prompt_tsg_extractor.py
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/secaware/tsg/motifs.py src/secaware/tsg/features.py src/secaware/tsg/graph.py src/secaware/tsg/__init__.py tests/test_tsg_motifs.py tests/test_tsg_shadow.py
git commit -m "feat: query prompt motifs from graph"
```

### Task 5: Graph-query discovery scoring

**Files:**
- Modify: `src/secaware/discovery/candidate_enum.py`
- Modify: `src/secaware/discovery/scoring.py`
- Modify: `src/secaware/discovery/tsg_qcd.py`
- Modify: `src/secaware/schema/hypotheses.py`
- Create: `tests/test_discovery_graph_scoring.py`
- Modify: `tests/test_discovery.py`

- [ ] **Step 1: Write failing graph-authority tests**

```python
def test_path_score_changes_when_graph_changes_even_if_shadow_is_copied() -> None:
    unsafe = extract_prompt_tsg(_path_prompt())
    changed = _remove_flow_edge_and_recanonicalize(unsafe)
    forged = changed.model_copy(update={"shadow": unsafe.shadow})  # deliberate hostile cache

    unsafe_score = path_score(PATH_SPEC, [unsafe], _oracle_by_prompt(insecure=True))
    with pytest.raises(SecAwareError, match="TSG"):
        path_score(PATH_SPEC, [forged], _oracle_by_prompt(insecure=True))
    assert unsafe_score > 0.0


def test_prompt_graph_formula_does_not_accept_code_graph_input() -> None:
    signature = inspect.signature(discover_hypotheses)
    assert "code_tsgs" not in signature.parameters
```

Add exact association, path-score formula, CWE bonus, empty denominator, stability, evidence digest,
and monkeypatched-shadow tests. Assert `rg "features.get|code_tsg" src/secaware/discovery` has no matches.

- [ ] **Step 2: Verify RED**

Run:

```text
pytest -q tests/test_discovery.py tests/test_discovery_graph_scoring.py
```

Expected: FAIL because discovery still reads feature dictionaries and requires Code TSG.

- [ ] **Step 3: Replace feature keys with typed query declarations**

Change `FactorSpec` to contain `FactorType`, `MotifId`, requirement label, guard label, CWE, scope,
operator, and label. Remove `prompt_factor`, `prompt_motif` string lookup keys, and `code_motif`.

- [ ] **Step 4: Implement graph-based formulas**

`association_score` groups by `has_factor_requirement`. `path_score` implements the approved
formula:

```python
p_motif = len(motif_absent) / len(absent) if absent else 0.0
p_insecure = _risk_rate(motif_oracles)
score = p_motif * p_insecure
if spec.cwe != "generic" and _oracle_has_cwe(motif_oracles, spec.cwe):
    score += 0.1
return min(1.0, score)
```

Every input TSG passes `record_to_multidigraph`; no score reads shadow. Remove `code_tsgs` from
`discover_hypotheses`, and add graph digest/motif evidence summaries to hypothesis support metadata.

- [ ] **Step 5: Re-run discovery tests**

Run:

```text
pytest -q tests/test_discovery.py tests/test_discovery_graph_scoring.py
rg -n "features\.get|code_tsg" src/secaware/discovery
```

Expected: tests PASS and `rg` exits 1 with no matches.

- [ ] **Step 6: Commit**

```bash
git add src/secaware/discovery src/secaware/schema/hypotheses.py tests/test_discovery.py tests/test_discovery_graph_scoring.py
git commit -m "feat: score discovery from prompt graphs"
```

### Task 6: Graph-query intervention validation

**Files:**
- Modify: `src/secaware/intervention/validator.py`
- Modify: `src/secaware/intervention/operators.py`
- Modify: `tests/test_intervention.py`
- Create: `tests/test_intervention_graph_validation.py`

- [ ] **Step 1: Write failing live-query intervention tests**

```python
def test_intervention_target_and_side_effect_ignore_shadow() -> None:
    original = extract_prompt_tsg(_path_prompt_without_guard())
    hypothesis = _path_hypothesis()
    result = validate_intervention(
        _path_prompt_without_guard(),
        original,
        _path_prompt_with_guard().prompt,
        hypothesis,
    )
    assert result == {
        "round_trip_valid": True,
        "semantic_valid": True,
        "target_changed": True,
        "side_effect": False,
    }


def test_unrelated_requirement_is_reported_as_side_effect() -> None:
    result = _validate_path_patch_that_also_adds_sql_requirement()
    assert result["target_changed"] is True
    assert result["side_effect"] is True
```

Add disconnected guard, wrong target, primary operation/sink preservation, hostile shadow, and safe
error-surface tests. Assert no intervention module reads `.features` or `.shadow`.

- [ ] **Step 2: Verify RED**

Run:

```text
pytest -q tests/test_intervention.py tests/test_intervention_graph_validation.py
```

Expected: FAIL because validation still diffs feature maps.

- [ ] **Step 3: Implement live graph validation**

Reconstruct both graphs. Determine target change from the hypothesis `FactorType`. Compare complete
factor and motif query vectors, excluding only the declared target factor and its paired motif from
side-effect detection. Determine semantic identity from typed operation/sink queries, not raw node
list order.

- [ ] **Step 4: Re-run intervention tests and static checks**

Run:

```text
pytest -q tests/test_intervention.py tests/test_intervention_graph_validation.py
rg -n "\.features|\.shadow" src/secaware/intervention
```

Expected: tests PASS and `rg` exits 1.

- [ ] **Step 5: Commit**

```bash
git add src/secaware/intervention tests/test_intervention.py tests/test_intervention_graph_validation.py
git commit -m "feat: validate interventions from prompt graphs"
```

### Task 7: Catalog-bound Prompt TSG pipeline and Code TSG removal

**Files:**
- Modify: `src/secaware/pipeline/manifest.py`
- Modify: `src/secaware/io/run_store.py`
- Modify: `src/secaware/cli.py`
- Modify: `src/secaware/schema/__init__.py`
- Modify: `src/secaware/extractors/__init__.py`
- Delete: `src/secaware/extractors/code_tsg_extractor.py`
- Delete: `tests/test_code_tsg_extractor.py`
- Modify: `tests/test_stage_manifest.py`
- Modify: `tests/test_stage_orchestration.py`
- Modify: `tests/test_generation_cli.py`
- Modify: `tests/test_generation_result_importer.py`
- Modify: `tests/test_provider_generation_cli.py`
- Modify: `tests/test_oracle_cli.py`
- Modify: `tests/test_run_all_demo.py`
- Create: `tests/test_prompt_tsg_pipeline.py`

- [ ] **Step 1: Write failing catalog-manifest tests**

```python
def test_prompt_tsg_manifest_requires_catalog_digest() -> None:
    with pytest.raises(ValidationError):
        StageManifest.model_validate(_prompt_tsg_manifest(catalog_sha256=None))


def test_prompt_tsg_skip_invalidates_on_catalog_change(store, prompt_input) -> None:
    extract_prompt_tsg_stage(_config(), store, force=False)
    assert store.should_skip_stage(
        "extract-prompt-tsg", [prompt_input], [_tsg_output(store)], False,
        catalog_sha256="0" * 64,
    ) is False
```

Add manifest/readback/tamper, old schema artifact, output seal, consumer expected-catalog mismatch,
producer lease, concurrent force, and force rollback tests.

- [ ] **Step 2: Write failing pipeline-removal tests**

```python
def test_run_all_has_no_code_tsg_stage_or_artifact() -> None:
    result = _run_all_with_controlled_oracle()
    assert result.exit_code == 0
    assert not result.run_dir.joinpath("tsg", "observed_code_tsg.jsonl").exists()
    assert not result.run_dir.joinpath("tsg", "counterfactual_code_tsg.jsonl").exists()
    assert "extract-code-tsg" not in _stage_names(result.run_dir)
```

Assert the CLI help has no `extract-code-tsg`, discovery holds committed Prompt TSG plus Oracle
leases in fixed order, intervention holds committed Prompt TSG plus selected hypotheses, and old TSG
v1 cannot be consumed.

- [ ] **Step 3: Verify RED**

Run:

```text
pytest -q tests/test_prompt_tsg_pipeline.py tests/test_stage_manifest.py tests/test_stage_orchestration.py tests/test_run_all_demo.py
```

Expected: FAIL because catalog binding, transactions, and Code TSG removal are absent.

- [ ] **Step 4: Bind catalog digest through manifests and RunStore**

Add `catalog_sha256` to `StageManifest` and `_StageSnapshot`. Require it only for
`extract-prompt-tsg`; require `None` for unrelated stages. Include it in fingerprint, skip,
`record_stage`, strict readback, and `hold_committed_output(expected_catalog_sha256=...)`.

The extraction stage passes `PROMPT_TSG_CATALOG_SHA256`, writes a candidate JSONL, strictly reads
non-empty exact `PromptTSGRecord` values, seals outputs, records the manifest, and uses the existing
preserve-committed transaction/lease pattern for force rollback.

- [ ] **Step 5: Remove Code TSG and migrate consumers**

Delete the extractor, stage, CLI command, artifacts, imports, tests, and run-all calls. Update
`discover_stage` to accept only Prompt TSG plus Oracle records and hold both committed producer
leases in fixed stage-name order. Update `intervene_stage` to hold committed Prompt TSG and discovery
outputs while using exact Prompt TSG v2 records.

- [ ] **Step 6: Re-run pipeline tests and static removal checks**

Run:

```text
pytest -q tests/test_prompt_tsg_pipeline.py tests/test_stage_manifest.py tests/test_stage_orchestration.py tests/test_generation_cli.py tests/test_generation_result_importer.py tests/test_provider_generation_cli.py tests/test_oracle_cli.py tests/test_run_all_demo.py
rg -n "extract_code_tsg|extract-code-tsg|code_tsg|observed_code_tsg|counterfactual_code_tsg" src tests configs
```

Expected: tests PASS and `rg` exits 1.

- [ ] **Step 7: Commit**

```bash
git add src/secaware/pipeline/manifest.py src/secaware/io/run_store.py src/secaware/cli.py src/secaware/schema src/secaware/extractors/__init__.py tests
git rm src/secaware/extractors/code_tsg_extractor.py tests/test_code_tsg_extractor.py
git commit -m "feat: connect catalog-bound prompt tsg pipeline"
```

### Task 8: Documentation, migration audit, and full verification

**Files:**
- Modify: `README.md`
- Create: `docs/migrations/prompt-tsg-v2.md`
- Modify: `configs/demo.yaml`
- Modify: `configs/paper_v0.yaml`
- Modify: `tests/test_run_all_demo.py`

- [ ] **Step 1: Document the graph/outcome boundary and migration**

README must state that Prompt TSG supplies pre-treatment graph factors, Semgrep+Bandit supply the
only `Y`, Code TSG is not a mandatory stage, and shadow is never authoritative. The migration note
must require regeneration of Prompt TSG v2 and downstream stages and state that v1 artifacts are
rejected rather than converted.

- [ ] **Step 2: Add final architecture/removal gates**

Add tests that inspect production source and CLI help:

```python
def test_discovery_and_intervention_have_no_shadow_or_feature_reads() -> None:
    for relative in (
        "src/secaware/discovery/scoring.py",
        "src/secaware/discovery/tsg_qcd.py",
        "src/secaware/intervention/validator.py",
    ):
        source = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert ".features" not in source
        assert ".shadow" not in source


def test_security_outcome_is_oracle_only() -> None:
    assert _run_all_security_labels() == _read_oracle_security_labels()
```

- [ ] **Step 3: Run focused M3 verification**

Run:

```text
pytest -q tests/test_tsg_schema_v2.py tests/test_tsg_graph.py tests/test_prompt_tsg_catalog.py tests/test_prompt_tsg_extractor.py tests/test_tsg_motifs.py tests/test_tsg_shadow.py tests/test_discovery_graph_scoring.py tests/test_intervention_graph_validation.py tests/test_prompt_tsg_pipeline.py tests/test_run_all_demo.py
```

Expected: PASS.

- [ ] **Step 4: Run the three full matrices**

Run:

```text
uv run --no-cache --isolated --no-project --no-python-downloads --python 3.10 --with-editable . --with pytest pytest -q -p no:cacheprovider
uv run --no-cache --isolated --no-project --no-python-downloads --python 3.12 --with-editable . --with pytest pytest -q -p no:cacheprovider
uv run --no-cache --isolated --no-project --no-python-downloads --python 3.12 --with pydantic==2.5.3 --with-editable . --with pytest pytest -q -p no:cacheprovider
```

Expected: all matrices PASS; only documented platform/optional-tool skips remain.

- [ ] **Step 5: Run static, CLI, and real-Oracle regression gates**

Run:

```text
ruff format --check src tests
ruff check src tests
python -m compileall -q src tests
git diff --check
rg -n "features\.get|extract_code_tsg|extract-code-tsg|code_tsg|observed_code_tsg|counterfactual_code_tsg" src tests configs
uv run --no-cache --isolated --no-project --no-python-downloads --python 3.12 --with-editable '.[oracle]' --with pytest pytest -q -p no:cacheprovider -m oracle_tools
```

Expected: formatting/lint/compile/diff and real Oracle gate PASS; `rg` exits 1.

- [ ] **Step 6: Commit documentation and final gates**

```bash
git add README.md docs/migrations/prompt-tsg-v2.md configs tests/test_run_all_demo.py
git commit -m "docs: finalize prompt tsg graph migration"
```

## Plan self-review

- Every design requirement maps to a task: strict schema (1), codec (2), ontology/extraction (3),
  motifs/shadow (4), discovery (5), intervention (6), pipeline/removal (7), and migration/full gates
  (8).
- Code TSG is removed rather than retained as a hidden compatibility path.
- Oracle remains unchanged and supplies the only security label.
- No task authorizes discovery or intervention to read shadow.
- Catalog digest invalidates old skip state and is verified by consumers.
- All bounded traversal, graph size, transaction, control-flow, and error-surface requirements have
  explicit tests.
- The plan contains no deferred placeholders.
