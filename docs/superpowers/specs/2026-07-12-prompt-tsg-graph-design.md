# Prompt TSG Graph-First Design

**Status:** Approved for planning  
**Date:** 2026-07-12  
**Scope:** M3 — authoritative Prompt TSG graph, graph-derived motifs, and removal of mandatory Code TSG

## 1. Decision

Prompt TSG becomes the only graph representation used by mechanism discovery. A strict
NetworkX `MultiDiGraph` reconstructed from canonical nodes and edges is authoritative. Motifs,
prompt factors, and discovery graph evidence are computed from that graph.

The independent Semgrep 1.168.0 plus Bandit 1.9.4 Oracle remains the sole source of the security
outcome `Y` (`secure` or `insecure`). Code TSG is removed from the mandatory pipeline and from all
primary discovery, eligibility, confirmation, effect-estimation, bootstrap, and multiple-testing
calculations.

The primary causal relation is therefore:

```text
prompt-side factor X  ──>  independent Oracle outcome Y
```

This design does not claim that a particular generated-code structure mediates the effect. A
future optional code-mechanism trace may support exploratory interpretation, but it must not alter
the Oracle label, eligibility, discovery score, or confirmatory estimate.

## 2. Rationale

The current implementation serializes nodes and edges but computes discovery from independently
written `features` booleans. The graph is therefore decorative and two contradictory truth sources
can exist.

Making Code TSG part of the primary estimator would introduce a second problem: it is a
post-treatment variable. Conditioning on or selecting by generated-code structure can bias the
estimated total effect of a prompt intervention. It would also grow a second handwritten source,
sink, and guard analyzer beside the locked external Oracle.

This design fixes both problems:

- Prompt graph structure is genuinely used by discovery.
- Security outcomes come only from the independent Oracle.
- Generated-code structure cannot redefine or filter the primary outcome.
- A flat compatibility projection cannot override graph facts.

## 3. Supported TSG Artifact

### 3.1 Schema version

Prompt TSG uses a breaking schema version `2.0`. Version 1 artifacts are not migrated or accepted;
the prompt TSG extraction stage must regenerate them. The stage fingerprint includes the extractor,
ontology, motif, and schema versions so an old manifest cannot be skipped.

### 3.2 Canonical record

The persisted record contains JSON-friendly immutable tuples rather than a pickled NetworkX
object:

```python
class PromptTSGRecord:
    schema_version: Literal["2.0"]
    graph_id: str
    source_type: Literal["prompt"]
    prompt_id: str
    graph_sha256: str
    nodes: tuple[TSGNode, ...]
    edges: tuple[TSGEdge, ...]
    shadow: FrozenMapping[str, bool | int | str]
```

`source_type="code"` and `code_id` are not part of schema 2.0. Code TSG artifacts and the
`extract-code-tsg` stage are removed from the mandatory run graph.

### 3.3 Node and edge contracts

Node and edge models are strict, frozen, and reject unknown fields. Arbitrary `dict[str, Any]`
attributes are replaced with bounded JSON scalar attributes whose allowed keys depend on the node
or edge type.

Validation enforces:

- at most 512 nodes and 2,048 edges;
- unique node IDs and edge IDs;
- every edge endpoint exists;
- node and edge types belong to finite enums;
- no blank or untrimmed identifiers and labels;
- at most 32 attributes per object;
- attribute strings are at most 1,024 UTF-8 bytes;
- no non-finite numbers, nested arbitrary objects, or mutable containers;
- canonical node and edge order;
- exact recomputation of `graph_sha256` and `shadow`.

Node IDs are `n_` plus the full lowercase SHA-256 of a canonical semantic key. Edge IDs are `e_`
plus the SHA-256 of source ID, destination ID, edge type, canonical attributes, and a deterministic
parallel-edge ordinal. A collision or duplicate semantic identity fails closed.

## 4. Graph Codec

`record_to_multidigraph(record)` is the only supported reconstruction boundary. It revalidates the
record, creates a `networkx.MultiDiGraph`, stores each `edge_id` as the NetworkX multiedge key, and
then checks that graph-derived digest and shadow equal the record.

`multidigraph_to_record(graph, prompt_id)` canonicalizes an internally produced graph. It never
accepts an arbitrary graph supplied by a stage consumer without the same node, edge, attribute,
size, and endpoint validation.

Graph serialization is deterministic: insertion order, Python hash randomization, and equivalent
parallel-edge construction order cannot alter the canonical JSON or digest.

## 5. Prompt Graph Extraction

The extractor emits graph facts only. It does not write motif or factor booleans.

The finite, versioned prompt ontology defines the supported requirement families:

- path normalization and path allowlisting;
- SQL parameterization;
- safe subprocess invocation;
- authorization checks;
- safe deserialization;
- generic input validation.

Each family maps explicit prompt evidence to typed facts such as:

- `PROMPT_REQUIREMENT` nodes;
- `GUARD` nodes;
- `TASK_OPERATION`, `DATA_OBJECT`, `SOURCE`, `SINK`, `TRUST_BOUNDARY`, and `CWE` nodes;
- `SOURCE_OF`, `FLOWS_TO`, `OPERATES_ON`, `REQUIRES`, `OMITS`, `MAPS_TO`, and `RELATED_TO`
  edges.

The ontology is centralized in one reviewed module. It is not a security classifier and never
emits `secure` or `insecure`. Unknown language creates fewer graph facts; it does not imply an
unsafe motif. Security conclusions remain external-Oracle-only.

Prompt evidence stores bounded offsets and an evidence digest, not the complete prompt text.
Errors and repr surfaces must not expose prompt contents.

## 6. Motif Query Engine

Motifs are finite declarative graph patterns. A `MotifSpec` identifies allowed source types, sink
labels, traversable edge types, accepted guard types, and an eight-hop maximum.

The query engine returns immutable evidence:

```python
class MotifMatch:
    motif_id: MotifId
    node_path: tuple[str, ...]
    edge_path: tuple[str, ...]
    guarded: bool
    guard_nodes: tuple[str, ...]
```

Queries use bounded deterministic traversal:

- at most eight hops per candidate path;
- at most 256 matches per motif;
- stable sorting by motif, node path, and edge path;
- explicit visited-state handling for cycles and parallel edges;
- an exceeded bound is `TSG_INVALID`, never silent truncation.

A guard is effective only when it protects the same flow: it must lie on the relevant path or be
connected by a typed guard relation to a path data/sink node. An isolated guard, or a guard attached
to another data object, does not suppress an unguarded motif.

The supported prompt motifs initially remain the six finite protocol motifs already represented by
`FactorSpec`; adding a motif requires an ontology version change, a schema fingerprint change, and
new positive, negative, disconnected-guard, and adversarial graph tests.

## 7. Shadow Projection

`shadow` is a deterministic flat projection computed from graph queries. It exists only for human
inspection, migration diagnostics, and compact reports.

Examples include:

```text
factor.path_normalization_required
factor.sql_parameterization_required
motif.user_path_to_file_open_without_guard
motif.user_input_to_shell_without_guard
graph.node_count
graph.edge_count
```

Rules:

- extractors never write shadow values directly;
- `derive_shadow(graph)` is the only producer;
- record loading recomputes and exactly compares every key and value;
- missing, extra, or mismatched keys are `TSG_INVALID`;
- discovery and confirmation are prohibited from reading `record.shadow`;
- changing shadow cannot change a result; changing graph structure changes both queries and shadow.

## 8. Discovery Integration

`FactorSpec` stops storing feature-map keys. It stores typed factor, motif, guard, and scope enums.

Discovery uses graph query APIs:

- factor presence comes from requirement-to-guard graph structure;
- prompt motif presence comes from `find_motif_matches`;
- association and stability group prompts by graph query results;
- nuisance adjustment may retain pre-treatment metadata such as task family and prompt length;
- the independent Oracle label supplies `Y`.

The primary `path_score` must not query Code TSG. For a factor specification, let `absent` be the
scoped prompt graphs where the target requirement query is false, and let `motif_absent` be the
subset with at least one live match for the specification's unguarded prompt motif. The score is:

```text
P(prompt motif | target requirement absent)
    * P(Oracle insecure | prompt motif)
```

The existing bounded `+0.1` scope bonus remains only when an Oracle finding has the specification's
declared CWE; the final score is capped at `1.0`. Empty denominators produce `0.0`. Any optional
future code-mechanism score is reported separately and cannot enter `discovery_score`, hypothesis
eligibility, or confirmation.

Hypothesis evidence records the prompt graph digest, motif ID, match count, and bounded node/edge
path IDs. It never records prompt text.

Prompt intervention validation also uses live graph queries rather than shadow values. The original
and counterfactual prompts are independently extracted to version 2 graphs. `target_changed` is
true only when the typed target requirement/guard query changes in the expected direction.
`side_effect` compares the complete finite vector of live factor and motif queries and ignores the
declared target query. Neither decision reads or diffs `record.shadow`.

## 9. Pipeline Changes

The mandatory stage order becomes:

```text
prompt loading
  -> prompt TSG v2 extraction
  -> generation
  -> independent Oracle
  -> graph-based discovery
  -> prompt intervention
  -> counterfactual generation and Oracle
  -> confirmation and reporting
```

`extract-code-tsg`, observed/counterfactual code TSG artifacts, their manifests, CLI command, and
run-all dependencies are removed. Discovery holds the committed prompt-TSG and Oracle producer
leases while validating and computing, following the transaction rules established in M2.

## 10. Failure Semantics

A stable `TSG_INVALID` error covers invalid schema, digest, graph, shadow, traversal bounds, and
ontology/motif version mismatches.

There is no fallback to version 1 features, keyword booleans, Code TSG, or inferred security labels.
Invalid Prompt TSG prevents discovery publication. Error messages, structured details, traceback
frames, and reprs do not contain prompt text or raw evidence.

## 11. Testing and Acceptance

M3 is complete only when tests prove all of the following:

1. Parallel typed edges survive record/graph round trips.
2. Equivalent insertion orders produce identical canonical JSON and graph digest.
3. Duplicate IDs, dangling endpoints, invalid attributes, oversize graphs, and digest tampering fail.
4. Isolated or wrong-flow guards do not protect a source-to-sink path.
5. A correctly connected guard changes the corresponding motif result.
6. Cycles and parallel paths obey deterministic hop and match limits.
7. Shadow tampering fails; discovery never reads shadow.
8. Modifying only graph structure changes motif and discovery results.
9. Prompt extractors contain no direct motif/factor assignments.
10. `features.get` and mandatory Code TSG dependencies are absent from discovery, intervention,
    confirmation, and run-all.
11. Old TSG artifacts cannot pass schema, manifest, or skip validation.
12. Prompt TSG, discovery, intervention, and run-all integration tests pass.
13. Python 3.10, Python 3.12, and the minimum Pydantic matrix pass.

## 12. Non-Goals

- TSG does not classify generated code security.
- M3 does not implement a replacement static analyzer.
- M3 does not estimate mediation or controlled direct effects.
- M3 does not retain a hidden Code TSG compatibility path.
- M3 does not add an unbounded prompt-rule registry.
- M3 does not change the locked Oracle outcome contract.

## 13. Consequences

The change is intentionally breaking and removes a misleading subsystem. It increases graph-schema
and query-engine rigor, but simplifies the causal interpretation: prompt graph factors are
pre-treatment structure, while Oracle records are the sole outcome. Existing run directories must
regenerate Prompt TSG v2 and all downstream artifacts.
