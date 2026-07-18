import ast
from dataclasses import fields
from pathlib import Path
import subprocess
import sys

import networkx as nx

from secaware.schema.causal import EndpointMark, FrozenHypothesisRecord
from secaware.schema.features import FeatureFamily
from secaware.schema.tsg import EdgeType, MotifId
from secaware.tsg import catalog, motifs
from secaware.tsg.feature_catalog import prompt_feature_spec
from secaware.tsg.features import derive_shadow


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TSG_MODULES = (
    "src/secaware/tsg/catalog.py",
    "src/secaware/tsg/motifs.py",
    "src/secaware/tsg/graph.py",
    "src/secaware/tsg/builder.py",
    "src/secaware/tsg/features.py",
)


def _direct_imports(relative_path: str) -> set[str]:
    tree = ast.parse((PROJECT_ROOT / relative_path).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    return imported


def test_prompt_tsg_modules_do_not_depend_on_retired_hypothesis_schema() -> None:
    for relative_path in TSG_MODULES:
        assert "secaware.schema.hypotheses" not in _direct_imports(relative_path)
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "import secaware.tsg.catalog, secaware.tsg.graph, secaware.tsg.motifs; "
                "assert 'secaware.schema.hypotheses' not in sys.modules"
            ),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert probe.returncode == 0, probe.stderr


def test_prompt_ontology_is_keyed_by_reviewed_task_and_target_feature_ids() -> None:
    assert {field.name for field in fields(catalog.PromptOntologyEntry)} == {
        "task_feature_id",
        "target_feature_id",
        "operation_label",
        "data_label",
        "sink_label",
        "requirement_label",
        "guard_label",
        "domain_terms",
        "guard_terms",
        "cwe",
    }
    assert len(catalog.PROMPT_TSG_CATALOG) == 6
    for entry in catalog.PROMPT_TSG_CATALOG:
        task = prompt_feature_spec(entry.task_feature_id)
        target = prompt_feature_spec(entry.target_feature_id)
        assert task.feature_family is FeatureFamily.TASK_FUNCTION
        assert target.feature_family is FeatureFamily.SAFETY_CONTROL
        assert task.deterministic_terms == entry.domain_terms
        assert target.deterministic_terms == entry.guard_terms
        assert catalog.prompt_ontology_entry(entry.target_feature_id) is entry


def test_motifs_bind_prompt_features_not_legacy_factors_or_hypotheses() -> None:
    assert {field.name for field in fields(motifs.MotifSpec)} == {
        "motif_id",
        "task_feature_id",
        "target_feature_id",
        "source_types",
        "data_label",
        "sink_label",
        "requirement_label",
        "guard_label",
        "first_edge_type",
        "traversable_edge_types",
        "max_hops",
    }
    assert tuple(motifs.MOTIF_SPECS) == tuple(MotifId)
    assert len({spec.target_feature_id for spec in motifs.MOTIF_SPECS.values()}) == 6
    for spec in motifs.MOTIF_SPECS.values():
        assert (
            prompt_feature_spec(spec.task_feature_id).feature_family is FeatureFamily.TASK_FUNCTION
        )
        assert (
            prompt_feature_spec(spec.target_feature_id).feature_family
            is FeatureFamily.SAFETY_CONTROL
        )
        assert FrozenHypothesisRecord.model_fields["target_feature_id"].annotation is str


def test_feature_requirement_queries_and_shadow_use_feature_ids() -> None:
    graph = nx.MultiDiGraph()
    targets = tuple(entry.target_feature_id for entry in catalog.PROMPT_TSG_CATALOG)

    assert (
        tuple(feature_id for feature_id, _ in motifs.feature_requirement_vector(graph)) == targets
    )
    assert all(motifs.has_feature_requirement(graph, feature_id) is False for feature_id in targets)
    shadow = derive_shadow(graph)
    expected = {f"feature.{feature_id}.required" for feature_id in targets}
    assert expected <= set(shadow)
    assert not any(key.startswith("factor.") for key in shadow)
    assert not hasattr(motifs, "factor_query_vector")
    assert not hasattr(motifs, "has_factor_requirement")


def test_prompt_tsg_edge_types_remain_semantic_not_causal_endpoint_marks() -> None:
    assert {edge.value for edge in EdgeType}.isdisjoint({mark.value for mark in EndpointMark})
    assert "secaware.schema.causal" not in _direct_imports("src/secaware/tsg/graph.py")
    assert all("causal" not in edge.value for edge in EdgeType)
