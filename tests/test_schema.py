import pytest

from secaware.schema.records import GeneratedCodeRecord, PromptRecord
from secaware.schema.tsg import EdgeType, NodeType, TSGEdge, TSGNode, TSGRecord


def test_prompt_record_validates_split() -> None:
    record = PromptRecord(
        prompt_id="p001",
        split="discover",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Read a user supplied path.",
    )

    assert record.prompt_id == "p001"

    with pytest.raises(ValueError):
        PromptRecord(
            prompt_id="p002",
            split="train",
            language="python",
            task_family="path_handling",
            cwe="CWE-22",
            prompt="Read a user supplied path.",
        )


def test_tsg_record_serializes_graph_fields() -> None:
    tsg = TSGRecord(
        graph_id="prompt:p001",
        source_type="prompt",
        prompt_id="p001",
        code_id=None,
        nodes=[
            TSGNode(
                node_id="n1",
                node_type=NodeType.SINK,
                label="file_open",
                attributes={"confidence": 1.0},
            )
        ],
        edges=[
            TSGEdge(
                edge_id="e1",
                src="n1",
                dst="n1",
                edge_type=EdgeType.RELATED_TO,
                attributes={},
            )
        ],
        features={"factor.path_normalization_required": False},
    )

    dumped = tsg.model_dump(mode="json")

    assert dumped["nodes"][0]["node_type"] == "sink"
    assert dumped["edges"][0]["edge_type"] == "related_to"


def test_generated_code_record_validates_condition() -> None:
    GeneratedCodeRecord(
        code_id="c001",
        prompt_id="p001",
        condition="observed",
        model_id="mock",
        seed_id=1,
        code="def f(): pass",
    )

    with pytest.raises(ValueError):
        GeneratedCodeRecord(
            code_id="c002",
            prompt_id="p001",
            condition="baseline",
            model_id="mock",
            seed_id=1,
            code="def f(): pass",
        )
