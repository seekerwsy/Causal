import pytest

from secaware.schema.records import GeneratedCodeRecord, PromptRecord
from secaware.schema.tsg import PromptTSGRecord


def test_prompt_record_validates_split() -> None:
    record = PromptRecord(
        prompt_id="p001",
        task_id="task-path-001",
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
            task_id="task-path-002",
            split="train",
            language="python",
            task_family="path_handling",
            cwe="CWE-22",
            prompt="Read a user supplied path.",
        )


@pytest.mark.parametrize("task_id", (None, "", " ", " task-path-001", "task-path-001 "))
def test_prompt_record_requires_canonical_task_id(task_id: object) -> None:
    payload = {
        "prompt_id": "p001",
        "task_id": task_id,
        "split": "discover",
        "language": "python",
        "task_family": "path_handling",
        "cwe": "CWE-22",
        "prompt": "Read a user supplied path.",
    }
    if task_id is None:
        payload.pop("task_id")
    with pytest.raises(ValueError):
        PromptRecord.model_validate(payload)


@pytest.mark.parametrize("task_id", (b"task-path-001", 123, True))
def test_prompt_record_rejects_non_string_task_id(task_id: object) -> None:
    with pytest.raises(ValueError):
        PromptRecord.model_validate(
            {
                "prompt_id": "p001",
                "task_id": task_id,
                "split": "discover",
                "language": "python",
                "task_family": "path_handling",
                "cwe": "CWE-22",
                "prompt": "Read a user supplied path.",
            }
        )


def test_prompt_tsg_record_serializes_graph_fields() -> None:
    tsg = PromptTSGRecord.model_validate(
        {
            "schema_version": "2.1",
            "graph_id": "prompt:p001",
            "source_type": "prompt",
            "prompt_id": "p001",
            "task_id": "task-path-001",
            "task_family": "path_handling",
            "cwe": "CWE-22",
            "extractor_backend": "llm_facts_v1",
            "extractor_policy_sha256": "8" * 64,
            "proposal_id": "proposal_" + "7" * 64,
            "ontology_version": "1.0",
            "motif_version": "1.0",
            "graph_sha256": "0" * 64,
            "nodes": [
                {
                    "node_id": "n_" + "1" * 64,
                    "semantic_key_sha256": "9" * 64,
                    "node_type": "sink",
                    "label": "file_open",
                    "attributes": {"confidence": 1.0},
                }
            ],
            "edges": [
                {
                    "edge_id": "e_" + "2" * 64,
                    "src": "n_" + "1" * 64,
                    "dst": "n_" + "1" * 64,
                    "edge_type": "related_to",
                    "attributes": {},
                }
            ],
            "shadow": {"factor.path_normalization_required": False},
        }
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
