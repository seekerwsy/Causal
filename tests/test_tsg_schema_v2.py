from decimal import Decimal
import math

import pytest
from pydantic import ValidationError

from secaware.errors import ErrorCode
from secaware.schema.tsg import MotifId, MotifMatch, PromptTSGRecord, TSGEdge, TSGNode


def _node(index: int, *, attributes: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "node_id": f"n_{index:064x}",
        "node_type": "source",
        "label": f"node_{index}",
        "attributes": {} if attributes is None else attributes,
    }


def _edge(index: int, *, src: str, dst: str) -> dict[str, object]:
    return {
        "edge_id": f"e_{index:064x}",
        "src": src,
        "dst": dst,
        "edge_type": "flows_to",
        "attributes": {},
    }


def _minimal_prompt_tsg() -> dict[str, object]:
    node_id = "n_" + "a" * 64
    return {
        "schema_version": "2.0",
        "graph_id": "prompt:p001",
        "source_type": "prompt",
        "prompt_id": "p001",
        "ontology_version": "1.0",
        "motif_version": "1.0",
        "graph_sha256": "b" * 64,
        "nodes": [
            {
                "node_id": node_id,
                "node_type": "source",
                "label": "user_input",
                "attributes": {"evidence_digest": "c" * 64},
            }
        ],
        "edges": [
            {
                "edge_id": "e_" + "d" * 64,
                "src": node_id,
                "dst": node_id,
                "edge_type": "related_to",
                "attributes": {"ordinal": 0},
            }
        ],
        "shadow": {"graph.node_count": 1, "factor.input_validation_required": False},
    }


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


@pytest.mark.parametrize("count", [512])
def test_prompt_tsg_v2_accepts_exact_node_limit(count: int) -> None:
    payload = _minimal_prompt_tsg()
    payload["nodes"] = [_node(index) for index in range(1, count + 1)]
    payload["edges"] = []
    assert len(PromptTSGRecord.model_validate(payload).nodes) == count


def test_prompt_tsg_v2_rejects_above_node_limit() -> None:
    payload = _minimal_prompt_tsg()
    payload["nodes"] = [_node(index) for index in range(1, 514)]
    payload["edges"] = []
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate(payload)


def test_prompt_tsg_v2_accepts_exact_edge_limit_and_rejects_one_more() -> None:
    payload = _minimal_prompt_tsg()
    node_id = payload["nodes"][0]["node_id"]
    payload["edges"] = [_edge(index, src=node_id, dst=node_id) for index in range(1, 2049)]
    assert len(PromptTSGRecord.model_validate(payload).edges) == 2048

    payload["edges"].append(_edge(2049, src=node_id, dst=node_id))
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate(payload)


def test_prompt_tsg_v2_accepts_32_attributes_and_rejects_33() -> None:
    payload = _minimal_prompt_tsg()
    payload["nodes"][0]["attributes"] = {f"key_{index}": index for index in range(32)}
    assert len(PromptTSGRecord.model_validate(payload).nodes[0].attributes) == 32

    payload["nodes"][0]["attributes"]["key_32"] = 32
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate(payload)


def test_prompt_tsg_v2_counts_attribute_string_limits_in_utf8_bytes() -> None:
    payload = _minimal_prompt_tsg()
    payload["nodes"][0]["attributes"] = {"evidence": "界" * 341 + "a"}
    PromptTSGRecord.model_validate(payload)

    payload["nodes"][0]["attributes"] = {"evidence": "界" * 342}
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate(payload)


@pytest.mark.parametrize("value", [math.inf, -math.inf, math.nan])
def test_prompt_tsg_v2_rejects_non_finite_floats(value: float) -> None:
    payload = _minimal_prompt_tsg()
    payload["nodes"][0]["attributes"] = {"confidence": value}
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("graph_id",), " "),
        (("prompt_id",), ""),
        (("ontology_version",), " 1.0"),
        (("nodes", 0, "label"), "sink "),
        (("nodes", 0, "attributes"), {" ": 1}),
    ],
)
def test_prompt_tsg_v2_rejects_blank_or_untrimmed_identifiers(path, value) -> None:
    payload = _minimal_prompt_tsg()
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate(payload)


def test_prompt_tsg_v2_requires_full_lowercase_sha256_ids() -> None:
    for invalid_id in ("n_abc", "n_" + "A" * 64, "e_" + "a" * 64):
        payload = _minimal_prompt_tsg()
        payload["nodes"][0]["node_id"] = invalid_id
        with pytest.raises(ValidationError):
            PromptTSGRecord.model_validate(payload)


def test_prompt_tsg_v2_snapshots_mutable_aliases_and_freezes_attribute_maps() -> None:
    payload = _minimal_prompt_tsg()
    input_attributes = payload["nodes"][0]["attributes"]
    record = PromptTSGRecord.model_validate(payload)
    payload["nodes"].clear()
    payload["shadow"]["graph.node_count"] = 999
    input_attributes["evidence_digest"] = "changed"

    assert len(record.nodes) == 1
    assert record.shadow["graph.node_count"] == 1
    assert record.nodes[0].attributes["evidence_digest"] == "c" * 64
    with pytest.raises(TypeError):
        record.nodes[0].attributes["new"] = True
    with pytest.raises(TypeError):
        record.shadow["new"] = True


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (
            TSGNode,
            {
                "node_id": "n_" + "a" * 64,
                "node_type": "source",
                "label": "user_input",
            },
        ),
        (
            TSGEdge,
            {
                "edge_id": "e_" + "b" * 64,
                "src": "n_" + "a" * 64,
                "dst": "n_" + "a" * 64,
                "edge_type": "related_to",
            },
        ),
    ],
)
def test_tsg_node_and_edge_freeze_omitted_default_attributes(model_type, payload) -> None:
    value = model_type.model_validate(payload)

    with pytest.raises(TypeError):
        value.attributes["nested"] = {"x": 1}


def test_prompt_tsg_v2_validation_and_repr_surfaces_hide_evidence() -> None:
    secret = "PROMPT-EVIDENCE-DO-NOT-LEAK"
    payload = _minimal_prompt_tsg()
    payload["nodes"][0]["attributes"] = {"evidence": secret}
    record = PromptTSGRecord.model_validate(payload)
    assert secret not in repr(record)
    assert secret not in repr(record.nodes[0])

    payload["nodes"][0]["attributes"] = {"nested": {"secret": secret}}
    with pytest.raises(ValidationError) as exc_info:
        PromptTSGRecord.model_validate(payload)
    rendered = str(exc_info.value) + repr(exc_info.value.errors(include_input=True))
    assert secret not in rendered
    assert ErrorCode.TSG_INVALID.name in rendered


def test_motif_match_is_strict_frozen_and_bounded() -> None:
    node_ids = tuple(f"n_{index:064x}" for index in range(9))
    edge_ids = tuple(f"e_{index:064x}" for index in range(8))
    match = MotifMatch.model_validate(
        {
            "schema_version": "1.0",
            "motif_id": MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD.value,
            "node_path": node_ids,
            "edge_path": edge_ids,
            "guarded": False,
            "guard_nodes": (),
        }
    )
    assert match.edge_path == edge_ids
    with pytest.raises((TypeError, ValidationError)):
        match.guarded = True

    oversized = match.model_dump(mode="python")
    oversized["node_path"] = (*node_ids, f"n_{9:064x}")
    oversized["edge_path"] = (*edge_ids, f"e_{8:064x}")
    with pytest.raises(ValidationError):
        MotifMatch.model_validate(oversized)


def test_prompt_tsg_v2_forbids_unknown_fields_and_non_strict_scalars() -> None:
    payload = _minimal_prompt_tsg()
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate({**payload, "features": {}})

    payload["shadow"] = {"graph.node_count": Decimal("1.0")}
    with pytest.raises(ValidationError):
        PromptTSGRecord.model_validate(payload)
