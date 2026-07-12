from decimal import Decimal
import math

import pytest
from pydantic import ValidationError

from secaware.errors import ErrorCode
from secaware.schema.tsg import (
    MAX_TSG_ATTRIBUTES,
    MotifId,
    MotifMatch,
    PromptTSGRecord,
    TSGEdge,
    TSGNode,
)


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
                "attributes": {
                    "evidence_start": 0,
                    "evidence_end": 10,
                    "evidence_sha256": "c" * 64,
                },
            }
        ],
        "edges": [
            {
                "edge_id": "e_" + "d" * 64,
                "src": node_id,
                "dst": node_id,
                "edge_type": "related_to",
                "attributes": {},
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


def test_finite_attribute_contract_is_tighter_than_defensive_32_item_gate() -> None:
    payload = _minimal_prompt_tsg()
    approved = payload["nodes"][0]["attributes"]
    assert len(approved) < MAX_TSG_ATTRIBUTES
    PromptTSGRecord.model_validate(payload)

    for count in (32, 33):
        payload["nodes"][0]["attributes"] = {
            f"unreviewed_key_{index}": index for index in range(count)
        }
        with pytest.raises(ValidationError):
            PromptTSGRecord.model_validate(payload)


def test_prompt_tsg_v2_counts_attribute_string_limits_in_utf8_bytes() -> None:
    payload = _minimal_prompt_tsg()
    payload["nodes"][0]["node_type"] = "api"
    payload["nodes"][0]["attributes"] = {"api_name": "界" * 341 + "a"}
    PromptTSGRecord.model_validate(payload)

    payload["nodes"][0]["attributes"] = {"api_name": "界" * 342}
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
    input_attributes["evidence_sha256"] = "changed"

    assert len(record.nodes) == 1
    assert record.shadow["graph.node_count"] == 1
    assert record.nodes[0].attributes["evidence_sha256"] == "c" * 64
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


def test_direct_attribute_and_shadow_reprs_are_structurally_redacted() -> None:
    secret = "PROMPT-EVIDENCE-DO-NOT-LEAK"
    node = TSGNode.model_validate(
        {
            "node_id": "n_" + "a" * 64,
            "node_type": "api",
            "label": "external_api",
            "attributes": {"api_name": secret},
        }
    )
    edge = TSGEdge.model_validate(
        {
            "edge_id": "e_" + "b" * 64,
            "src": node.node_id,
            "dst": node.node_id,
            "edge_type": "related_to",
            "attributes": {"relation_kind": secret},
        }
    )
    payload = _minimal_prompt_tsg()
    payload["shadow"] = {"review.secret": secret}
    record = PromptTSGRecord.model_validate(payload)

    for value in (node.attributes, edge.attributes, record.shadow):
        rendered = repr(value)
        assert secret not in rendered
        assert "<1 items>" in rendered


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (
            TSGNode,
            {
                "node_id": "n_" + "a" * 64,
                "node_type": "source",
                "label": "user_input",
                "attributes": {"unknown": 1},
            },
        ),
        (
            TSGNode,
            {
                "node_id": "n_" + "a" * 64,
                "node_type": "source",
                "label": "user_input",
                "attributes": {"evidence": "raw prompt evidence"},
            },
        ),
        (
            TSGEdge,
            {
                "edge_id": "e_" + "b" * 64,
                "src": "n_" + "a" * 64,
                "dst": "n_" + "a" * 64,
                "edge_type": "flows_to",
                "attributes": {"unknown": 1},
            },
        ),
        (
            TSGEdge,
            {
                "edge_id": "e_" + "b" * 64,
                "src": "n_" + "a" * 64,
                "dst": "n_" + "a" * 64,
                "edge_type": "flows_to",
                "attributes": {"evidence": "raw prompt evidence"},
            },
        ),
    ],
)
def test_node_and_edge_attribute_contracts_reject_unknown_and_raw_evidence(
    model_type, payload
) -> None:
    with pytest.raises(ValidationError):
        model_type.model_validate(payload)


def test_node_and_edge_accept_bounded_prompt_evidence_metadata() -> None:
    evidence = {
        "evidence_start": 2,
        "evidence_end": 7,
        "evidence_sha256": "c" * 64,
        "confidence": 0.75,
    }
    node = TSGNode.model_validate(
        {
            "node_id": "n_" + "a" * 64,
            "node_type": "source",
            "label": "user_input",
            "attributes": evidence,
        }
    )
    edge = TSGEdge.model_validate(
        {
            "edge_id": "e_" + "b" * 64,
            "src": node.node_id,
            "dst": node.node_id,
            "edge_type": "flows_to",
            "attributes": evidence,
        }
    )
    assert node.attributes == evidence
    assert edge.attributes == evidence


@pytest.mark.parametrize(
    "attributes",
    [
        {"evidence_start": -1, "evidence_end": 7, "evidence_sha256": "c" * 64},
        {"evidence_start": 7, "evidence_end": 7, "evidence_sha256": "c" * 64},
        {"evidence_start": 2, "evidence_end": 7, "evidence_sha256": "C" * 64},
        {"evidence_start": True, "evidence_end": 7, "evidence_sha256": "c" * 64},
        {"evidence_start": 2, "evidence_end": 7},
    ],
)
def test_prompt_evidence_metadata_is_complete_strict_ordered_and_hashed(attributes) -> None:
    with pytest.raises(ValidationError):
        TSGNode.model_validate(
            {
                "node_id": "n_" + "a" * 64,
                "node_type": "source",
                "label": "user_input",
                "attributes": attributes,
            }
        )


def test_attribute_structural_overrides_are_type_dependent() -> None:
    api = {
        "node_id": "n_" + "a" * 64,
        "node_type": "api",
        "label": "external_api",
        "attributes": {"api_name": "payments.lookup"},
    }
    TSGNode.model_validate(api)
    with pytest.raises(ValidationError):
        TSGNode.model_validate({**api, "node_type": "source"})

    related = {
        "edge_id": "e_" + "b" * 64,
        "src": "n_" + "a" * 64,
        "dst": "n_" + "a" * 64,
        "edge_type": "related_to",
        "attributes": {"relation_kind": "same_resource"},
    }
    TSGEdge.model_validate(related)
    with pytest.raises(ValidationError):
        TSGEdge.model_validate({**related, "edge_type": "flows_to"})


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (
            TSGNode,
            {
                "node_id": "n_" + "a" * 64,
                "node_type": "source",
                "label": "user_input",
                "attributes": {"confidence": None},
            },
        ),
        (
            TSGNode,
            {
                "node_id": "n_" + "a" * 64,
                "node_type": "api",
                "label": "external_api",
                "attributes": {"api_name": None},
            },
        ),
        (
            TSGEdge,
            {
                "edge_id": "e_" + "b" * 64,
                "src": "n_" + "a" * 64,
                "dst": "n_" + "a" * 64,
                "edge_type": "related_to",
                "attributes": {"relation_kind": None},
            },
        ),
    ],
)
def test_reviewed_attribute_keys_reject_null_values(model_type, payload) -> None:
    with pytest.raises(ValidationError):
        model_type.model_validate(payload)


def test_prompt_tsg_v2_validation_and_repr_surfaces_hide_evidence() -> None:
    secret = "PROMPT-EVIDENCE-DO-NOT-LEAK"
    payload = _minimal_prompt_tsg()
    payload["nodes"][0]["node_type"] = "api"
    payload["nodes"][0]["attributes"] = {"api_name": secret}
    record = PromptTSGRecord.model_validate(payload)
    assert secret not in repr(record)
    assert secret not in repr(record.nodes[0])

    payload["nodes"][0]["attributes"] = {"evidence": {"secret": secret}}
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
