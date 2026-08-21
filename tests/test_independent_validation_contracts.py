from __future__ import annotations

import pytest

from secaware.exploratory.independent_validation_contracts import (
    _TASK_FAMILY_V2,
    _requirement_records,
)
from secaware.tsg.feature_catalog import prompt_feature_spec


def _requirement(*, criterion: str, quote: str) -> dict[str, str]:
    return {
        "requirement_id": "req_behavior",
        "kind": "behavior",
        "criterion": criterion,
        "prompt_evidence_quote": quote,
    }


def test_contract_requirement_requires_verbatim_prompt_evidence() -> None:
    records = _requirement_records(
        [_requirement(criterion="Return the requested item.", quote="return the item")],
        source_prompt="Implement a function that will return the item.",
    )
    assert records[0].requirement_id == "req_behavior"

    with pytest.raises(ValueError):
        _requirement_records(
            [_requirement(criterion="Return the requested item.", quote="missing quote")],
            source_prompt="Implement a function that will return the item.",
        )


@pytest.mark.parametrize(
    "criterion",
    [
        "The target patch must be present.",
        "The implementation must be secure.",
        "Prevent the CWE-89 vulnerability.",
        "Avoid SQL injection.",
    ],
)
def test_contract_requirement_rejects_mechanism_or_label_leakage(criterion: str) -> None:
    with pytest.raises(ValueError):
        _requirement_records(
            [_requirement(criterion=criterion, quote="return the item")],
            source_prompt="Implement a function that will return the item.",
        )


def test_v2_task_families_match_existing_feature_catalog_coordinates() -> None:
    assert _TASK_FAMILY_V2 == {
        "CWE-78": "command_execution",
        "CWE-89": "sql_query",
        "CWE-502": "deserialization",
        "CWE-328": "message_hashing",
        "CWE-338": "security_random_generation",
    }
    targets = {
        "CWE-78": "safety.safe_subprocess",
        "CWE-89": "safety.sql_parameterization",
        "CWE-502": "safety.safe_deserialization",
        "CWE-328": "safety.collision_resistant_hash",
        "CWE-338": "safety.cryptographic_randomness",
    }
    for cwe, feature_id in targets.items():
        spec = prompt_feature_spec(feature_id)
        assert cwe in spec.applicable_cwes
        assert _TASK_FAMILY_V2[cwe] in spec.applicable_task_families
