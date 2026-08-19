from __future__ import annotations

import pytest

from secaware.exploratory.independent_validation_contracts import _requirement_records


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
