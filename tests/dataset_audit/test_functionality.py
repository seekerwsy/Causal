from __future__ import annotations

from pathlib import Path
import sys

from secaware.dataset_audit.adapters import adapt_record
from secaware.dataset_audit.functionality import (
    FunctionalAssessment,
    SmokeLimits,
    classify_functional_evidence,
    smoke_validate_existing_contract,
)
from secaware.dataset_audit.schema import FunctionalState


FIXTURES = Path(__file__).parent / "fixtures" / "functional_contracts"


def _record(raw: dict):
    return adapt_record(
        source_id="fixture",
        source_path=Path("fixture.jsonl"),
        line_number=1,
        raw=raw,
    )


def test_classification_preserves_all_functional_evidence_states(tmp_path: Path) -> None:
    present = classify_functional_evidence(
        _record({"prompt": "Implement add.", "test": "assert add(1, 2) == 3"}),
        tmp_path,
    )
    reference = classify_functional_evidence(
        _record({"prompt": "Implement add.", "test_path": "tests/test_add.py"}),
        tmp_path,
    )
    absent = classify_functional_evidence(_record({"prompt": "Implement add."}), tmp_path)
    conflicting = classify_functional_evidence(
        _record({"prompt": "Implement add."}).model_copy(
            update={"functional_state": FunctionalState.CONFLICTING}
        ),
        tmp_path,
    )

    assert present.state is FunctionalState.PRESENT_UNVALIDATED
    assert reference.state is FunctionalState.REFERENCE_ONLY
    assert absent.state is FunctionalState.ABSENT
    assert conflicting.state is FunctionalState.CONFLICTING


def test_controlled_allowlisted_contract_can_be_smoke_validated() -> None:
    assessment = FunctionalAssessment(
        state=FunctionalState.PRESENT_UNVALIDATED,
        harness="python_script_v1",
        contract_path=(FIXTURES / "passing_contract.py").resolve(),
        trusted_contract_root=FIXTURES.resolve(),
        execution_allowed=True,
        evidence_fields=("test_path",),
        diagnostics=(),
    )

    result = smoke_validate_existing_contract(
        assessment,
        SmokeLimits(python_executable=Path(sys.executable), timeout_seconds=5.0),
    )

    assert result.state is FunctionalState.EXECUTABLE_VALIDATED
    assert result.diagnostics == ("contract smoke validation passed",)


def test_unknown_harness_is_diagnostic_and_never_executed() -> None:
    assessment = FunctionalAssessment(
        state=FunctionalState.PRESENT_UNVALIDATED,
        harness="unknown_harness",
        contract_path=(FIXTURES / "passing_contract.py").resolve(),
        trusted_contract_root=FIXTURES.resolve(),
        execution_allowed=True,
        evidence_fields=("test_path",),
        diagnostics=(),
    )

    result = smoke_validate_existing_contract(
        assessment,
        SmokeLimits(python_executable=Path(sys.executable), timeout_seconds=5.0),
    )

    assert result.state is FunctionalState.PRESENT_UNVALIDATED
    assert result.diagnostics == ("unsupported functional harness",)


def test_failed_contract_is_diagnostic_not_a_model_outcome() -> None:
    assessment = FunctionalAssessment(
        state=FunctionalState.PRESENT_UNVALIDATED,
        harness="python_script_v1",
        contract_path=(FIXTURES / "failing_contract.py").resolve(),
        trusted_contract_root=FIXTURES.resolve(),
        execution_allowed=True,
        evidence_fields=("test_path",),
        diagnostics=(),
    )

    result = smoke_validate_existing_contract(
        assessment,
        SmokeLimits(python_executable=Path(sys.executable), timeout_seconds=5.0),
    )

    assert result.state is FunctionalState.PRESENT_UNVALIDATED
    assert result.diagnostics == ("contract smoke validation failed: backend_failure",)


def test_path_outside_trusted_root_is_not_executed(tmp_path: Path) -> None:
    assessment = FunctionalAssessment(
        state=FunctionalState.PRESENT_UNVALIDATED,
        harness="python_script_v1",
        contract_path=(FIXTURES / "passing_contract.py").resolve(),
        trusted_contract_root=tmp_path.resolve(),
        execution_allowed=True,
        evidence_fields=("test_path",),
        diagnostics=(),
    )

    result = smoke_validate_existing_contract(
        assessment,
        SmokeLimits(python_executable=Path(sys.executable), timeout_seconds=5.0),
    )

    assert result.state is FunctionalState.PRESENT_UNVALIDATED
    assert result.diagnostics == ("contract path is outside trusted root",)
