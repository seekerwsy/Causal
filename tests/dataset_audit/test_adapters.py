from __future__ import annotations

from pathlib import Path

from secaware.dataset_audit.adapters import adapt_record
from secaware.dataset_audit.schema import CweEvidence, FunctionalState


def _adapt(source_id: str, raw: dict) -> object:
    return adapt_record(
        source_id=source_id,
        source_path=Path(f"{source_id}.jsonl"),
        line_number=7,
        raw=raw,
    )


def test_adapter_extracts_explicit_cwe_and_source_coordinate() -> None:
    record = _adapt(
        "securityeval",
        {"ID": "task-9", "Prompt": "Implement a query function.", "CWE": "CWE-89"},
    )

    assert record.coordinate.source_id == "securityeval"
    assert record.coordinate.line_number == 7
    assert record.coordinate.record_id == "task-9"
    assert record.prompt == "Implement a query function."
    assert record.cwe_ids == ("CWE-89",)
    assert record.cwe_evidence is CweEvidence.EXPLICIT_FIELD
    assert record.cwe_evidence_spans[0].field == "CWE"


def test_adapter_parses_cwe_from_identifier_only_when_explicit_field_is_absent() -> None:
    record = _adapt(
        "cweval_python",
        {"task_id": "CWE-078_03", "prompt": "Implement a command wrapper."},
    )

    assert record.cwe_ids == ("CWE-78",)
    assert record.cwe_evidence is CweEvidence.SOURCE_ID_PARSE


def test_adapter_marks_conflicting_cwe_evidence_without_guessing() -> None:
    record = _adapt(
        "securityeval",
        {"ID": "CWE-78-case", "Prompt": "Implement a handler.", "CWE": "CWE-89"},
    )

    assert record.cwe_ids == ("CWE-78", "CWE-89")
    assert record.cwe_evidence is CweEvidence.CONFLICTING


def test_adapter_preserves_missing_prompt_as_unresolved_data() -> None:
    record = _adapt("mbpp", {"task_id": 4, "text": "   "})

    assert record.prompt is None
    assert record.exact_prompt_sha256 is None
    assert record.normalized_prompt_sha256 is None


def test_adapter_records_language_and_existing_functional_contract_evidence() -> None:
    record = _adapt(
        "humaneval_plus",
        {
            "task_id": "HumanEval/1",
            "prompt": "def add(a, b):\n",
            "language": "Python",
            "test": "assert add(1, 2) == 3",
        },
    )

    assert record.language == "python"
    assert record.functional_state is FunctionalState.PRESENT_UNVALIDATED
    assert record.functional_evidence_spans[0].field == "test"


def test_adapter_accepts_cyberseceval_cwe_identifier_as_explicit_evidence() -> None:
    record = _adapt(
        "cyberseceval_discover_adv",
        {
            "prompt_id": "cyberseceval_discover_adv_0000000",
            "prompt": "Implement a candidate generator.",
            "cwe_identifier": "CWE-338",
        },
    )

    assert record.cwe_ids == ("CWE-338",)
    assert record.cwe_evidence is CweEvidence.EXPLICIT_FIELD
    assert record.cwe_evidence_spans[0].field == "cwe_identifier"


def test_adapter_scans_secondary_source_identifier_for_cwe() -> None:
    record = _adapt(
        "securityeval",
        {
            "prompt_id": "securityeval_0000000",
            "ID": "CWE-020_author_1.py",
            "Prompt": "Implement a YAML loader.",
        },
    )

    assert record.coordinate.record_id == "securityeval_0000000"
    assert record.cwe_ids == ("CWE-20",)
    assert record.cwe_evidence is CweEvidence.SOURCE_ID_PARSE
    assert record.cwe_evidence_spans[0].field == "ID"


def test_cweval_file_path_uses_closed_source_mapping() -> None:
    record = _adapt(
        "cweval_python",
        {
            "task_id": "CWEval/95",
            "prompt": "Implement an input validator.",
            "file_path": "core/py/cwe_020_0_task.py",
        },
    )

    assert record.cwe_ids == ("CWE-20",)
    assert record.cwe_evidence is CweEvidence.SOURCE_MAPPING
    assert record.cwe_evidence_spans[0].field == "file_path"


def test_file_path_mapping_does_not_expand_to_unapproved_sources() -> None:
    record = _adapt(
        "apps",
        {
            "id": 1,
            "prompt": "Implement a parser.",
            "file_path": "cwe_078_0_task.py",
        },
    )

    assert record.cwe_ids == ()
    assert record.cwe_evidence is CweEvidence.UNRESOLVED
