from __future__ import annotations

from pathlib import PurePosixPath

from pydantic import ValidationError
import pytest

from secaware.dataset_audit.catalog import LEGACY_SOURCES, cyberseceval_v2_source
from secaware.dataset_audit.schema import (
    CweEvidence,
    DatasetRole,
    FunctionalState,
    NeutralityState,
    RecordAudit,
)


def test_catalog_freezes_exact_legacy_inputs() -> None:
    assert [item.filename for item in LEGACY_SOURCES] == [
        "apps.jsonl",
        "classeval.jsonl",
        "cweval.jsonl",
        "cweval_python.jsonl",
        "cyberseceval_discover_adv.jsonl",
        "cyberseceval_secure_code.jsonl",
        "humaneval.jsonl",
        "humaneval_plus.jsonl",
        "mbpp.jsonl",
        "sallm.jsonl",
        "seccodebench_python.jsonl",
        "securityeval.jsonl",
    ]
    assert len({item.source_id for item in LEGACY_SOURCES}) == len(LEGACY_SOURCES)


def test_cyberseceval_v2_source_is_official_and_pinnable() -> None:
    source = cyberseceval_v2_source()

    assert source.repository == "meta-llama/PurpleLlama"
    assert source.revision == "main"
    assert PurePosixPath(source.relative_path).name == "instruct-v2.json"
    assert source.official_https_url.startswith("https://github.com/meta-llama/PurpleLlama/")


def test_persisted_record_is_strict_and_frozen() -> None:
    with pytest.raises(ValidationError):
        RecordAudit.model_validate({"schema_version": "1.0", "unexpected": True})


def test_audit_vocabularies_are_frozen() -> None:
    assert [item.value for item in CweEvidence] == [
        "EXPLICIT_FIELD",
        "SOURCE_ID_PARSE",
        "SOURCE_MAPPING",
        "CONFLICTING",
        "UNRESOLVED",
    ]
    assert [item.value for item in NeutralityState] == [
        "OBVIOUS_CONFLICT",
        "CANDIDATE_NEUTRAL",
        "UNRESOLVED",
    ]
    assert [item.value for item in FunctionalState] == [
        "EXECUTABLE_VALIDATED",
        "PRESENT_UNVALIDATED",
        "REFERENCE_ONLY",
        "ABSENT",
        "CONFLICTING",
        "UNRESOLVED",
    ]
    assert {item.value for item in DatasetRole} == {
        "PAPER_PRIMARY_CANDIDATE",
        "SECURITY_ONLY_SECONDARY_CANDIDATE",
        "FUNCTIONAL_CALIBRATION",
        "ORACLE_CALIBRATION",
        "EXTRACTOR_OR_TSG_EVALUATION",
        "EXTERNAL_REPLICATION_CANDIDATE",
        "PENDING_CONTRACT_OR_ADJUDICATION",
        "UNUSABLE_UNDER_CURRENT_SCOPE",
    }
