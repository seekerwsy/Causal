from __future__ import annotations

import json
from pathlib import Path

import pytest

from secaware.functional_audit import prepare_functional_audit_pilot


def _record(index: int, cwe: str) -> dict[str, object]:
    digest = f"{index:064x}"
    return {
        "schema_version": "1.0",
        "coordinate": {
            "source_id": "cyberseceval_instruct_v2",
            "relative_path": "instruct-v2.json",
            "line_number": index + 1,
            "record_id": str(index),
        },
        "prompt": f"Write a Python function for task {index}.",
        "language": "python",
        "cwe_ids": [cwe],
        "exact_prompt_sha256": digest,
        "neutrality": "CANDIDATE_NEUTRAL",
        "cluster_independence_resolved": True,
        "task_cluster_id": f"cluster-{index:020x}",
    }


def _source(path: Path) -> None:
    cwes = (
        "CWE-120",
        "CWE-680",
        "CWE-121",
        "CWE-78",
        "CWE-95",
        "CWE-89",
        "CWE-94",
        "CWE-338",
        "CWE-798",
        "CWE-327",
        "CWE-328",
        "CWE-330",
        "CWE-807",
        "CWE-502",
        "CWE-918",
        "CWE-676",
    )
    records = [_record(index, cwe) for index, cwe in enumerate(cwes, 1)]
    path.write_text(
        "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in records),
        encoding="utf-8",
    )


def test_functional_audit_selection_is_deterministic_and_never_overwrites(tmp_path: Path) -> None:
    source = tmp_path / "record-audit.jsonl"
    _source(source)
    config = {"seed": 7, "tasks_per_cwe": 1}
    first = tmp_path / "run-a"
    second = tmp_path / "run-b"

    first_report = prepare_functional_audit_pilot(
        source_record_audit=source,
        run_dir=first,
        config=config,
        command_argv=("secaware", "prepare-functional-audit"),
    )
    prepare_functional_audit_pilot(
        source_record_audit=source,
        run_dir=second,
        config=config,
        command_argv=("secaware", "prepare-functional-audit"),
    )

    assert first_report["status"] == "PACKETS_READY"
    assert first_report["counts"]["packets"] == 16
    assert (first / "packets.jsonl").read_bytes() == (second / "packets.jsonl").read_bytes()
    with pytest.raises(FileExistsError):
        prepare_functional_audit_pilot(
            source_record_audit=source,
            run_dir=first,
            config=config,
            command_argv=("secaware", "prepare-functional-audit"),
        )


def test_published_pilot_has_complete_consistent_a_b_contract_coverage() -> None:
    from secaware.functional_judge.schema import (
        FunctionalAuditDecisionRecord,
        TaskFunctionalContractRecord,
    )
    from secaware.io.jsonl import read_jsonl

    root = Path(__file__).resolve().parents[1] / "data" / "functional-audit" / "pilot-v1"
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    decisions = read_jsonl(
        root / "audit-decisions.jsonl", FunctionalAuditDecisionRecord, required=True
    )
    contracts = read_jsonl(root / "contracts.jsonl", TaskFunctionalContractRecord, required=True)

    assert report["status"] == "CONTRACTS_READY"
    assert report["counts"] == {
        "audit_decisions": 96,
        "contracts": 48,
        "cwe_scopes": 16,
        "failed": 0,
        "packets": 48,
        "pending": 0,
    }
    assert len(decisions) == 96
    assert len(contracts) == 48
    assert all(contract.audit_pass_ids == ("A", "B") for contract in contracts)
