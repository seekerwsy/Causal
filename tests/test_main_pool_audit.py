from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.functional_audit.main_pool import (
    MAIN_CWE_ORDER,
    MainPoolAuditResponse,
    prepare_main_pool_audit,
    run_main_pool_audit,
)
from secaware.llm.structured_transport import StructuredLLMPolicy


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    records: list[dict[str, object]] = []
    assignments: list[dict[str, str]] = []
    for cwe_index, cwe in enumerate(MAIN_CWE_ORDER):
        for split_index, split in enumerate(("discover", "confirm")):
            record_id = str(100 + cwe_index * 2 + split_index)
            cluster_id = f"cluster-{cwe_index}-{split}"
            prompt = f"Write a Python function for {cwe} task {split}."
            records.append(
                {
                    "coordinate": {
                        "source_id": "cyberseceval_instruct_v2",
                        "record_id": record_id,
                    },
                    "language": "python",
                    "neutrality": "CANDIDATE_NEUTRAL",
                    "cluster_independence_resolved": True,
                    "task_cluster_id": cluster_id,
                    "cwe_ids": [cwe, "CWE-999"] if record_id == "100" else [cwe],
                    "exact_prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                    "prompt": prompt,
                }
            )
            assignments.append({"cluster_id": cluster_id, "split": split})
    source = tmp_path / "records.jsonl"
    splits = tmp_path / "splits.jsonl"
    config = tmp_path / "prepare-config.json"
    _write_jsonl(source, records)
    _write_jsonl(splits, [{"seed": 7, "assignments": assignments}])
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "source_id": "cyberseceval_instruct_v2",
            "split_simulation_seed": 7,
            "selection_seed": 11,
            "expected_candidates_by_cwe": {cwe: 2 for cwe in MAIN_CWE_ORDER},
            "quotas_by_split": {"discover": 1, "confirm": 1},
        },
    )
    return source, splits, config


class FakeTransport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.calls: list[tuple[bytes, StructuredLLMPolicy]] = []

    def complete(self, request_bytes: bytes, policy: StructuredLLMPolicy) -> bytes:
        self.calls.append((request_bytes, policy))
        return self.response


def _accepted_response(quote: str = "Write") -> bytes:
    return json.dumps(
        {
            "eligible": True,
            "operation_opportunity": True,
            "profile_compatible": True,
            "weak_mechanism_required": False,
            "judgeability": "semantic_only",
            "requirements": [
                {
                    "requirement_id": "req_task",
                    "kind": "behavior",
                    "criterion": "Implement the requested task.",
                    "prompt_evidence_quote": quote,
                }
            ],
            "environment_dependencies": [],
            "reason_code": "accepted",
            "rationale": "The task states a finite operation and observable behavior.",
        },
        separators=(",", ":"),
    ).encode()


def test_prepare_main_pool_audit_is_zero_call_and_preserves_split_counts(tmp_path: Path) -> None:
    source, splits, config = _inputs(tmp_path)
    run_dir = tmp_path / "prepared"

    report = prepare_main_pool_audit(
        source_record_audit=source,
        split_simulations=splits,
        config_path=config,
        run_dir=run_dir,
        command_argv=("prepare",),
    )

    assert report["status"] == "MAIN_POOL_AUDIT_PACKETS_READY"
    assert report["counts"] == {
        "packets": 10,
        "provider_calls": 0,
        "completed": 0,
        "errors": 0,
        "pending": 10,
    }
    assert all(
        report["candidates_by_cwe_split"][cwe] == {"discover": 1, "confirm": 1}
        for cwe in MAIN_CWE_ORDER
    )
    packets = [
        json.loads(line) for line in (run_dir / "candidate-packets.jsonl").read_text().splitlines()
    ]
    multi_cwe_packet = next(item for item in packets if item["record_id"] == "100")
    assert multi_cwe_packet["source_cwe_ids"] == ["CWE-78", "CWE-999"]


def test_main_pool_audit_canary_calls_once_per_cwe_and_validates_quotes(tmp_path: Path) -> None:
    source, splits, prepare_config = _inputs(tmp_path)
    prepared = tmp_path / "prepared"
    prepare_main_pool_audit(
        source_record_audit=source,
        split_simulations=splits,
        config_path=prepare_config,
        run_dir=prepared,
        command_argv=("prepare",),
    )
    live_config = tmp_path / "live-config.json"
    _write_json(
        live_config,
        {
            "schema_version": "1.0",
            "allow_provider_calls": True,
            "authorization_id": "test-authorization",
            "max_candidates_per_cwe": 1,
            "maximum_provider_calls": 5,
            "llm": {
                "model_id": "judge-model",
                "base_url": "https://example.invalid/v1",
                "api_key_env": "TEST_KEY",
                "timeout_seconds": 30.0,
                "max_attempts": 1,
                "max_response_bytes": 4096,
                "temperature": 0.0,
                "top_p": 1.0,
                "seed": 19,
                "enable_thinking": False,
            },
        },
    )
    transport = FakeTransport(_accepted_response())

    report = run_main_pool_audit(
        prepared_dir=prepared,
        live_config_path=live_config,
        run_dir=tmp_path / "live",
        command_argv=("run",),
        transport=transport,
    )

    assert report["status"] == "MAIN_POOL_AUDIT_COMPLETE"
    assert report["counts"] == {
        "selected_packets": 5,
        "provider_calls": 5,
        "completed": 5,
        "errors": 0,
        "pending": 0,
        "eligible": 5,
    }
    assert len(transport.calls) == 5
    request = json.loads(transport.calls[0][0])
    assert request["packet"]["blindness"] == {
        "generated_code_withheld": True,
        "intervention_arm_withheld": True,
        "model_identity_withheld": True,
        "oracle_label_withheld": True,
        "outcomes_withheld": True,
    }


def test_main_pool_audit_records_non_verbatim_response_as_error(tmp_path: Path) -> None:
    source, splits, prepare_config = _inputs(tmp_path)
    prepared = tmp_path / "prepared"
    prepare_main_pool_audit(
        source_record_audit=source,
        split_simulations=splits,
        config_path=prepare_config,
        run_dir=prepared,
        command_argv=("prepare",),
    )
    live_config = tmp_path / "live-config.json"
    _write_json(
        live_config,
        {
            "schema_version": "1.0",
            "allow_provider_calls": True,
            "authorization_id": "test-authorization",
            "max_candidates_per_cwe": 1,
            "maximum_provider_calls": 5,
            "llm": {
                "model_id": "judge-model",
                "base_url": "https://example.invalid/v1",
                "api_key_env": "TEST_KEY",
                "timeout_seconds": 30.0,
                "max_attempts": 1,
                "max_response_bytes": 4096,
                "temperature": 0.0,
                "top_p": 1.0,
                "seed": 19,
                "enable_thinking": False,
            },
        },
    )

    report = run_main_pool_audit(
        prepared_dir=prepared,
        live_config_path=live_config,
        run_dir=tmp_path / "live",
        command_argv=("run",),
        transport=FakeTransport(_accepted_response("not in any prompt")),
    )

    assert report["status"] == "MAIN_POOL_AUDIT_INCOMPLETE"
    assert report["counts"]["completed"] == 0
    assert report["counts"]["errors"] == 5


def test_audit_response_rejects_inconsistent_eligibility() -> None:
    payload = json.loads(_accepted_response())
    payload["eligible"] = False

    try:
        MainPoolAuditResponse.model_validate(payload)
    except Exception:
        pass
    else:
        raise AssertionError("inconsistent eligibility was accepted")
