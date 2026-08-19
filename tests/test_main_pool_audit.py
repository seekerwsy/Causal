from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.functional_audit.main_pool import (
    MAIN_CWE_ORDER,
    MAIN_POOL_AUDIT_OUTPUT_SCHEMA,
    MainPoolAuditResponse,
    _response_for_prompt,
    prepare_main_pool_audit,
    run_main_pool_audit,
)
from secaware.functional_audit.reconcile import reconcile_main_pool_audit
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
        payload = json.loads(self.response)
        if payload["requirements"][0]["prompt_evidence_quote"] == "__EVIDENCE_SEGMENT__":
            request = json.loads(request_bytes)
            payload["requirements"][0]["prompt_evidence_quote"] = request[
                "prompt_evidence_segments"
            ][0]["text"]
        return json.dumps(payload, separators=(",", ":")).encode()


class FirstResponseInvalidTransport(FakeTransport):
    def complete(self, request_bytes: bytes, policy: StructuredLLMPolicy) -> bytes:
        self.calls.append((request_bytes, policy))
        payload = json.loads(self.response)
        request = json.loads(request_bytes)
        payload["requirements"][0]["prompt_evidence_quote"] = (
            "not in the registered prompt"
            if len(self.calls) == 1
            else request["prompt_evidence_segments"][0]["text"]
        )
        return json.dumps(payload, separators=(",", ":")).encode()


def _accepted_response(quote: str = "__EVIDENCE_SEGMENT__") -> bytes:
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
            "provider_packet_fields": [
                "packet_id",
                "language",
                "finite_profile_scope",
                "prompt",
                "blindness",
            ],
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
    transport = FakeTransport(_accepted_response("Write"))

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
    decisions = [
        json.loads(line)
        for line in (tmp_path / "live" / "decisions.jsonl").read_text().splitlines()
    ]
    assert all(item["evidence_quote_expansions"] == 1 for item in decisions)
    assert all(item["semantic_field_normalizations"] == 0 for item in decisions)
    progress = [
        json.loads(line) for line in (tmp_path / "live" / "progress.jsonl").read_text().splitlines()
    ]
    assert len(progress) == 5
    assert progress[-1]["remaining"] == 0
    request = json.loads(transport.calls[0][0])
    assert "cwe" not in request["packet"]
    assert "source_id" not in request["packet"]
    assert request["packet"]["blindness"] == {
        "generated_code_withheld": True,
        "intervention_arm_withheld": True,
        "model_identity_withheld": True,
        "oracle_label_withheld": True,
        "outcomes_withheld": True,
    }
    segments = [item["text"] for item in request["prompt_evidence_segments"]]
    assert (
        request["response_contract"]["properties"]["requirements"]["items"]["properties"][
            "prompt_evidence_quote"
        ]["enum"]
        == segments
    )


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


def test_response_parser_deterministically_recomputes_eligibility_fields() -> None:
    payload = json.loads(_accepted_response("Write."))
    payload["eligible"] = False
    payload["reason_code"] = "outside_profile"

    response, expansions, normalizations = _response_for_prompt(
        json.dumps(payload).encode(),
        "Write.",
        ("Write.",),
    )

    assert response.eligible is True
    assert response.reason_code.value == "accepted"
    assert expansions == 0
    assert normalizations == 2


def test_audit_response_accepts_semantically_valid_noncanonical_order() -> None:
    payload = json.loads(_accepted_response())
    payload["requirements"] = [
        {
            "requirement_id": "req_z_output",
            "kind": "behavior",
            "criterion": "Return the requested result.",
            "prompt_evidence_quote": "Write",
        },
        {
            "requirement_id": "req_a_interface",
            "kind": "interface",
            "criterion": "Define the requested function.",
            "prompt_evidence_quote": "Write",
        },
    ]
    payload["environment_dependencies"] = ["z-runtime", "a-filesystem"]

    response = MainPoolAuditResponse.model_validate(payload)

    assert [item.requirement_id for item in response.requirements] == [
        "req_z_output",
        "req_a_interface",
    ]


def test_provider_contract_exposes_nested_requirement_enums() -> None:
    requirement = MAIN_POOL_AUDIT_OUTPUT_SCHEMA["properties"]["requirements"]["items"]

    assert requirement["properties"]["requirement_id"]["pattern"].startswith("^req_")
    assert requirement["properties"]["kind"]["enum"] == [
        "interface",
        "behavior",
        "input_output",
        "side_effect",
        "error_handling",
        "environment",
    ]


def test_reconciliation_revalidates_retained_responses_and_applies_explicit_override(
    tmp_path: Path,
) -> None:
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
            "maximum_provider_calls": 10,
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
    source_run = tmp_path / "source-run"
    source_report = run_main_pool_audit(
        prepared_dir=prepared,
        live_config_path=live_config,
        run_dir=source_run,
        command_argv=("run",),
        transport=FirstResponseInvalidTransport(_accepted_response()),
    )
    assert source_report["counts"]["completed"] == 9
    assert source_report["counts"]["errors"] == 1

    first_response = json.loads((source_run / "responses.jsonl").read_text().splitlines()[0])
    second_response = json.loads((source_run / "responses.jsonl").read_text().splitlines()[1])
    packets = {
        row["packet_id"]: row
        for row in (
            json.loads(line)
            for line in (prepared / "candidate-packets.jsonl").read_text().splitlines()
        )
    }
    first_packet = packets[first_response["packet_id"]]
    second_packet = packets[second_response["packet_id"]]
    override_payload = json.loads(_accepted_response(first_packet["prompt"]))
    semantic_override_payload = json.loads(_accepted_response(second_packet["prompt"]))
    semantic_override_payload.update(
        {
            "eligible": False,
            "operation_opportunity": False,
            "reason_code": "no_target_operation",
            "rationale": "Manual review found no target operation in the source prompt.",
        }
    )
    overrides = tmp_path / "overrides.jsonl"
    _write_jsonl(
        overrides,
        [
            {
                "schema_version": "1.0",
                "record_id": first_packet["record_id"],
                "reviewer": "codex-primary",
                "review_rationale": "The retained response used a non-verbatim evidence quote.",
                "audit": override_payload,
            },
            {
                "schema_version": "1.0",
                "record_id": second_packet["record_id"],
                "reviewer": "codex-primary",
                "override_mode": "semantic_adjudication",
                "review_rationale": "The parsed proposal requires a semantic correction.",
                "audit": semantic_override_payload,
            },
        ],
    )

    report = reconcile_main_pool_audit(
        prepared_dir=prepared,
        source_run_dirs=(source_run,),
        output_dir=tmp_path / "reconciled",
        command_argv=("reconcile",),
        overrides_path=overrides,
    )

    assert report["status"] == "MAIN_POOL_AUDIT_RECONCILED"
    assert report["counts"] == {
        "prepared_packets": 10,
        "source_responses": 10,
        "decisions": 10,
        "eligible": 9,
        "unresolved": 0,
        "overrides": 2,
        "provider_calls": 0,
    }
