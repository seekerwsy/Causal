from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secaware.exploratory import artifact_integrity, gate_c_live
from secaware.oracle.aggregator import OracleCodeAnalysis
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.profile_decision import extract_python_mechanism_trace
from secaware.schema.oracle import OracleEvaluability, SecurityLabel


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


@pytest.mark.parametrize((("assignments", "tasks")), ((8, 2), (20, 5)))
def test_gate_c_live_bounded_assignment_count(assignments: int, tasks: int) -> None:
    assert gate_c_live._bounded_task_count(assignments) == tasks


def test_gate_c_live_accepts_only_the_frozen_full_population_at_scale() -> None:
    assert gate_c_live._bounded_task_count(204, "all_gate_b_tasks") == 51
    assert gate_c_live._bounded_task_count(168, "all_gate_b_tasks") == 42
    with pytest.raises(ValueError, match="assignment count"):
        gate_c_live._bounded_task_count(200, "all_gate_b_tasks")
    with pytest.raises(ValueError, match="assignment count"):
        gate_c_live._bounded_task_count(204)


@pytest.mark.parametrize(("assignments", "tasks"), ((4, 2), (24, 12)))
def test_gate_c_live_accepts_only_registered_two_arm_development_sizes(
    assignments: int, tasks: int
) -> None:
    assert gate_c_live._bounded_task_count(assignments, "explicit_dev_canary", 2) == tasks
    with pytest.raises(ValueError, match="assignment count"):
        gate_c_live._bounded_task_count(assignments, "explicit_dev_canary", 4)


def test_gate_c_live_reads_arm_contract_from_plan_report_with_legacy_fallback() -> None:
    assert gate_c_live._plan_arm_roles({}) == gate_c_live._LEGACY_ARM_ROLES
    assert (
        gate_c_live._plan_arm_roles(
            {
                "arm_roles": ["target_patch", "noop_rewrite"],
                "arms_per_task": 2,
            }
        )
        == gate_c_live._DEV_CANARY_ARM_ROLES
    )
    with pytest.raises(ValueError, match="arm roles"):
        gate_c_live._plan_arm_roles(
            {
                "arm_roles": ["target_patch", "noop_rewrite"],
                "arms_per_task": 4,
            }
        )


def test_gate_c_live_validates_development_dimensions_for_main_and_recovery_paths() -> None:
    plan_report = {
        "arm_roles": ["target_patch", "noop_rewrite"],
        "arms_per_task": 2,
    }
    assert gate_c_live._validated_plan_dimensions(
        plan_report,
        expected_assignments=24,
        task_selection_policy="explicit_dev_canary",
    ) == (12, gate_c_live._DEV_CANARY_ARM_ROLES)

    with pytest.raises(ValueError, match="development arm protocol"):
        gate_c_live._validated_plan_dimensions(
            plan_report,
            expected_assignments=8,
            task_selection_policy="explicit_bounded_canary",
        )


def test_gate_c_live_report_contract_is_explicit_and_non_scientific() -> None:
    assert gate_c_live._report_contract_fields(
        "explicit_dev_canary", gate_c_live._DEV_CANARY_ARM_ROLES
    ) == {
        "scientific_claim_allowed": False,
        "task_selection_policy": "explicit_dev_canary",
        "arm_roles": ["target_patch", "noop_rewrite"],
        "arms_per_task": 2,
    }


@pytest.mark.parametrize("assignments", (0, 4, 9, 24))
def test_gate_c_live_rejects_unregistered_assignment_count(assignments: int) -> None:
    with pytest.raises(ValueError, match="assignment count"):
        gate_c_live._bounded_task_count(assignments)


def test_gate_c_live_plan_manifest_is_closed_and_authenticated(tmp_path: Path) -> None:
    plan = tmp_path / "plan"
    plan.mkdir()
    report = {
        "schema_version": "1.0",
        "status": "GATE_C_PLAN_COMPLETE",
        "provider_calls_allowed": False,
        "oracle_execution_allowed": False,
        "scientific_claim_allowed": False,
    }
    _write_json(plan / "report.json", report)
    digest = hashlib.sha256((plan / "report.json").read_bytes()).hexdigest()
    _write_json(
        plan / "artifact-manifest.json",
        {
            "schema_version": "1.0",
            "files": [{"path": "report.json", "sha256": digest}],
        },
    )

    assert gate_c_live._verify_plan(plan)["status"] == "GATE_C_PLAN_COMPLETE"
    (plan / "report.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="manifest"):
        gate_c_live._verify_plan(plan)


def test_gate_c_live_plan_manifest_covers_nested_manifest(tmp_path: Path) -> None:
    plan = tmp_path / "plan"
    nested = plan / "nested"
    nested.mkdir(parents=True)
    report = {
        "schema_version": "1.0",
        "status": "GATE_C_PLAN_COMPLETE",
        "provider_calls_allowed": False,
        "oracle_execution_allowed": False,
        "scientific_claim_allowed": False,
    }
    _write_json(plan / "report.json", report)
    _write_json(nested / "artifact-manifest.json", {"nested": True})
    files = tuple(path for path in plan.rglob("*") if path.is_file())
    _write_json(
        plan / "artifact-manifest.json",
        {
            "schema_version": "1.0",
            "files": [
                {
                    "path": path.relative_to(plan).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for path in sorted(files)
            ],
        },
    )

    gate_c_live._verify_plan(plan)
    manifest = json.loads((plan / "artifact-manifest.json").read_text(encoding="utf-8"))
    manifest["files"] = [
        item for item in manifest["files"] if item["path"] != "nested/artifact-manifest.json"
    ]
    _write_json(plan / "replacement.json", manifest)
    (plan / "artifact-manifest.json").write_bytes((plan / "replacement.json").read_bytes())
    (plan / "replacement.json").unlink()
    with pytest.raises(ValueError, match="closure"):
        gate_c_live._verify_plan(plan)


def test_gate_c_live_rejects_a_plan_that_allows_scientific_claims(tmp_path: Path) -> None:
    plan = tmp_path / "plan"
    plan.mkdir()
    _write_json(
        plan / "report.json",
        {
            "schema_version": "1.0",
            "status": "GATE_C_PLAN_COMPLETE",
            "provider_calls_allowed": False,
            "oracle_execution_allowed": False,
            "scientific_claim_allowed": True,
        },
    )
    artifact_integrity.write_closed_manifest_atomic(plan)

    with pytest.raises(ValueError, match="source plan"):
        gate_c_live._verify_plan(plan)


def test_gate_c_live_requires_exact_selection_to_retain_authenticated_randomization(
    tmp_path: Path,
) -> None:
    base = {
        "schema_version": "1.0",
        "status": "GATE_C_PLAN_COMPLETE",
        "provider_calls_allowed": False,
        "oracle_execution_allowed": False,
        "scientific_claim_allowed": False,
        "task_selection_binding": {
            "policy": "exact_content_addressed_v1",
            "selection_id": "selection-v2",
            "selection_sha256": "a" * 64,
            "task_count": 2,
            "unique_task_cluster_count": 2,
            "task_cluster_counts": {"cluster-78": 1, "cluster-89": 1},
            "cwe_task_counts": {"CWE-78": 1, "CWE-89": 1},
        },
        "same_seed_within_task": False,
        "arm_seed_distribution_balanced": False,
    }
    for name, policy, accepted in (
        ("valid", "inherited_gate_a_randomization_v1", True),
        ("forged", "balanced_distinct_seed_slots_v1", False),
    ):
        plan = tmp_path / name
        plan.mkdir()
        _write_json(plan / "report.json", {**base, "seed_assignment_policy": policy})
        artifact_integrity.write_closed_manifest_atomic(plan)
        if accepted:
            assert gate_c_live._verify_plan(plan)["seed_assignment_policy"] == policy
        else:
            with pytest.raises(ValueError, match="selection binding"):
                gate_c_live._verify_plan(plan)


def test_gate_c_live_required_source_plan_contract_binds_exact_v2_plan(
    tmp_path: Path,
) -> None:
    plan = tmp_path / "plan"
    plan.mkdir()
    report = {
        "schema_version": "1.0",
        "status": "GATE_C_PLAN_COMPLETE",
        "provider_calls_allowed": False,
        "oracle_execution_allowed": False,
        "scientific_claim_allowed": False,
        "task_selection_binding": {
            "policy": "exact_content_addressed_v1",
            "selection_id": "selection-v2",
            "selection_sha256": "a" * 64,
            "task_count": 2,
            "unique_task_cluster_count": 2,
            "task_cluster_counts": {"cluster-78": 1, "cluster-89": 1},
            "cwe_task_counts": {"CWE-78": 1, "CWE-89": 1},
        },
        "seed_assignment_policy": "inherited_gate_a_randomization_v1",
        "same_seed_within_task": False,
        "arm_seed_distribution_balanced": False,
    }
    _write_json(plan / "report.json", report)
    artifact_integrity.write_closed_manifest_atomic(plan)
    verified_report = gate_c_live._verify_plan(plan)
    manifest_sha256 = hashlib.sha256((plan / "artifact-manifest.json").read_bytes()).hexdigest()
    contract = {
        "manifest_sha256": manifest_sha256,
        "task_selection_binding_policy": "exact_content_addressed_v1",
        "seed_assignment_policy": "inherited_gate_a_randomization_v1",
    }

    gate_c_live._validate_required_source_plan_contract(
        {"required_source_plan_contract": contract},
        plan_report=verified_report,
        source_plan_manifest_sha256=manifest_sha256,
    )
    gate_c_live._validate_required_source_plan_contract(
        {},
        plan_report={},
        source_plan_manifest_sha256=manifest_sha256,
    )

    attacks = (
        (
            {**contract, "manifest_sha256": "b" * 64},
            verified_report,
        ),
        (
            contract,
            {**verified_report, "task_selection_binding": {"policy": "legacy_unbound_v1"}},
        ),
        (
            contract,
            {**verified_report, "seed_assignment_policy": "balanced_distinct_seed_slots_v1"},
        ),
        (
            {**contract, "unexpected": True},
            verified_report,
        ),
    )
    for attacked_contract, attacked_report in attacks:
        with pytest.raises(ValueError, match="required source plan contract"):
            gate_c_live._validate_required_source_plan_contract(
                {"required_source_plan_contract": attacked_contract},
                plan_report=attacked_report,
                source_plan_manifest_sha256=manifest_sha256,
            )


def test_gate_c_live_unit_manifest_requires_closed_file_set(tmp_path: Path) -> None:
    unit = tmp_path / "unit"
    unit.mkdir()
    _write_json(unit / "status.json", {"status": "COMPLETE"})
    digest = hashlib.sha256((unit / "status.json").read_bytes()).hexdigest()
    _write_json(
        unit / "artifact-manifest.json",
        {
            "schema_version": "1.0",
            "files": [{"path": "status.json", "sha256": digest}],
        },
    )

    gate_c_live._verify_unit_manifest(unit)
    _write_json(unit / "unlisted.json", {"unexpected": True})
    with pytest.raises(ValueError, match="closure"):
        gate_c_live._verify_unit_manifest(unit)


def test_gate_c_live_root_unit_manifest_covers_nested_manifest(tmp_path: Path) -> None:
    unit = tmp_path / "unit"
    nested = unit / "transport"
    nested.mkdir(parents=True)
    _write_json(unit / "status.json", {"status": "COMPLETE"})
    _write_json(nested / "artifact-manifest.json", {"nested": True})

    gate_c_live._unit_manifest(unit)

    manifest = gate_c_live._verify_unit_manifest(unit)
    assert "transport/artifact-manifest.json" in {item["path"] for item in manifest["files"]}


def test_atomic_manifest_publish_never_clobbers_a_racing_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _write_json(root / "evidence.json", {"preserved": True})
    target = root / "artifact-manifest.json"
    competitor = b'{"competitor":true}\n'
    real_link = artifact_integrity.os.link

    def racing_link(source: Path, destination: Path) -> None:
        Path(destination).write_bytes(competitor)
        real_link(source, destination)

    monkeypatch.setattr(artifact_integrity.os, "link", racing_link)

    with pytest.raises(FileExistsError):
        artifact_integrity.write_closed_manifest_atomic(root)
    assert target.read_bytes() == competitor
    assert not tuple(root.glob(".*.tmp"))


def test_functional_judge_transport_persists_exact_request_and_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeTransport:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def complete(self, request: bytes, _policy: object) -> bytes:
            assert request == b'{"request":1}'
            return b'{"response":1}'

    monkeypatch.setattr(gate_c_live, "OpenAICompatibleStructuredTransport", FakeTransport)
    recorder = gate_c_live._RecordingStructuredTransport(
        base_url="https://example.invalid/v1",
        api_key_env="TEST_API_KEY",
        system_template="test",
    )
    destination = tmp_path / "judge"
    recorder.bind(destination)

    assert recorder.complete(b'{"request":1}', object()) == b'{"response":1}'
    assert (destination / "request.json").read_bytes() == b'{"request":1}\n'
    assert (destination / "response.json").read_bytes() == b'{"response":1}\n'
    metadata = json.loads((destination / "transport.json").read_text(encoding="utf-8"))
    assert metadata["attempts"] == 1


def test_generation_transport_persists_exact_request_and_response(tmp_path: Path) -> None:
    recorder = gate_c_live._RecordingGenerationTransport()
    destination = tmp_path / "generation"
    recorder.bind(destination)
    payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": "return code"}],
        "seed": 7,
    }
    response = {
        "model": "local-model",
        "choices": [{"message": {"content": "print(1)"}, "finish_reason": "stop"}],
    }

    recorder("request_1", 1, payload, response, None)

    assert json.loads((destination / "request.json").read_text(encoding="utf-8")) == payload
    assert json.loads((destination / "response.json").read_text(encoding="utf-8")) == response
    metadata = json.loads((destination / "transport.json").read_text(encoding="utf-8"))
    assert metadata["request_id"] == "request_1"
    assert metadata["attempt"] == 1
    assert metadata["transport_error"] is False


def test_oracle_analyzer_runner_persists_output_before_adapter_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = (b'{"semgrep":true}', b'{"bandit":true}')

    def run(
        _argv: object,
        **_kwargs: object,
    ) -> gate_c_live.AnalyzerProcessResult:
        payload = outputs[run.calls]
        run.calls += 1
        return gate_c_live.AnalyzerProcessResult(
            returncode=0,
            stdout=payload,
            argv_sha256=str(run.calls) * 64,
        )

    run.calls = 0
    monkeypatch.setattr(gate_c_live, "run_analyzer_process", run)
    recorder = gate_c_live._RecordingAnalyzerRunner()
    recorder.bind(tmp_path / "oracle")

    recorder(
        ("semgrep",), cwd=tmp_path, timeout_seconds=1, max_stdout_bytes=100, max_stderr_bytes=100
    )
    recorder(
        ("bandit",), cwd=tmp_path, timeout_seconds=1, max_stdout_bytes=100, max_stderr_bytes=100
    )
    recorder.finish()

    assert (tmp_path / "oracle" / "call-001-semgrep" / "stdout.bin").read_bytes() == outputs[0]
    assert (tmp_path / "oracle" / "call-002-bandit" / "stdout.bin").read_bytes() == outputs[1]
    assert json.loads((tmp_path / "oracle" / "session.json").read_text())["calls"] == 2


def test_oracle_repair_selects_a_failed_remaining_unit_after_completed_pilot() -> None:
    assert (
        gate_c_live._repair_assignment_id(
            {"pilot", "completed"},
            {"failed_remaining"},
            "pilot",
        )
        == "failed_remaining"
    )

    with pytest.raises(ValueError, match="completed or failed pilot"):
        gate_c_live._repair_assignment_id(set(), {"failed_remaining"}, "pilot")
    with pytest.raises(ValueError, match="exactly one failed"):
        gate_c_live._repair_assignment_id({"pilot"}, {"failed_a", "failed_b"}, "pilot")


def test_remaining_phase_history_allocates_non_overwriting_attempts(tmp_path: Path) -> None:
    assert gate_c_live._next_remaining_attempt(tmp_path) == 1
    _write_json(tmp_path / "command-remaining.json", {"argv": []})
    assert gate_c_live._next_remaining_attempt(tmp_path) == 2
    _write_json(tmp_path / "command-remaining-002.json", {"argv": []})
    assert gate_c_live._next_remaining_attempt(tmp_path) == 3

    (tmp_path / "command-remaining-002.json").rename(tmp_path / "command-remaining-003.json")
    with pytest.raises(ValueError, match="phase history"):
        gate_c_live._next_remaining_attempt(tmp_path)


def test_invalid_single_pass_judge_response_becomes_provenance_bound_unknown(
    tmp_path: Path,
) -> None:
    transport = tmp_path / "functional-judge-transport"
    transport.mkdir()
    request = b'{"request":1}'
    response = b'{"schema_invalid_but_preserved":true}'
    (transport / "request.json").write_bytes(request + b"\n")
    (transport / "response.json").write_bytes(response + b"\n")
    _write_json(
        transport / "transport.json",
        {
            "attempts": 1,
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "response_sha256": hashlib.sha256(response).hexdigest(),
        },
    )

    outcome, diagnostic = gate_c_live._invalid_judge_unknown_outcome(
        unit_dir=tmp_path,
        assignment_id="assignment_" + "1" * 64,
        contract_id="functional_contract_" + "2" * 64,
        evaluator_policy_sha256="3" * 64,
    )

    assert outcome.status.value == "unknown"
    assert diagnostic["functional_status"] == "unknown"
    assert diagnostic["provider_attempts"] == 1
    assert diagnostic["additional_provider_attempts"] == 0


def test_gate_c_live_remaining_requires_an_authorization_only_delta() -> None:
    stored_base = {
        "schema_version": "1.0",
        "gate_c_live_id": ("randomized-exploratory-gate-c-live-cwe78-cwe89-qwen25-coder-7b-v1"),
        "scale_up_allowed": False,
        "expected_assignments": 8,
    }
    authorized = {
        **stored_base,
        "scale_up_allowed": True,
        "scale_up_authorization_id": "user-approved-remaining-20260817-v1",
        "scale_up_authorization_scope": "remaining_assignments_only",
    }

    gate_c_live._validate_scale_up_authorization(
        authorized, mode="remaining", stored_base=stored_base
    )

    changed = {**authorized, "expected_assignments": 9}
    with pytest.raises(ValueError, match="changed the frozen pilot config"):
        gate_c_live._validate_scale_up_authorization(
            changed, mode="remaining", stored_base=stored_base
        )

    with pytest.raises(ValueError, match="authorization failed"):
        gate_c_live._validate_scale_up_authorization(
            stored_base, mode="remaining", stored_base=stored_base
        )

    five_cwe = {
        **stored_base,
        "gate_c_live_id": ("randomized-exploratory-gate-c-live-five-cwe-qwen25-coder-7b-v1"),
        "expected_assignments": 20,
        "scale_up_allowed": True,
        "scale_up_authorization_id": "user-approved-five-cwe-outcome-pilot-20260818-v1",
        "scale_up_authorization_scope": "remaining_assignments_only",
    }
    frozen_five_cwe = {
        key: value
        for key, value in five_cwe.items()
        if key not in {"scale_up_authorization_id", "scale_up_authorization_scope"}
    }
    frozen_five_cwe["scale_up_allowed"] = False
    gate_c_live._validate_scale_up_authorization(
        five_cwe,
        mode="remaining",
        stored_base=frozen_five_cwe,
    )

    main_prompt = {
        **stored_base,
        "gate_c_live_id": "gate-c-main-prompt-canary-live-qwen25-coder-7b-v1",
        "expected_assignments": 20,
        "scale_up_allowed": True,
        "scale_up_authorization_id": ("user-approved-main-prompt-outcome-canary-20260818-v1"),
        "scale_up_authorization_scope": "remaining_assignments_only",
    }
    frozen_main_prompt = {
        key: value
        for key, value in main_prompt.items()
        if key not in {"scale_up_authorization_id", "scale_up_authorization_scope"}
    }
    frozen_main_prompt["scale_up_allowed"] = False
    gate_c_live._validate_scale_up_authorization(
        main_prompt,
        mode="remaining",
        stored_base=frozen_main_prompt,
    )

    randomized_main = {
        **stored_base,
        "gate_c_live_id": "randomized-discovery-gate-c-main-live-qwen7b-v1",
        "expected_assignments": 204,
        "task_selection_policy": "all_gate_b_tasks",
        "scale_up_allowed": True,
        "scale_up_authorization_id": (
            "user-approved-five-cwe-randomized-discovery-main-20260818-v1"
        ),
        "scale_up_authorization_scope": "remaining_assignments_only",
    }
    frozen_randomized_main = {
        key: value
        for key, value in randomized_main.items()
        if key not in {"scale_up_authorization_id", "scale_up_authorization_scope"}
    }
    frozen_randomized_main["scale_up_allowed"] = False
    gate_c_live._validate_scale_up_authorization(
        randomized_main,
        mode="remaining",
        stored_base=frozen_randomized_main,
    )


def test_minimal_validation_remaining_authorization_id_is_exact() -> None:
    stored_base = {
        "schema_version": "1.0",
        "gate_c_live_id": "minimal-validation-dev-canary-full-live-qwen7b-v1",
        "task_selection_policy": "explicit_dev_canary",
        "scale_up_allowed": False,
        "expected_assignments": 24,
    }
    authorized = {
        **stored_base,
        "scale_up_allowed": True,
        "scale_up_authorization_id": ("user-approved-minimal-validation-dev-canary-20260820-v1"),
        "scale_up_authorization_scope": "remaining_assignments_only",
    }

    gate_c_live._validate_scale_up_authorization(
        authorized,
        mode="remaining",
        stored_base=stored_base,
    )

    rejected = {**authorized, "scale_up_authorization_id": "user-approved-minimal-validation"}
    with pytest.raises(ValueError, match="authorization failed"):
        gate_c_live._validate_scale_up_authorization(
            rejected,
            mode="remaining",
            stored_base=stored_base,
        )

    cross_experiment = {
        **authorized,
        "scale_up_authorization_id": "user-approved-remaining-20260817-v1",
    }
    with pytest.raises(ValueError, match="authorization failed"):
        gate_c_live._validate_scale_up_authorization(
            cross_experiment,
            mode="remaining",
            stored_base=stored_base,
        )


def test_minimal_validation_v2_micro_live_configs_are_frozen_and_fail_closed() -> None:
    root = Path(__file__).resolve().parents[1]
    config_dir = root / "configs" / "minimal-validation"
    base = json.loads(
        (config_dir / "dev-canary-micro-python-comment-live-v2.json").read_text(encoding="utf-8")
    )
    remaining = json.loads(
        (config_dir / "dev-canary-micro-python-comment-live-remaining-v2.json").read_text(
            encoding="utf-8"
        )
    )
    live_id = "minimal-validation-dev-canary-micro-python-comment-live-qwen7b-v2"
    authorization_id = (
        "user-approved-minimal-validation-dev-canary-micro-python-comment-20260821-v2"
    )
    pilot_id = "assignment_05867d4b65d75f77bf167c465b9807ddfca2210049898c466aa82693c5b2f66e"
    plan_manifest_sha256 = "9e38163e2401d5a0b8ab81bead0c30048bd58bf367f9f84fd6e7a8c40f5664bf"
    contract = {
        "manifest_sha256": plan_manifest_sha256,
        "task_selection_binding_policy": "exact_content_addressed_v1",
        "seed_assignment_policy": "inherited_gate_a_randomization_v1",
    }

    assert base == {
        "schema_version": "1.0",
        "gate_c_live_id": live_id,
        "source_plan_dir": "runs/minimal-validation/dev-canary-micro-python-comment-plan-v2",
        "required_source_plan_contract": contract,
        "task_selection_policy": "explicit_dev_canary",
        "pilot_assignment_id": pilot_id,
        "expected_assignments": 4,
        "maximum_generation_provider_attempts": 4,
        "maximum_functional_judge_provider_attempts": 4,
        "require_pilot_before_remaining": True,
        "fail_fast": True,
        "oracle_coordinate_blinding": True,
        "zero_finding_interpretation": "profile_scoped_decision",
        "scientific_claim_allowed": False,
        "scale_up_allowed": False,
    }
    expected_remaining = {
        **base,
        "scale_up_allowed": True,
        "scale_up_authorization_id": authorization_id,
        "scale_up_authorization_scope": "remaining_assignments_only",
    }
    assert remaining == expected_remaining
    assert gate_c_live._SCALE_UP_AUTHORIZATION_BY_LIVE_ID[live_id] == authorization_id
    assert (
        tuple(gate_c_live._SCALE_UP_AUTHORIZATION_BY_LIVE_ID.values()).count(authorization_id) == 1
    )
    gate_c_live._validate_scale_up_authorization(
        remaining,
        mode="remaining",
        stored_base=base,
    )

    exact_remaining_assignment_ids = tuple(
        sorted(
            (
                "assignment_f5363899c7c8d81b80ec4e32bc8b34764defa7221cb740fc32124a3baa166339",
                "assignment_753722b9ea0684c2c87a23a8e039ce538578e4b4b0d368e40aea21784880ca46",
                "assignment_706d6b92609b30908d1ddfcbc8a98d36aff44d58b6a9f0ed04f8e6537d0c53ac",
            )
        )
    )
    receipt = gate_c_live._authorization_receipt_payload(
        live=remaining,
        source_plan_id=remaining["source_plan_dir"],
        source_plan_manifest_sha256=plan_manifest_sha256,
        app_config_id="configs/minimal-validation/dev-canary-micro-qwen7b-bailian-v1.yaml",
        app_config_sha256="a" * 64,
        base_live_config_sha256="b" * 64,
        pilot_snapshot_id="gate_c_live_pilot_snapshot_v2_micro_test",
        pilot_snapshot_sha256="c" * 64,
        authorized_assignment_ids=exact_remaining_assignment_ids,
    )
    assert receipt["authorized_assignment_ids"] == list(exact_remaining_assignment_ids)
    assert all(item["maximum"] == 3 for item in receipt["typed_budgets"].values())

    plan_report = {
        "task_selection_binding": {"policy": "exact_content_addressed_v1"},
        "seed_assignment_policy": "inherited_gate_a_randomization_v1",
    }
    gate_c_live._validate_required_source_plan_contract(
        base,
        plan_report=plan_report,
        source_plan_manifest_sha256=plan_manifest_sha256,
    )

    for rejected_token in (
        "user-approved-remaining-20260817-v1",
        "user-approved-minimal-validation-dev-canary-20260820-v1",
    ):
        attacked = {**remaining, "scale_up_authorization_id": rejected_token}
        with pytest.raises(ValueError, match="authorization failed"):
            gate_c_live._validate_scale_up_authorization(
                attacked,
                mode="remaining",
                stored_base=base,
            )

    for key, attacked_value in (
        ("pilot_assignment_id", "assignment_" + "f" * 64),
        ("maximum_generation_provider_attempts", 5),
        ("maximum_functional_judge_provider_attempts", 5),
    ):
        attacked = {**remaining, key: attacked_value}
        with pytest.raises(ValueError, match="changed the frozen pilot config"):
            gate_c_live._validate_scale_up_authorization(
                attacked,
                mode="remaining",
                stored_base=base,
            )

    attacked_contracts = (
        {**contract, "manifest_sha256": "f" * 64},
        {**contract, "task_selection_binding_policy": "legacy_unbound_v1"},
        {**contract, "seed_assignment_policy": "balanced_distinct_seed_slots_v1"},
    )
    for attacked_contract in attacked_contracts:
        attacked = {**base, "required_source_plan_contract": attacked_contract}
        with pytest.raises(ValueError, match="required source plan contract"):
            gate_c_live._validate_required_source_plan_contract(
                attacked,
                plan_report=plan_report,
                source_plan_manifest_sha256=plan_manifest_sha256,
            )


def _authorization_receipt_inputs() -> dict[str, object]:
    live = {
        "gate_c_live_id": "minimal-validation-dev-canary-full-live-qwen7b-v1",
        "pilot_assignment_id": "assignment_pilot",
        "scale_up_authorization_id": ("user-approved-minimal-validation-dev-canary-20260820-v1"),
        "scale_up_authorization_scope": "remaining_assignments_only",
    }
    return {
        "live": live,
        "source_plan_id": "runs/minimal-validation/plan",
        "source_plan_manifest_sha256": "1" * 64,
        "app_config_id": "configs/minimal-validation/app.yaml",
        "app_config_sha256": "2" * 64,
        "base_live_config_sha256": "3" * 64,
        "pilot_snapshot_id": "gate_c_live_pilot_snapshot_test",
        "pilot_snapshot_sha256": "4" * 64,
        "authorized_assignment_ids": ("assignment_a", "assignment_b"),
    }


def test_gate_c_live_authorization_receipt_binds_plan_ids_and_typed_budgets() -> None:
    inputs = _authorization_receipt_inputs()
    receipt = gate_c_live._authorization_receipt_payload(**inputs)

    assert receipt["source_plan"]["manifest_sha256"] == "1" * 64
    assert receipt["pilot"]["assignment_id"] == "assignment_pilot"
    assert receipt["authorized_assignment_ids"] == ["assignment_a", "assignment_b"]
    assert receipt["typed_budgets"]["oracle_executions"] == {
        "unit": "executions",
        "maximum": 2,
    }
    gate_c_live._verify_authorization_receipt(receipt, **inputs)

    wrong_plan = {**inputs, "source_plan_manifest_sha256": "9" * 64}
    with pytest.raises(ValueError, match="receipt failed"):
        gate_c_live._verify_authorization_receipt(receipt, **wrong_plan)

    wrong_id = json.loads(json.dumps(receipt))
    wrong_id["authorization_receipt_id"] = "gate_c_live_authorization_receipt_wrong"
    with pytest.raises(ValueError, match="receipt failed"):
        gate_c_live._verify_authorization_receipt(wrong_id, **inputs)

    wrong_budget = json.loads(json.dumps(receipt))
    wrong_budget["typed_budgets"]["oracle_executions"]["maximum"] = 3
    with pytest.raises(ValueError, match="receipt failed"):
        gate_c_live._verify_authorization_receipt(wrong_budget, **inputs)


def test_recovered_remaining_retry_reuses_one_durable_full_scope_receipt(
    tmp_path: Path,
) -> None:
    output = tmp_path / "live"
    output.mkdir()
    inputs = _authorization_receipt_inputs()

    path, first = gate_c_live._load_or_create_authorization_receipt(
        output,
        allow_create=True,
        expected_inputs=inputs,
    )
    original = path.read_bytes()
    _write_json(output / "command-remaining.json", {"argv": ["first-attempt"]})

    retry_path, retry = gate_c_live._load_or_create_authorization_receipt(
        output,
        allow_create=False,
        expected_inputs=inputs,
    )

    assert retry_path == path
    assert retry == first
    assert retry_path.read_bytes() == original
    assert retry["authorized_assignment_ids"] == ["assignment_a", "assignment_b"]
    assert retry["typed_budgets"]["generation_provider_attempts"]["maximum"] == 2
    assert not (output / "authorization-receipt-remaining-002.json").exists()

    narrowed = {**inputs, "authorized_assignment_ids": ("assignment_b",)}
    with pytest.raises(ValueError, match="receipt failed"):
        gate_c_live._load_or_create_authorization_receipt(
            output,
            allow_create=False,
            expected_inputs=narrowed,
        )

    missing = tmp_path / "missing-receipt"
    missing.mkdir()
    with pytest.raises(FileNotFoundError, match="durable authorization receipt"):
        gate_c_live._load_or_create_authorization_receipt(
            missing,
            allow_create=False,
            expected_inputs=inputs,
        )


def test_remaining_retry_only_reuses_durable_scope_files(tmp_path: Path) -> None:
    output = tmp_path / "live"
    output.mkdir()
    live = {"gate_c_live_id": "test", "scale_up_allowed": True}
    provenance = {"authorization_receipt_id": "receipt_test"}
    live_path = output / gate_c_live._REMAINING_LIVE_CONFIG_NAME
    provenance_path = output / gate_c_live._REMAINING_INPUT_PROVENANCE_NAME
    gate_c_live._write_or_verify_durable_json(
        live_path,
        live,
        allow_create=True,
        label="remaining live config",
    )
    gate_c_live._write_or_verify_durable_json(
        provenance_path,
        provenance,
        allow_create=True,
        label="remaining input provenance",
    )
    original_files = {path.name: path.read_bytes() for path in output.iterdir()}

    gate_c_live._write_or_verify_durable_json(
        live_path,
        live,
        allow_create=False,
        label="remaining live config",
    )
    gate_c_live._write_or_verify_durable_json(
        provenance_path,
        provenance,
        allow_create=False,
        label="remaining input provenance",
    )

    assert {path.name: path.read_bytes() for path in output.iterdir()} == original_files
    with pytest.raises(ValueError, match="durable remaining input provenance"):
        gate_c_live._write_or_verify_durable_json(
            provenance_path,
            {"authorization_receipt_id": "tampered"},
            allow_create=False,
            label="remaining input provenance",
        )


def test_gate_c_live_pilot_snapshot_is_content_addressed_and_non_overwriting(
    tmp_path: Path,
) -> None:
    output = tmp_path / "live"
    phase = output / "phases" / "phase-001-pilot"
    unit = output / "units" / "assignment_pilot"
    phase.mkdir(parents=True)
    unit.mkdir(parents=True)
    summary = {
        "schema_version": "1.0",
        "phase": "pilot",
        "status": "GATE_C_LIVE_PARTIAL",
        "scientific_claim_allowed": False,
        "counts": {"completed": 1, "errors": 0, "pending": 23},
        "completed_assignment_ids": ["assignment_pilot"],
        "failed_assignment_ids": [],
    }
    _write_json(phase / "selection.json", {"mode": "pilot", "assignment_ids": ["assignment_pilot"]})
    _write_json(phase / "report.json", summary)
    _write_json(output / "report-pilot.json", summary)
    _write_json(unit / "status.json", {"assignment_id": "assignment_pilot", "status": "COMPLETE"})
    gate_c_live._unit_manifest(unit)
    live = {
        "gate_c_live_id": "minimal-validation-dev-canary-full-live-qwen7b-v1",
        "source_plan_dir": "runs/minimal-validation/plan",
        "pilot_assignment_id": "assignment_pilot",
    }
    inputs = {
        "live": live,
        "source_plan_manifest_sha256": "1" * 64,
        "app_config_id": "configs/app.yaml",
        "app_config_sha256": "2" * 64,
        "base_live_config_sha256": "3" * 64,
    }

    snapshot = gate_c_live._write_pilot_phase_snapshot(output, **inputs)

    assert str(snapshot["pilot_phase_snapshot_id"]).startswith("gate_c_live_pilot_snapshot_")
    assert gate_c_live._verify_pilot_phase_snapshot(output, **inputs) == snapshot
    with pytest.raises(FileExistsError):
        gate_c_live._write_pilot_phase_snapshot(output, **inputs)


@pytest.mark.parametrize(
    ("phase_report_relative", "root_report_name"),
    (
        ("phases/phase-002-remaining/report.json", "report-remaining.json"),
        ("phases/phase-remaining-002/report.json", "report-remaining-002.json"),
    ),
)
def test_gate_c_live_final_root_is_first_write_closed_and_covers_retry_manifests(
    tmp_path: Path,
    phase_report_relative: str,
    root_report_name: str,
) -> None:
    output = tmp_path / "live"
    pilot_snapshot_path = output / "phases" / "phase-001-pilot" / "phase-snapshot.json"
    remaining_report_path = output / phase_report_relative
    root_report_path = output / root_report_name
    pilot_snapshot_path.parent.mkdir(parents=True)
    remaining_report_path.parent.mkdir(parents=True)
    pilot_snapshot = {"pilot_phase_snapshot_id": "gate_c_live_pilot_snapshot_test"}
    _write_json(pilot_snapshot_path, pilot_snapshot)
    expected_ids = ("assignment_a", "assignment_pilot")
    summary = {
        "schema_version": "1.0",
        "phase": "remaining",
        "status": "GATE_C_LIVE_COMPLETE",
        "scientific_claim_allowed": False,
        "counts": {
            "completed": 2,
            "errors": 0,
            "pending": 0,
            "generation_provider_attempts": 2,
            "functional_judge_provider_attempts": 2,
            "oracle_results": 2,
        },
        "completed_assignment_ids": list(expected_ids),
        "failed_assignment_ids": [],
    }
    _write_json(remaining_report_path, summary)
    _write_json(root_report_path, summary)
    for assignment_id in expected_ids:
        unit = output / "units" / assignment_id
        unit.mkdir(parents=True)
        _write_json(
            unit / "status.json",
            {
                "assignment_id": assignment_id,
                "status": "COMPLETE",
                "generation_provider_attempts": 1,
                "functional_judge_provider_attempts": 1,
                "oracle_results": 1,
            },
        )
        gate_c_live._unit_manifest(unit)
    inputs = {
        **_authorization_receipt_inputs(),
        "pilot_snapshot_sha256": hashlib.sha256(pilot_snapshot_path.read_bytes()).hexdigest(),
        "authorized_assignment_ids": ("assignment_a",),
    }
    receipt = gate_c_live._authorization_receipt_payload(**inputs)
    receipt_path = output / "authorization-receipt-remaining.json"
    _write_json(receipt_path, receipt)

    manifest = gate_c_live._finalize_live_root(
        output,
        live=inputs["live"],
        summary=summary,
        expected_assignment_ids=expected_ids,
        source_plan_manifest_sha256="1" * 64,
        app_config_sha256="2" * 64,
        base_live_config_sha256="3" * 64,
        pilot_snapshot=pilot_snapshot,
        authorization_receipt_path=receipt_path,
        authorization_receipt_inputs=inputs,
        phase_report_path=remaining_report_path,
        root_report_path=root_report_path,
    )

    covered = {item["path"] for item in manifest["files"]}
    assert "root-provenance.json" in covered
    assert "units/assignment_pilot/artifact-manifest.json" in covered
    assert "units/assignment_a/artifact-manifest.json" in covered
    assert (output / "artifact-manifest.json").is_file()
    provenance = json.loads((output / "root-provenance.json").read_text(encoding="utf-8"))
    assert provenance["provenance_version"] == "gate_c_live_final_root_v2"
    assert provenance["authorization_receipt_path"] == "authorization-receipt-remaining.json"
    assert provenance["final_phase_report_path"] == phase_report_relative
    assert (
        provenance["final_phase_report_sha256"]
        == hashlib.sha256(remaining_report_path.read_bytes()).hexdigest()
    )
    with pytest.raises(FileExistsError):
        gate_c_live._finalize_live_root(
            output,
            live=inputs["live"],
            summary=summary,
            expected_assignment_ids=expected_ids,
            source_plan_manifest_sha256="1" * 64,
            app_config_sha256="2" * 64,
            base_live_config_sha256="3" * 64,
            pilot_snapshot=pilot_snapshot,
            authorization_receipt_path=receipt_path,
            authorization_receipt_inputs=inputs,
            phase_report_path=remaining_report_path,
            root_report_path=root_report_path,
        )

    outside_receipt = tmp_path / "outside-receipt.json"
    outside_receipt.write_bytes(receipt_path.read_bytes())
    with pytest.raises(ValueError, match="escaped final root"):
        gate_c_live._finalize_live_root(
            output,
            live=inputs["live"],
            summary=summary,
            expected_assignment_ids=expected_ids,
            source_plan_manifest_sha256="1" * 64,
            app_config_sha256="2" * 64,
            base_live_config_sha256="3" * 64,
            pilot_snapshot=pilot_snapshot,
            authorization_receipt_path=outside_receipt,
            authorization_receipt_inputs=inputs,
            phase_report_path=remaining_report_path,
            root_report_path=root_report_path,
        )

    partial_report = {**summary, "status": "GATE_C_LIVE_PARTIAL"}
    remaining_report_path.write_text(
        json.dumps(partial_report, sort_keys=True) + "\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="final report binding"):
        gate_c_live._finalize_live_root(
            output,
            live=inputs["live"],
            summary=summary,
            expected_assignment_ids=expected_ids,
            source_plan_manifest_sha256="1" * 64,
            app_config_sha256="2" * 64,
            base_live_config_sha256="3" * 64,
            pilot_snapshot=pilot_snapshot,
            authorization_receipt_path=receipt_path,
            authorization_receipt_inputs=inputs,
            phase_report_path=remaining_report_path,
            root_report_path=root_report_path,
        )
    remaining_report_path.write_text(json.dumps(summary, sort_keys=True) + "\n", encoding="utf-8")

    tampered_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    tampered_receipt["authorized_assignment_ids"] = []
    receipt_path.write_text(json.dumps(tampered_receipt, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="receipt failed"):
        gate_c_live._finalize_live_root(
            output,
            live=inputs["live"],
            summary=summary,
            expected_assignment_ids=expected_ids,
            source_plan_manifest_sha256="1" * 64,
            app_config_sha256="2" * 64,
            base_live_config_sha256="3" * 64,
            pilot_snapshot=pilot_snapshot,
            authorization_receipt_path=receipt_path,
            authorization_receipt_inputs=inputs,
            phase_report_path=remaining_report_path,
            root_report_path=root_report_path,
        )


def test_gate_c_live_partial_or_error_summary_never_finalizes_root(tmp_path: Path) -> None:
    output = tmp_path / "live"
    output.mkdir()
    partial = {
        "phase": "remaining",
        "status": "GATE_C_LIVE_PARTIAL",
        "scientific_claim_allowed": False,
        "counts": {"completed": 1, "errors": 0, "pending": 1},
        "completed_assignment_ids": ["assignment_pilot"],
        "failed_assignment_ids": [],
    }
    with pytest.raises(ValueError, match="exact COMPLETE"):
        gate_c_live._finalize_live_root(
            output,
            live={},
            summary=partial,
            expected_assignment_ids=("assignment_a", "assignment_pilot"),
            source_plan_manifest_sha256="1" * 64,
            app_config_sha256="2" * 64,
            base_live_config_sha256="3" * 64,
            pilot_snapshot={},
            authorization_receipt_path=output / "missing-receipt.json",
            authorization_receipt_inputs={},
            phase_report_path=output / "missing-phase.json",
            root_report_path=output / "missing-root.json",
        )
    assert not (output / "root-provenance.json").exists()
    assert not (output / "artifact-manifest.json").exists()


def test_gate_c_live_summary_counts_profile_decisions_and_joint_outcome(
    tmp_path: Path,
) -> None:
    unit = tmp_path / "units" / "assignment_test"
    unit.mkdir(parents=True)
    _write_json(
        unit / "status.json",
        {
            "assignment_id": "assignment_test",
            "status": "COMPLETE",
            "generated": 1,
            "terminal_no_code": 0,
            "functional_judge_provider_attempts": 1,
            "oracle_results": 1,
        },
    )
    _write_json(unit / "oracle-decision.json", {"security_label": "secure"})
    (unit / "functional-outcome.jsonl").write_text(
        json.dumps({"status": "pass"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    gate_c_live._unit_manifest(unit)

    summary = gate_c_live._summary(
        tmp_path,
        1,
        "pilot",
        task_selection_policy="explicit_dev_canary",
        arm_roles=gate_c_live._DEV_CANARY_ARM_ROLES,
    )

    assert summary["status"] == "GATE_C_LIVE_COMPLETE"
    assert summary["scientific_claim_allowed"] is False
    assert summary["task_selection_policy"] == "explicit_dev_canary"
    assert summary["arm_roles"] == ["target_patch", "noop_rewrite"]
    assert summary["arms_per_task"] == 2
    assert summary["counts"]["secure"] == 1
    assert summary["counts"]["secure_and_functional"] == 1


def _profile_analysis() -> OracleCodeAnalysis:
    code = "import secrets\n\ndef token():\n    return secrets.token_urlsafe(24)\n"
    return OracleCodeAnalysis(
        request_id="req_" + "1" * 64,
        code_id="code_" + "2" * 64,
        code_sha256=hashlib.sha256(code.encode("utf-8")).hexdigest(),
        prompt_id="prompt_test",
        model_id="test/model",
        seed_id=7,
        parse_ok=True,
        functional_ok=True,
        security_label=SecurityLabel.UNKNOWN,
        evaluability=OracleEvaluability.UNKNOWN_COVERAGE,
        severity="none",
        findings=(),
        analyzers=(),
        mechanism_trace=extract_python_mechanism_trace(code),
    )


def test_gate_c_live_profile_decision_is_shared_with_reconstructed_analysis() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = load_policy_bundle(root / "policies" / "oracle" / "python-v2" / "policy.lock.json")
    profile = next(item for item in policy.coverage_profiles if item.cwe == "CWE-338")
    original = _profile_analysis()
    reconstructed = gate_c_live._oracle_analysis_from_payload(gate_c_live._json_value(original))

    normal_payload = gate_c_live._profile_decision_payload(original, profile)
    recovery_payload = gate_c_live._profile_decision_payload(reconstructed, profile)

    assert recovery_payload == normal_payload
    assert recovery_payload["security_label"] == "secure"
    assert recovery_payload["decision_reason_code"] == "all_relevant_sinks_proved_safe"


def test_gate_c_live_rejects_tampered_preserved_mechanism_trace() -> None:
    payload = gate_c_live._json_value(_profile_analysis())
    payload["mechanism_trace"]["sink_facts"][0]["line"] = "4"

    with pytest.raises(ValueError, match="mechanism trace"):
        gate_c_live._oracle_analysis_from_payload(payload)
