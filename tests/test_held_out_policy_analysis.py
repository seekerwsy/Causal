from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile

import pytest

from secaware.experiments.held_out_policy_analysis import (
    _archive_files,
    _estimate_contrast,
    _verify_manifest_bytes,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.experiments import AssignmentExecutionStatus, AssignmentRecord
from secaware.schema.outcomes import (
    AssignmentEvaluability,
    AssignmentOutcomeRecord,
    CWESecurityOutcome,
    FunctionalOutcomeStatus,
)


_ROOT = Path(__file__).parents[1]
_PLAN = _ROOT / "data/e2e-pilot/five-cwe-held-out-policy-itt-gate-c-plan-qwen7b-20260819-01"


def _assignments() -> list[AssignmentRecord]:
    return [
        AssignmentRecord.model_validate(json.loads(line))
        for line in (_PLAN / "assignments.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]


def _synthetic_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for assignment in _assignments():
        success = int(assignment.arm_role.value == "target_patch")
        outcome = AssignmentOutcomeRecord.from_content(
            assignment_id=assignment.assignment_id,
            task_id=assignment.experimental_unit.task_id,
            hypothesis_id=assignment.experimental_unit.hypothesis_id,
            target_spec_id=assignment.target_spec_id,
            target_instance_id=assignment.target_instance_id,
            arm_protocol_id=assignment.arm_protocol_id,
            protocol_instance_id=assignment.protocol_instance_id,
            variant_id=assignment.variant_id,
            arm_role=assignment.arm_role,
            model_id=assignment.experimental_unit.model_id,
            seed_id=assignment.seed_id,
            execution_status=AssignmentExecutionStatus.GENERATED,
            secure_functional_success=success,
            cwe_security_outcome=(
                CWESecurityOutcome.SECURE if success else CWESecurityOutcome.INSECURE
            ),
            oracle_evaluability=AssignmentEvaluability.EVALUABLE,
            parse_ok=True,
            functional_ok=True,
            functional_outcome_status=FunctionalOutcomeStatus.PASS,
            target_changed=bool(success),
            semantic_compliance=True,
            source_digests_sha256=canonical_sha256({"assignment_id": assignment.assignment_id}),
        )
        rows.append(
            {
                "assignment_outcome": outcome.model_dump(mode="json"),
                "security_unknown": False,
                "functional_unknown": False,
                "decision_reason_code": (
                    "all_relevant_sinks_proved_safe" if success else "proved_unsafe_sink"
                ),
                "mechanism_outcomes": {
                    "z_all_relevant_sinks_proved_safe": success,
                    "z_proved_unsafe_sink": 1 - success,
                    "z_relevant_sink_present": 1,
                },
            }
        )
    return rows


def test_frozen_policy_effect_uses_all_task_blocks_and_is_deterministic() -> None:
    kwargs = {
        "model_id": "qwen2.5-coder-7b-instruct",
        "outcome_id": "y_secure_functional",
        "treatment": "target_patch",
        "control": "noop_rewrite",
        "priority": "primary",
        "family_id": "five_cwe_policy_primary_by_model_v1",
        "family_size": 2,
        "bootstrap_config": {
            "samples": 200,
            "confidence_level": 0.95,
            "percentile_method": "linear-v1",
            "max_failed_fraction": 0.0,
            "seed_kind": "held-out-policy-task-cluster-bootstrap-v1",
        },
        "input_bundle_sha256": "a" * 64,
    }

    first = _estimate_contrast(_synthetic_rows(), **kwargs)
    second = _estimate_contrast(_synthetic_rows(), **kwargs)

    effect, draws, flip = first
    assert first == second
    assert effect["independent_task_clusters"] == 42
    assert effect["treatment_n"] == effect["control_n"] == 42
    assert effect["risk_difference"] == 1.0
    assert effect["ci_low"] == effect["ci_high"] == 1.0
    assert effect["multiplicity_method"] == "bonferroni"
    assert len(draws) == 200
    assert all(len(draw["sampled_task_ids"]) == 42 for draw in draws)
    assert flip["improved"] == 42
    assert flip["harmed"] == flip["unchanged"] == 0


def _tar_member(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))


def test_archive_reader_authenticates_nested_manifest_closure(tmp_path: Path) -> None:
    archive_path = tmp_path / "run.tar.gz"
    nested = b'{"value":1}\n'
    manifest = (
        json.dumps(
            {
                "schema_version": "1.0",
                "files": [
                    {
                        "path": "nested/value.json",
                        "sha256": __import__("hashlib").sha256(nested).hexdigest(),
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    with tarfile.open(archive_path, "w:gz") as archive:
        _tar_member(archive, "run/artifact-manifest.json", manifest)
        _tar_member(archive, "run/nested/value.json", nested)

    root, files = _archive_files(archive_path)

    assert root == "run"
    assert _verify_manifest_bytes(files) == __import__("hashlib").sha256(manifest).hexdigest()


def test_archive_reader_rejects_parent_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "invalid.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        _tar_member(archive, "run/../private.txt", b"private")

    with pytest.raises(ValueError, match="archive path"):
        _archive_files(archive_path)
