from dataclasses import replace
import pytest
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.tsg.representation import (
    DataRole,
    DataRoleBinding,
    DataRoleManifest,
    TaskUnitDataRoleRecord,
    validate_data_role_firewall,
)


def test_data_role_manifest_closes_task_and_near_duplicate_firewalls() -> None:
    def task(
        task_unit_id: str,
        group_id: str,
        *,
        exposures: tuple[str, ...] = (),
    ) -> TaskUnitDataRoleRecord:
        return TaskUnitDataRoleRecord(
            task_unit_id,
            group_id,
            f"lineage-{task_unit_id}",
            exposures,
            "role-assignment-v1",
        )

    qual_a = task("qual-a", "qual-group")
    qual_b = task("qual-b", "qual-group")
    bindings = (
        DataRoleBinding(
            "CONFIRM-001",
            DataRole.CONFIRMATION,
            (task("confirm-a", "confirm-group"),),
            content_hash("confirm-manifest"),
        ),
        DataRoleBinding(
            "DISCOVERY-001",
            DataRole.DISCOVERY,
            (
                task("discover-a", "discover-group"),
                task("discover-b", "discover-group"),
            ),
            content_hash("discovery-manifest"),
        ),
        DataRoleBinding(
            "LEGACY-001",
            DataRole.LEGACY_ONLY,
            (
                task(
                    "legacy-a",
                    "legacy-group",
                    exposures=("used_for_legacy_gate_c_v4",),
                ),
            ),
            content_hash("legacy-manifest"),
        ),
        DataRoleBinding(
            "QUAL-ACCEPT-001",
            DataRole.QUAL_ACCEPT,
            (task("accept-a", "accept-group"),),
            content_hash("qual-accept-manifest"),
        ),
        DataRoleBinding(
            "QUAL-DEV-FCI-001",
            DataRole.QUAL_DEV,
            (qual_a, qual_b),
            content_hash("qual-fci-manifest"),
        ),
        DataRoleBinding(
            "QUAL-DEV-RD-001",
            DataRole.QUAL_DEV,
            (qual_b,),
            content_hash("qual-rd-manifest"),
        ),
    )
    manifest = DataRoleManifest(
        "phase-context-policy-v3",
        content_hash("source-universe"),
        bindings,
    )

    assert manifest.declared_roles == tuple(DataRole)
    assert manifest.qualification_data_ids == (
        "QUAL-ACCEPT-001",
        "QUAL-DEV-FCI-001",
        "QUAL-DEV-RD-001",
    )
    assert manifest.qualification_dev_data_ids == (
        "QUAL-DEV-FCI-001",
        "QUAL-DEV-RD-001",
    )
    assert manifest.qualification_accept_data_id == "QUAL-ACCEPT-001"
    assert manifest.require_dataset_role(
        "QUAL-DEV-FCI-001",
        DataRole.QUAL_DEV,
    ) == bindings[4]
    preflight = validate_data_role_firewall(
        manifest,
        {
            "QUAL-ACCEPT-001": DataRole.QUAL_ACCEPT,
            "QUAL-DEV-FCI-001": DataRole.QUAL_DEV,
        },
    )
    assert preflight["status"] == "PASS"
    assert preflight["outcome_data_read"] is False
    with pytest.raises(ValueError, match="not authorized"):
        validate_data_role_firewall(
            manifest,
            {"LEGACY-001": DataRole.DISCOVERY},
        )

    crossed_task = (
        *bindings,
        DataRoleBinding(
            "DISCOVERY-OVERLAP",
            DataRole.DISCOVERY,
            (qual_a,),
            content_hash("overlap-manifest"),
        ),
    )
    with pytest.raises(ValueError, match="cannot cross data roles"):
        DataRoleManifest(
            "phase-context-policy-v3",
            content_hash("source-universe"),
            tuple(sorted(crossed_task, key=lambda item: item.data_id)),
        )

    crossed_group = (
        *bindings[:3],
        replace(
            bindings[3],
            task_units=(task("accept-a", "discover-group"),),
        ),
        *bindings[4:],
    )
    with pytest.raises(ValueError, match="near-duplicate group cannot cross"):
        DataRoleManifest(
            "phase-context-policy-v3",
            content_hash("source-universe"),
            crossed_group,
        )

    with pytest.raises(ValueError, match="must be unexposed"):
        DataRoleBinding(
            "QUAL-ACCEPT-EXPOSED",
            DataRole.QUAL_ACCEPT,
            (
                task(
                    "accept-exposed",
                    "accept-exposed-group",
                    exposures=("profile_debugging",),
                ),
            ),
            content_hash("qual-accept-exposed-manifest"),
        )

    with pytest.raises(ValueError, match="all five data roles"):
        DataRoleManifest(
            "phase-context-policy-v3",
            content_hash("source-universe"),
            tuple(item for item in bindings if item.role is not DataRole.LEGACY_ONLY),
        )


def test_current_source_screen_reads_three_axes_without_reapplying_old_design_gate():
    from prompt_mechanism_study.data.qualification_data import _frozen_source_axis_states
    from prompt_mechanism_study.tsg.representation import (
        AnalysisScope, AtomicPolicyKey, Operation, PolicyFactor,
    )

    task = {"task_unit_id": "task-1", "prompt": "Query records", "language": "python"}
    scope = AnalysisScope("sql", "query", ("python",), ("database",), ("query",))
    policy = AtomicPolicyKey(scope, PolicyFactor("parameter_binding", Operation.ADD), "secure")
    evidence = [{"start": 0, "end": 5, "text": "Query"}]
    review = {
        "task_unit_id": "task-1", "source_prompt_sha256": content_hash(task["prompt"]),
        "source_use_rule_sha256": content_hash("frozen-source-rule"),
        "candidate_family": "Atomic", "candidate_id": policy.policy_key,
        "candidate_policy": {
            "analysis_scope": {
                "security_pattern_id": "sql", "context_query_id": "query",
                "language_scope": ["python"], "api_scope": ["database"],
                "task_archetype_scope": ["query"],
            },
            "factor": {"actionable_feature_id": "parameter_binding", "operation": Operation.ADD.value},
            "outcome_id": "secure",
        },
        "axes": {
            **{name: {"state": "supported", "evidence": evidence}
               for name in ("context", "security_boundary", "non_target_invariants")},
            "target_operation": {"state": "contradicted", "evidence": evidence},
            "arm_compatibility": {"state": "contradicted", "evidence": evidence},
        },
        "arms_or_outcomes_used": False,
    }
    axes = ("context", "security_boundary", "non_target_invariants")
    assert _frozen_source_axis_states(
        review, task, content_hash("frozen-source-rule"), axes
    ) == dict.fromkeys(axes, "supported")
    bad_review = {**review, "axes": {**review["axes"], "context": {
        "state": "supported", "evidence": [{"start": 0, "end": 5, "text": "Other"}]
    }}}
    with pytest.raises(ValueError, match="evidence differs"):
        _frozen_source_axis_states(bad_review, task, content_hash("frozen-source-rule"), axes)
