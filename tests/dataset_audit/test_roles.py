from __future__ import annotations

from secaware.dataset_audit.roles import DatasetEvidence, assign_roles
from secaware.dataset_audit.schema import DatasetRole


def test_primary_candidate_requires_security_neutrality_and_functionality() -> None:
    decision = assign_roles(
        DatasetEvidence(
            dataset_id="primary",
            total_records=30,
            independent_clusters=24,
            candidate_neutral_clusters=22,
            cwe_resolved_clusters=21,
            executable_functional_clusters=20,
            functional_reference_clusters=20,
            external_replication_source=False,
        )
    )

    assert DatasetRole.PAPER_PRIMARY_CANDIDATE in decision.roles
    assert "primary candidate evidence is complete" in decision.supporting_reasons


def test_security_only_data_is_secondary_and_pending_not_discovery_only() -> None:
    decision = assign_roles(
        DatasetEvidence(
            dataset_id="security-only",
            total_records=30,
            independent_clusters=25,
            candidate_neutral_clusters=23,
            cwe_resolved_clusters=22,
            executable_functional_clusters=0,
            functional_reference_clusters=0,
            external_replication_source=False,
        )
    )

    assert decision.roles == (
        DatasetRole.SECURITY_ONLY_SECONDARY_CANDIDATE,
        DatasetRole.ORACLE_CALIBRATION,
        DatasetRole.EXTRACTOR_OR_TSG_EVALUATION,
        DatasetRole.PENDING_CONTRACT_OR_ADJUDICATION,
    )
    assert all("discovery-only" not in reason for reason in decision.blocking_reasons)


def test_functional_and_external_roles_can_coexist() -> None:
    decision = assign_roles(
        DatasetEvidence(
            dataset_id="functional",
            total_records=80,
            independent_clusters=75,
            candidate_neutral_clusters=70,
            cwe_resolved_clusters=0,
            executable_functional_clusters=70,
            functional_reference_clusters=75,
            external_replication_source=True,
        )
    )

    assert decision.roles == (
        DatasetRole.FUNCTIONAL_CALIBRATION,
        DatasetRole.EXTERNAL_REPLICATION_CANDIDATE,
        DatasetRole.PENDING_CONTRACT_OR_ADJUDICATION,
    )


def test_empty_dataset_is_unusable() -> None:
    decision = assign_roles(
        DatasetEvidence(
            dataset_id="empty",
            total_records=0,
            independent_clusters=0,
            candidate_neutral_clusters=0,
            cwe_resolved_clusters=0,
            executable_functional_clusters=0,
            functional_reference_clusters=0,
            external_replication_source=False,
        )
    )

    assert decision.roles == (DatasetRole.UNUSABLE_UNDER_CURRENT_SCOPE,)
