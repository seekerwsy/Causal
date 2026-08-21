from __future__ import annotations

from dataclasses import dataclass

from secaware.dataset_audit.schema import DatasetRole


@dataclass(frozen=True, slots=True)
class DatasetEvidence:
    dataset_id: str
    total_records: int
    independent_clusters: int
    candidate_neutral_clusters: int
    cwe_resolved_clusters: int
    executable_functional_clusters: int
    functional_reference_clusters: int
    external_replication_source: bool


@dataclass(frozen=True, slots=True)
class RoleDecision:
    dataset_id: str
    roles: tuple[DatasetRole, ...]
    supporting_reasons: tuple[str, ...]
    blocking_reasons: tuple[str, ...]


def assign_roles(evidence: DatasetEvidence) -> RoleDecision:
    values = (
        evidence.total_records,
        evidence.independent_clusters,
        evidence.candidate_neutral_clusters,
        evidence.cwe_resolved_clusters,
        evidence.executable_functional_clusters,
        evidence.functional_reference_clusters,
    )
    if any(value < 0 for value in values):
        raise ValueError("dataset evidence counts cannot be negative")
    if evidence.total_records == 0 or evidence.independent_clusters == 0:
        return RoleDecision(
            dataset_id=evidence.dataset_id,
            roles=(DatasetRole.UNUSABLE_UNDER_CURRENT_SCOPE,),
            supporting_reasons=(),
            blocking_reasons=("no independently usable task clusters",),
        )

    roles: list[DatasetRole] = []
    supporting: list[str] = []
    blocking: list[str] = []
    has_security = evidence.cwe_resolved_clusters > 0
    has_neutral = evidence.candidate_neutral_clusters > 0
    has_executable = evidence.executable_functional_clusters > 0
    primary = has_security and has_neutral and has_executable
    if primary:
        roles.append(DatasetRole.PAPER_PRIMARY_CANDIDATE)
        supporting.append("primary candidate evidence is complete")
    elif has_security:
        roles.append(DatasetRole.SECURITY_ONLY_SECONDARY_CANDIDATE)
        supporting.append("CWE-resolved security clusters are available")

    if has_executable:
        roles.append(DatasetRole.FUNCTIONAL_CALIBRATION)
        supporting.append("executable functional contracts are available")
    if has_security:
        roles.append(DatasetRole.ORACLE_CALIBRATION)
        roles.append(DatasetRole.EXTRACTOR_OR_TSG_EVALUATION)
        supporting.append("security labels support calibration and extraction evaluation")
    if evidence.external_replication_source:
        roles.append(DatasetRole.EXTERNAL_REPLICATION_CANDIDATE)
        supporting.append("dataset is designated as an external replication source")

    if not primary:
        roles.append(DatasetRole.PENDING_CONTRACT_OR_ADJUDICATION)
        if not has_security:
            blocking.append("CWE scope requires resolution or is intentionally absent")
        if not has_neutral:
            blocking.append("security-neutrality eligibility requires adjudication")
        if not has_executable:
            blocking.append("no existing executable functional contract was validated")
    return RoleDecision(
        dataset_id=evidence.dataset_id,
        roles=tuple(roles),
        supporting_reasons=tuple(supporting),
        blocking_reasons=tuple(blocking),
    )
