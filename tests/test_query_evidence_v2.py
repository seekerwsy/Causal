from __future__ import annotations

import pytest
from pydantic import ValidationError

from secaware.extractors.base import ExtractionPolicy
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.schema.features import FeatureOperation, PromptExtractorBackend
from secaware.schema.policy_v2 import (
    ContextQueryResultRecord,
    EligibilityExclusionReason,
    PolicySplit,
    PreOutcomeEligibilityRecord,
    QueryState,
    SemanticTaskClusterMembershipRecord,
)
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2
from secaware.schema.query_evidence_v2 import (
    QueryEvidenceManifestV2,
    QueryEvidenceTaskRecordV2,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.context_queries_v2 import CWE78_COMMAND_FLOW_QUERY, context_query_spec
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256
from test_protocol_freeze_v2 import (
    SHA_C,
    SHA_D,
    _context_spec,
    _feature_spec,
    _fixture,
    _natural_prompt,
    _root_components,
    _sha,
)


def _extraction(prompt: PromptRecord, *, policy_sha256: str = SHA_C):
    policy = ExtractionPolicy(
        backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
        policy_sha256=policy_sha256,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        max_response_chars=262_144,
    )
    proposal = DeterministicCatalogExtractor().extract(prompt, policy)
    return proposal, build_prompt_tsg(proposal, prompt)


def _membership(task_id: str) -> SemanticTaskClusterMembershipRecord:
    return SemanticTaskClusterMembershipRecord.from_content(
        semantic_task_cluster_id=f"cluster.{task_id}",
        task_instance_id=task_id,
        split=PolicySplit.CONFIRM,
        cwe="CWE-89",
        task_archetype="value-parameterization",
        source_task_sha256=_sha(f"source:{task_id}"),
        clustering_policy_sha256=_sha("cluster-policy"),
        adjudication_sha256=None,
    )


def _standalone_task(
    *, operation: FeatureOperation, target_present: bool
) -> QueryEvidenceTaskRecordV2:
    task_id = f"standalone.{operation.value}.{int(target_present)}"
    prompt = _natural_prompt(task_id, target_present=target_present)
    proposal, graph = _extraction(prompt)
    remove = operation is FeatureOperation.REMOVE and target_present
    return QueryEvidenceTaskRecordV2.from_natural_prompt(
        membership=_membership(task_id),
        natural_prompt=prompt,
        extraction_proposal=proposal,
        prompt_tsg=graph,
        context_query=_context_spec(),
        actionable_feature=_feature_spec(),
        operation=operation,
        eligibility_function_sha256=SHA_D,
        neutral_counterpart_attested=True if remove else None,
        neutral_counterpart_attestation_sha256=(
            _sha(f"neutral-counterpart:{task_id}") if remove else None
        ),
    )


def _replacement_prompt_task(
    original: QueryEvidenceTaskRecordV2,
) -> QueryEvidenceTaskRecordV2:
    content = original.natural_prompt.to_prompt_record().model_dump(mode="python")
    content["prompt"] += " Return the database result."
    prompt = PromptRecord.model_validate(content)
    proposal, graph = _extraction(
        prompt,
        policy_sha256=original.extraction_proposal.policy_sha256,
    )
    return QueryEvidenceTaskRecordV2.from_natural_prompt(
        membership=original.membership,
        natural_prompt=prompt,
        extraction_proposal=proposal,
        prompt_tsg=graph,
        context_query=original.context_query,
        actionable_feature=original.actionable_feature,
        operation=original.eligibility.operation,
        eligibility_function_sha256=original.eligibility.eligibility_function_sha256,
    )


def _manifest_with_tasks(
    original: QueryEvidenceManifestV2,
    tasks: tuple[QueryEvidenceTaskRecordV2, ...],
) -> QueryEvidenceManifestV2:
    return QueryEvidenceManifestV2.from_tasks(
        context_query=original.context_query,
        actionable_feature=original.actionable_feature,
        operation=original.operation,
        extractor_backend=original.extractor_backend,
        extractor_policy_sha256=original.extractor_policy_sha256,
        eligibility_function_sha256=original.eligibility_function_sha256,
        tasks=tasks,
    )


def test_query_evidence_json_replay_and_add_remove_source_state_gates() -> None:
    fixture = _fixture()
    manifest = fixture.root.query_evidence

    assert QueryEvidenceManifestV2.model_validate_json(manifest.model_dump_json()) == manifest
    assert all(item.eligibility.eligible for item in manifest.tasks)
    assert all(item.context_query_result.state is QueryState.PRESENT for item in manifest.tasks)
    assert all(item.actionable_query_result.state is QueryState.ABSENT for item in manifest.tasks)

    remove = _standalone_task(operation=FeatureOperation.REMOVE, target_present=True)
    assert remove.eligibility.eligible is True
    assert (
        remove.eligibility.target_evidence_sha256
        == remove.actionable_query_result.evaluation_evidence_sha256
    )
    add_present = _standalone_task(operation=FeatureOperation.ADD, target_present=True)
    assert add_present.eligibility.eligible is False
    assert add_present.eligibility.exclusion_reason is EligibilityExclusionReason.ADD_SOURCE_PRESENT
    remove_absent = _standalone_task(operation=FeatureOperation.REMOVE, target_present=False)
    assert remove_absent.eligibility.eligible is False
    assert (
        remove_absent.eligibility.exclusion_reason
        is EligibilityExclusionReason.REMOVE_SOURCE_ABSENT
    )


@pytest.mark.parametrize(
    "field_name",
    ("context_query_result", "actionable_query_result"),
)
def test_task_evidence_rejects_foreign_query_result(
    field_name: str,
) -> None:
    tasks = _fixture().root.query_evidence.tasks
    content = tasks[0].model_dump(
        mode="python", exclude={"schema_version", "query_evidence_task_id"}
    )
    content[field_name] = getattr(tasks[1], field_name)

    with pytest.raises(ValidationError, match="query evidence v2 contract failed validation"):
        QueryEvidenceTaskRecordV2.from_content(**content)


def test_task_evidence_rejects_synchronized_query_and_eligibility_rehash() -> None:
    original = _fixture().root.query_evidence.tasks[0]
    context_content = original.context_query_result.model_dump(
        mode="python", exclude={"schema_version", "context_query_result_id"}
    )
    context_content.update(
        {
            "state": QueryState.ABSENT,
            "applicable": True,
            "required_roles_resolved": True,
            "bounded_matching_complete": True,
            "match_evidence_ids": (),
            "evaluation_evidence_sha256": _sha("forged-context-evaluation"),
        }
    )
    forged_context = ContextQueryResultRecord.from_content(**context_content)
    forged_eligibility = PreOutcomeEligibilityRecord.from_query_results(
        context_result=forged_context,
        feature_result=original.actionable_query_result,
        operation=original.eligibility.operation,
        eligibility_function_sha256=original.eligibility.eligibility_function_sha256,
    )
    task_content = original.model_dump(
        mode="python", exclude={"schema_version", "query_evidence_task_id"}
    )
    task_content["context_query_result"] = forged_context
    task_content["eligibility"] = forged_eligibility

    with pytest.raises(ValidationError, match="query evidence v2 contract failed validation"):
        QueryEvidenceTaskRecordV2.from_content(**task_content)


def test_task_evidence_rejects_wrong_prompt_or_prompt_tsg() -> None:
    tasks = _fixture().root.query_evidence.tasks
    for field_name, replacement in (
        ("natural_prompt", tasks[1].natural_prompt),
        ("prompt_tsg", tasks[1].prompt_tsg),
        ("extraction_proposal", tasks[1].extraction_proposal),
    ):
        content = tasks[0].model_dump(
            mode="python", exclude={"schema_version", "query_evidence_task_id"}
        )
        content[field_name] = replacement
        with pytest.raises(ValidationError, match="query evidence v2 contract failed validation"):
            QueryEvidenceTaskRecordV2.from_content(**content)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("feature_catalog_sha256", "f" * 64),
        ("extractor_policy_sha256", "e" * 64),
        ("context_query", context_query_spec(CWE78_COMMAND_FLOW_QUERY)),
    ),
)
def test_manifest_rejects_wrong_catalog_extractor_or_query_spec(
    field_name: str, replacement: object
) -> None:
    manifest = _fixture().root.query_evidence
    content = manifest.model_dump(
        mode="python", exclude={"schema_version", "query_evidence_manifest_id"}
    )
    content[field_name] = replacement

    with pytest.raises(ValidationError, match="query evidence v2 contract failed validation"):
        QueryEvidenceManifestV2.from_content(**content)


def test_protocol_root_rejects_missing_task_query_evidence() -> None:
    fixture = _fixture()
    reduced = _manifest_with_tasks(
        fixture.root.query_evidence,
        fixture.root.query_evidence.tasks[:-1],
    )
    components = _root_components(fixture)
    components["query_evidence"] = reduced

    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.from_components(**components)


def test_protocol_root_rejects_synchronized_prompt_graph_query_and_eligibility_replacement() -> (
    None
):
    fixture = _fixture()
    original = fixture.root.query_evidence.tasks[0]
    replacement = _replacement_prompt_task(original)
    assert replacement.natural_prompt.prompt_sha256 != original.natural_prompt.prompt_sha256
    tasks = tuple(
        replacement
        if item.membership.task_instance_id == original.membership.task_instance_id
        else item
        for item in fixture.root.query_evidence.tasks
    )
    synchronized = _manifest_with_tasks(fixture.root.query_evidence, tasks)
    components = _root_components(fixture)
    components["query_evidence"] = synchronized

    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.from_components(**components)

    payload = fixture.root.model_dump(mode="json")
    payload["query_evidence"] = synchronized.model_dump(mode="json")
    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.model_validate(payload, strict=True)


def test_protocol_root_rejects_synchronized_extractor_replacement() -> None:
    fixture = _fixture()
    replacement_policy_sha256 = _sha("replacement-extractor-policy")
    replacements = []
    for original in fixture.root.query_evidence.tasks:
        prompt = original.natural_prompt.to_prompt_record()
        proposal, graph = _extraction(prompt, policy_sha256=replacement_policy_sha256)
        replacement = QueryEvidenceTaskRecordV2.from_natural_prompt(
            membership=original.membership,
            natural_prompt=prompt,
            extraction_proposal=proposal,
            prompt_tsg=graph,
            context_query=original.context_query,
            actionable_feature=original.actionable_feature,
            operation=original.eligibility.operation,
            eligibility_function_sha256=original.eligibility.eligibility_function_sha256,
        )
        assert replacement.eligibility == original.eligibility
        replacements.append(replacement)
    synchronized = QueryEvidenceManifestV2.from_tasks(
        context_query=fixture.root.query_evidence.context_query,
        actionable_feature=fixture.root.query_evidence.actionable_feature,
        operation=fixture.root.query_evidence.operation,
        extractor_backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
        extractor_policy_sha256=replacement_policy_sha256,
        eligibility_function_sha256=(fixture.root.query_evidence.eligibility_function_sha256),
        tasks=tuple(replacements),
    )
    components = _root_components(fixture)
    components["query_evidence"] = synchronized

    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.from_components(**components)


def test_protocol_root_rejects_synchronized_context_query_spec_replacement() -> None:
    fixture = _fixture()
    replacement_context = context_query_spec(CWE78_COMMAND_FLOW_QUERY)
    replacements = tuple(
        QueryEvidenceTaskRecordV2.from_natural_prompt(
            membership=original.membership,
            natural_prompt=original.natural_prompt.to_prompt_record(),
            extraction_proposal=original.extraction_proposal,
            prompt_tsg=original.prompt_tsg,
            context_query=replacement_context,
            actionable_feature=original.actionable_feature,
            operation=original.eligibility.operation,
            eligibility_function_sha256=original.eligibility.eligibility_function_sha256,
        )
        for original in fixture.root.query_evidence.tasks
    )
    synchronized = QueryEvidenceManifestV2.from_tasks(
        context_query=replacement_context,
        actionable_feature=fixture.root.query_evidence.actionable_feature,
        operation=fixture.root.query_evidence.operation,
        extractor_backend=fixture.root.query_evidence.extractor_backend,
        extractor_policy_sha256=fixture.root.query_evidence.extractor_policy_sha256,
        eligibility_function_sha256=(fixture.root.query_evidence.eligibility_function_sha256),
        tasks=replacements,
    )
    components = _root_components(fixture)
    components["query_evidence"] = synchronized

    with pytest.raises(ValidationError, match="protocol freeze v2 contract failed validation"):
        ProtocolFreezeRootV2.from_components(**components)
