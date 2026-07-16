from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from typing import Iterable

import pytest

from m5_executor_fixtures import proposal_graph, request
from secaware.causal.jci import (
    build_jci_tables,
    jci_stratum_key,
    validate_jci_table_bundle,
)
from secaware.intervention.executors import (
    DETERMINISTIC_INTERVENTION_POLICY_SHA256,
)
from secaware.schema.causal import JCIContextSpec, JCIStratum, VariableRole
from secaware.schema.experiments import (
    ArmRole,
    AssignmentExecutionStatus,
    AssignmentRecord,
    ExperimentalUnit,
    FeatureFamily,
    FeatureOperation,
    PromptRole,
    PromptVariantRecord,
)
from secaware.schema.outcomes import (
    AssignmentEvaluability,
    AssignmentOutcomeRecord,
    CWESecurityOutcome,
    JCIObservationRecord,
)
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord


def _sha(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class JCIFixture:
    assignments: tuple[AssignmentRecord, ...]
    outcomes: tuple[AssignmentOutcomeRecord, ...]
    graphs: tuple[PromptTSGRecord, ...]
    variants: tuple[PromptVariantRecord, ...]
    hypotheses: tuple[object, ...]
    protocols: tuple[object, ...]


def _outcome(assignment: AssignmentRecord, *, secure: bool) -> AssignmentOutcomeRecord:
    return AssignmentOutcomeRecord.from_content(
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
        secure_functional_success=int(secure),
        cwe_security_outcome=(CWESecurityOutcome.SECURE if secure else CWESecurityOutcome.INSECURE),
        oracle_evaluability=AssignmentEvaluability.EVALUABLE,
        parse_ok=True,
        functional_ok=True,
        target_changed=None,
        semantic_compliance=None,
        source_digests_sha256=_sha(assignment.assignment_id, "outcome-sources"),
    )


def _arm_texts(family: FeatureFamily, operation: FeatureOperation, *, contracted: bool):
    base = request(
        family,
        operation,
        with_functional_contract=contracted,
    )
    target_roles = {
        ArmRole.TARGET_PATCH,
        ArmRole.TARGET_REMOVE,
        ArmRole.TASK_TARGET,
        ArmRole.PRESENTATION_TARGET,
    }
    target_text = (
        base.prompt_bundle[1].prompt
        if operation is FeatureOperation.ADD
        else base.prompt_bundle[0].prompt
    )
    return base, {
        arm.role: target_text if arm.role in target_roles else base.source_prompt.prompt
        for arm in base.protocol.arms
    }


def fixture_for(
    family: FeatureFamily = FeatureFamily.SAFETY_CONTROL,
    operation: FeatureOperation = FeatureOperation.ADD,
    *,
    task_count: int = 2,
    contracted: bool = False,
) -> JCIFixture:
    base, text_by_role = _arm_texts(family, operation, contracted=contracted)
    assignments: list[AssignmentRecord] = []
    outcomes: list[AssignmentOutcomeRecord] = []
    graphs: list[PromptTSGRecord] = []
    variants: list[PromptVariantRecord] = []
    for task_index in range(task_count):
        task_id = (
            f"task-{family.value}-{operation.value}-"
            f"{'contracted' if contracted else 'reserved'}-{task_index:03d}"
        )
        target_instance_id = "target_instance_" + _sha(base.target.target_spec_id, task_id)
        protocol_instance_id = "protocol_instance_" + _sha(
            base.protocol.arm_protocol_id, target_instance_id
        )
        for seed_slot, arm in enumerate(base.protocol.arms):
            prompt_id = "variant_prompt_" + _sha(task_id, arm.role.value, "prompt")
            source = PromptRecord(
                prompt_id=prompt_id,
                task_id=task_id,
                split="confirm",
                language=base.source_prompt.language,
                task_family=base.source_prompt.task_family,
                cwe=base.source_prompt.cwe,
                prompt=text_by_role[arm.role],
                prompt_role=PromptRole.NEUTRAL_BASELINE,
                counterpart_prompt_id=None,
            )
            proposal, graph = proposal_graph(source)
            length_match_id = (
                "length_match_" + _sha(task_id, arm.role.value)
                if arm.role
                in {
                    ArmRole.LENGTH_MATCHED_PLACEBO,
                    ArmRole.LENGTH_MATCHED_SHAM_EDIT,
                    ArmRole.TASK_LENGTH_PLACEBO,
                    ArmRole.PRESENTATION_MATCHED_CONTROL,
                }
                else None
            )
            variant = PromptVariantRecord.from_content(
                task_id=task_id,
                source_prompt_id=f"source-{task_id}",
                language=source.language,
                variant_prompt_id=source.prompt_id,
                hypothesis_id=base.hypothesis.hypothesis_id,
                target_spec_id=base.target.target_spec_id,
                target_instance_id=target_instance_id,
                arm_protocol_id=base.protocol.arm_protocol_id,
                protocol_instance_id=protocol_instance_id,
                arm_role=arm.role,
                prompt_sha256=source.prompt_sha256,
                prompt_text=source.prompt,
                proposal_id=proposal.proposal_id,
                graph_id=graph.graph_id,
                delta_id="delta_" + _sha(task_id, arm.role.value, "delta"),
                executor_policy_sha256=DETERMINISTIC_INTERVENTION_POLICY_SHA256,
                extractor_policy_sha256=proposal.policy_sha256,
                length_match_id=length_match_id,
            )
            unit = ExperimentalUnit(
                task_id=task_id,
                hypothesis_id=base.hypothesis.hypothesis_id,
                target_spec_id=base.target.target_spec_id,
                model_id=base.hypothesis.model_id,
                seed_slot=seed_slot,
            )
            assignment = AssignmentRecord.from_content(
                block_id=AssignmentRecord.block_id_from_key(
                    task_id,
                    base.hypothesis.hypothesis_id,
                    base.target.target_spec_id,
                    base.protocol.arm_protocol_id,
                    base.hypothesis.model_id,
                ),
                experimental_unit=unit,
                target_spec_id=base.target.target_spec_id,
                target_instance_id=target_instance_id,
                arm_protocol_id=base.protocol.arm_protocol_id,
                protocol_instance_id=protocol_instance_id,
                variant_id=variant.variant_id,
                arm_role=arm.role,
                seed_id=int(_sha(task_id, arm.role.value)[:15], 16),
                rng_version="sha256-rejection-fisher-yates-v1",
                randomization_plan_sha256=_sha(base.protocol.arm_protocol_id, "plan"),
            )
            assignments.append(assignment)
            outcomes.append(
                _outcome(
                    assignment,
                    secure=arm.role
                    in {
                        ArmRole.TARGET_PATCH,
                        ArmRole.TASK_TARGET,
                        ArmRole.PRESENTATION_TARGET,
                    },
                )
            )
            variants.append(variant)
            graphs.append(graph)
    return JCIFixture(
        assignments=tuple(assignments),
        outcomes=tuple(outcomes),
        graphs=tuple(graphs),
        variants=tuple(variants),
        hypotheses=(base.hypothesis,),
        protocols=(base.protocol,),
    )


def merge_fixtures(*fixtures: JCIFixture) -> JCIFixture:
    def unique(values: Iterable[object], identity: str) -> tuple[object, ...]:
        found: dict[str, object] = {}
        for item in values:
            found[getattr(item, identity)] = item
        return tuple(found[key] for key in sorted(found))

    return JCIFixture(
        assignments=tuple(item for fixture in fixtures for item in fixture.assignments),
        outcomes=tuple(item for fixture in fixtures for item in fixture.outcomes),
        graphs=tuple(item for fixture in fixtures for item in fixture.graphs),
        variants=tuple(item for fixture in fixtures for item in fixture.variants),
        hypotheses=unique(
            (item for fixture in fixtures for item in fixture.hypotheses),
            "hypothesis_id",
        ),
        protocols=unique(
            (item for fixture in fixtures for item in fixture.protocols),
            "arm_protocol_id",
        ),
    )


def build_fixture(fixture: JCIFixture, *, minimum: int = 2):
    return build_jci_tables(
        fixture.assignments,
        fixture.outcomes,
        fixture.graphs,
        variants=fixture.variants,
        hypotheses=fixture.hypotheses,
        protocols=fixture.protocols,
        min_independent_tasks=minimum,
    )


def _rows_for(table, rows):
    return tuple(row for row in rows if row.table_id == table.table_id)


def _replace_assignment(
    assignment: AssignmentRecord,
    **updates: object,
) -> AssignmentRecord:
    content = assignment.model_dump(mode="python", exclude={"assignment_id"})
    content.update(updates)
    return AssignmentRecord.from_content(**content)


def _replace_outcome(
    outcome: AssignmentOutcomeRecord,
    **updates: object,
) -> AssignmentOutcomeRecord:
    content = outcome.model_dump(mode="python", exclude={"outcome_id"})
    content.update(updates)
    return AssignmentOutcomeRecord.from_content(**content)


def _replace_variant(
    variant: PromptVariantRecord,
    **updates: object,
) -> PromptVariantRecord:
    content = variant.model_dump(mode="python", exclude={"variant_id"})
    content.update(updates)
    return PromptVariantRecord.from_content(**content)


def test_jci_tables_pool_task_instances_but_never_semantic_strata() -> None:
    safety_add = fixture_for(task_count=20)
    safety_remove = fixture_for(FeatureFamily.SAFETY_CONTROL, FeatureOperation.REMOVE)
    task_add = fixture_for(FeatureFamily.TASK_FUNCTION, FeatureOperation.ADD)
    presentation_add = fixture_for(
        FeatureFamily.PRESENTATION_CONTROL,
        FeatureOperation.ADD,
    )
    fixture = merge_fixtures(safety_add, safety_remove, task_add, presentation_add)

    tables, rows = build_fixture(fixture)

    assignment_by_id = {item.assignment_id: item for item in fixture.assignments}
    hypothesis_by_id = {item.hypothesis_id: item for item in fixture.hypotheses}
    assert len(tables) == 4
    for table in tables:
        local = _rows_for(table, rows)
        assignments = tuple(assignment_by_id[row.assignment_id] for row in local)
        strata = {
            jci_stratum_key(
                assignment,
                hypothesis_by_id[assignment.experimental_unit.hypothesis_id],
            )
            for assignment in assignments
        }
        assert len(strata) == 1
        assert len({row.task_id for row in local}) == table.independent_task_count
        assert len({row.target_instance_id for row in local}) == table.independent_task_count
        assert len({row.protocol_instance_id for row in local}) == table.independent_task_count
        assert len({row.target_spec_id for row in local}) == 1
        assert len({row.arm_protocol_id for row in local}) == 1


def test_exact_protocol_order_is_one_categorical_context_not_one_hot() -> None:
    three = fixture_for(FeatureFamily.TASK_FUNCTION, contracted=False)
    four = fixture_for(FeatureFamily.TASK_FUNCTION, contracted=True)
    fixture = merge_fixtures(three, four)

    tables, rows = build_fixture(fixture)

    protocol_by_id = {item.arm_protocol_id: item for item in fixture.protocols}
    assert {len(item.arm_roles) for item in fixture.protocols} == {3, 4}
    for table in tables:
        local = _rows_for(table, rows)
        protocol = protocol_by_id[local[0].arm_protocol_id]
        context = tuple(variable for variable in table.variables if variable.role is VariableRole.C)
        assert tuple(item.variable_id for item in context) == ("c.arm",)
        assert context[0].states == tuple(role.value for role in protocol.arm_roles)
        context_index = tuple(item.variable_id for item in table.variables).index("c.arm")
        codes = {row.values[context_index] for row in local}
        assert codes == set(range(len(protocol.arm_roles)))
        assert JCIContextSpec.from_protocol(protocol).category_codes == tuple(
            range(len(protocol.arm_roles))
        )


def test_jci_stratum_is_strict_and_uses_frozen_scope() -> None:
    fixture = fixture_for()
    assignment = fixture.assignments[0]
    hypothesis = fixture.hypotheses[0]

    assert jci_stratum_key(assignment, hypothesis) == JCIStratum(
        scope_id=hypothesis.scope_id,
        model_id=assignment.experimental_unit.model_id,
        hypothesis_id=hypothesis.hypothesis_id,
        target_spec_id=assignment.target_spec_id,
        arm_protocol_id=assignment.arm_protocol_id,
    )
    with pytest.raises(Exception, match="JCI"):
        jci_stratum_key(
            assignment,
            hypothesis.model_copy(update={"hypothesis_id": "hypothesis_" + "f" * 64}),
        )


def test_configured_independent_task_minimum_is_hard() -> None:
    with pytest.raises(Exception, match="JCI"):
        build_fixture(fixture_for(task_count=2), minimum=3)


def test_exactly_one_instance_pair_per_task_semantic_target_is_required() -> None:
    fixture = fixture_for()
    assignment = fixture.assignments[0]
    variant = fixture.variants[0]
    outcome = fixture.outcomes[0]
    protocol_instance_id = "protocol_instance_" + _sha("second-instance")
    changed_variant = _replace_variant(
        variant,
        protocol_instance_id=protocol_instance_id,
    )
    changed_assignment = _replace_assignment(
        assignment,
        protocol_instance_id=protocol_instance_id,
        variant_id=changed_variant.variant_id,
    )
    changed_outcome = _replace_outcome(
        outcome,
        assignment_id=changed_assignment.assignment_id,
        protocol_instance_id=protocol_instance_id,
        variant_id=changed_variant.variant_id,
    )
    forged = replace(
        fixture,
        assignments=(changed_assignment, *fixture.assignments[1:]),
        outcomes=(changed_outcome, *fixture.outcomes[1:]),
        variants=(changed_variant, *fixture.variants[1:]),
    )

    with pytest.raises(Exception, match="JCI"):
        build_fixture(forged)


@pytest.mark.parametrize(
    "producer",
    ("assignment", "outcome", "variant", "graph", "hypothesis", "protocol"),
)
@pytest.mark.parametrize("coverage", ("missing", "duplicate", "extra"))
def test_all_input_producers_require_exact_unique_coverage(
    producer: str,
    coverage: str,
) -> None:
    fixture = fixture_for()
    field = {
        "assignment": "assignments",
        "outcome": "outcomes",
        "variant": "variants",
        "graph": "graphs",
        "hypothesis": "hypotheses",
        "protocol": "protocols",
    }[producer]
    values = getattr(fixture, field)
    if coverage == "missing":
        changed = values[:-1]
    elif coverage == "duplicate":
        changed = (*values, values[0])
    else:
        other = fixture_for(
            FeatureFamily.PRESENTATION_CONTROL,
            FeatureOperation.REMOVE,
        )
        changed = (*values, getattr(other, field)[0])
    forged = replace(fixture, **{field: changed})

    with pytest.raises(Exception, match="JCI"):
        build_fixture(forged)


@pytest.mark.parametrize(
    "drift",
    (
        "outcome-assignment",
        "outcome-arm",
        "variant-assignment",
        "variant-graph",
        "variant-extractor-policy",
        "graph-task",
    ),
)
def test_assignment_outcome_variant_graph_coordinates_close_exactly(drift: str) -> None:
    fixture = fixture_for()
    first_assignment = fixture.assignments[0]
    first_outcome = fixture.outcomes[0]
    first_variant = fixture.variants[0]
    if drift == "outcome-assignment":
        outcomes = (
            _replace_outcome(first_outcome, assignment_id=fixture.assignments[1].assignment_id),
            *fixture.outcomes[1:],
        )
        forged = replace(fixture, outcomes=outcomes)
    elif drift == "outcome-arm":
        outcomes = (
            _replace_outcome(first_outcome, arm_role=fixture.outcomes[1].arm_role),
            *fixture.outcomes[1:],
        )
        forged = replace(fixture, outcomes=outcomes)
    elif drift == "variant-assignment":
        assignment = _replace_assignment(
            first_assignment,
            variant_id=fixture.variants[1].variant_id,
        )
        outcome = _replace_outcome(
            first_outcome,
            assignment_id=assignment.assignment_id,
            variant_id=assignment.variant_id,
        )
        forged = replace(
            fixture,
            assignments=(assignment, *fixture.assignments[1:]),
            outcomes=(outcome, *fixture.outcomes[1:]),
        )
    elif drift == "variant-graph":
        variant = _replace_variant(first_variant, graph_id=fixture.graphs[1].graph_id)
        assignment = _replace_assignment(first_assignment, variant_id=variant.variant_id)
        outcome = _replace_outcome(
            first_outcome,
            assignment_id=assignment.assignment_id,
            variant_id=variant.variant_id,
        )
        forged = replace(
            fixture,
            assignments=(assignment, *fixture.assignments[1:]),
            outcomes=(outcome, *fixture.outcomes[1:]),
            variants=(variant, *fixture.variants[1:]),
        )
    elif drift == "variant-extractor-policy":
        variant = _replace_variant(first_variant, extractor_policy_sha256="f" * 64)
        assignment = _replace_assignment(first_assignment, variant_id=variant.variant_id)
        outcome = _replace_outcome(
            first_outcome,
            assignment_id=assignment.assignment_id,
            variant_id=variant.variant_id,
        )
        forged = replace(
            fixture,
            assignments=(assignment, *fixture.assignments[1:]),
            outcomes=(outcome, *fixture.outcomes[1:]),
            variants=(variant, *fixture.variants[1:]),
        )
    else:
        graph = fixture.graphs[0].model_copy(update={"task_id": "wrong-task"})
        forged = replace(fixture, graphs=(graph, *fixture.graphs[1:]))

    with pytest.raises(Exception, match="JCI"):
        build_fixture(forged)


def test_jci_observations_are_frozen_content_addressed_and_bounded() -> None:
    table, row = (lambda result: (result[0][0], result[1][0]))(build_fixture(fixture_for()))
    assert isinstance(row, JCIObservationRecord)
    with pytest.raises(Exception):
        row.values = (0,)  # type: ignore[misc]
    forged = row.model_copy(update={"row_id": "row_" + "f" * 64})
    with pytest.raises(Exception, match="JCI"):
        JCIObservationRecord.model_validate(forged)
    assert row.table_id == table.table_id
    with pytest.raises(Exception, match="JCI"):
        JCIObservationRecord.from_content(
            table_id=table.table_id,
            assignment_id=row.assignment_id,
            task_id=row.task_id,
            target_spec_id=row.target_spec_id,
            target_instance_id=row.target_instance_id,
            arm_protocol_id=row.arm_protocol_id,
            protocol_instance_id=row.protocol_instance_id,
            values=tuple(0 for _ in range(65)),
        )


@pytest.mark.parametrize("mutation", ("missing", "duplicate", "wrong-table", "forged-bundle"))
def test_persisted_jci_table_bundle_revalidates_exact_table_row_closure(mutation: str) -> None:
    tables, rows = build_fixture(fixture_for())
    validate_jci_table_bundle(tables, rows)
    if mutation == "missing":
        changed_tables, changed_rows = tables, rows[:-1]
    elif mutation == "duplicate":
        changed_tables, changed_rows = tables, (*rows, rows[0])
    elif mutation == "wrong-table":
        changed_tables = tables
        changed_rows = (
            rows[0].model_copy(update={"table_id": "table_" + "f" * 64}),
            *rows[1:],
        )
    else:
        changed_tables = (
            tables[0].model_copy(
                update={
                    "table_id": "table_" + "f" * 64,
                    "table_sha256": "f" * 64,
                }
            ),
        )
        changed_rows = tuple(
            row.model_copy(update={"table_id": "table_" + "f" * 64}) for row in rows
        )

    with pytest.raises(Exception, match="JCI"):
        validate_jci_table_bundle(changed_tables, changed_rows)
