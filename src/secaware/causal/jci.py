"""Exact randomized-context JCI tables and explicit background assumptions."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
import hashlib
import json
from typing import Any

from secaware.causal.background import typed_adjacency_exclusions
from secaware.causal.variable_catalog import (
    CWE_SECURITY_OUTCOME,
    PRIMARY_OUTCOME,
    PROMPT_CAUSAL_VARIABLES,
    VariableDeclaration,
    declaration_by_id,
    declaration_sha256,
)
from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.arm_catalog import _target_feature_from_protocol
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    CausalVariableSpec,
    FrozenHypothesisRecord,
    JCIBackgroundKnowledgeRecord,
    JCIContextSpec,
    JCIStratum,
    VariableRole,
    jci_row_id_from_content,
)
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import (
    ArmRole,
    AssignmentRecord,
    ConfirmationProtocolRecord,
    PromptVariantRecord,
)
from secaware.schema.features import FeatureState
from secaware.schema.outcomes import AssignmentOutcomeRecord, JCIObservationRecord
from secaware.schema.tsg import MotifId, PromptTSGRecord
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.motifs import motif_query_vector
from secaware.tsg.queries import feature_state


JCI_CONTEXT_EXOGENEITY = "jci.randomized_context_exogeneity.v1"
_MAX_ROWS = 100_000
_MAX_VARIABLES = 64
_TASK_FAMILY_STATES = (
    "authorization",
    "command_execution",
    "deserialization",
    "file_access",
    "input_handling",
    "path_handling",
    "sql_query",
    "other",
)


def _jci_error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.jci",
        message="JCI assembly failed validation",
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _snapshots_in_order(
    value: object,
    model: type,
    identity: str,
    *,
    maximum: int = _MAX_ROWS,
) -> tuple[object, ...]:
    if type(value) not in {list, tuple} or not 1 <= len(value) <= maximum:
        raise ValueError
    result: list[object] = []
    identities: set[str] = set()
    for item in value:
        if type(item) is not model or not model_shape_is_intact(item):
            raise ValueError
        checked = model.model_validate(
            item.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
        item_id = getattr(checked, identity)
        if type(item_id) is not str or item_id in identities:
            raise ValueError
        identities.add(item_id)
        result.append(checked)
    return tuple(result)


def _snapshots(
    value: object,
    model: type,
    identity: str,
    *,
    maximum: int = _MAX_ROWS,
) -> tuple[object, ...]:
    checked = _snapshots_in_order(value, model, identity, maximum=maximum)
    return tuple(sorted(checked, key=lambda item: getattr(item, identity)))


def _strictly_increasing(value: Sequence[object], key: Callable[[Any], Any]) -> bool:
    if len(value) < 2:
        return True
    previous = key(value[0])
    for item in value[1:]:
        current = key(item)
        if previous >= current:
            return False
        previous = current
    return True


def jci_stratum_key(
    assignment: AssignmentRecord,
    hypothesis: FrozenHypothesisRecord,
) -> JCIStratum:
    """Return the exact semantic stratum without inferring frozen coordinates."""
    try:
        checked_assignment = AssignmentRecord.model_validate(assignment, strict=True)
        checked_hypothesis = FrozenHypothesisRecord.model_validate(hypothesis, strict=True)
        unit = checked_assignment.experimental_unit
        if unit.hypothesis_id != checked_hypothesis.hypothesis_id:
            raise ValueError
        return JCIStratum(
            scope_id=checked_hypothesis.scope_id,
            model_id=unit.model_id,
            hypothesis_id=unit.hypothesis_id,
            target_spec_id=checked_assignment.target_spec_id,
            arm_protocol_id=checked_assignment.arm_protocol_id,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _jci_error() from None


def _same_outcome_coordinates(
    assignment: AssignmentRecord,
    outcome: AssignmentOutcomeRecord,
) -> bool:
    unit = assignment.experimental_unit
    return (
        outcome.assignment_id == assignment.assignment_id
        and outcome.task_id == unit.task_id
        and outcome.hypothesis_id == unit.hypothesis_id
        and outcome.target_spec_id == assignment.target_spec_id
        and outcome.target_instance_id == assignment.target_instance_id
        and outcome.arm_protocol_id == assignment.arm_protocol_id
        and outcome.protocol_instance_id == assignment.protocol_instance_id
        and outcome.variant_id == assignment.variant_id
        and outcome.arm_role is assignment.arm_role
        and outcome.model_id == unit.model_id
        and outcome.seed_id == assignment.seed_id
    )


def _same_variant_coordinates(
    assignment: AssignmentRecord,
    variant: PromptVariantRecord,
) -> bool:
    unit = assignment.experimental_unit
    return (
        variant.task_id == unit.task_id
        and variant.hypothesis_id == unit.hypothesis_id
        and variant.target_spec_id == assignment.target_spec_id
        and variant.target_instance_id == assignment.target_instance_id
        and variant.arm_protocol_id == assignment.arm_protocol_id
        and variant.protocol_instance_id == assignment.protocol_instance_id
        and variant.arm_role is assignment.arm_role
        and variant.variant_id == assignment.variant_id
    )


def _variable_spec(declaration: VariableDeclaration, scope_id: str) -> CausalVariableSpec:
    return CausalVariableSpec(
        schema_version="1.0",
        variable_id=declaration.variable_id,
        role=declaration.role,
        states=declaration.states,
        source_query_id=declaration.query_id,
        scope_id=scope_id,
        temporal_tier=declaration.tier,
        adjacency_type=declaration.adjacency_type,
        producer_sha256=declaration_sha256(declaration),
    )


def _context_variable(
    stratum: JCIStratum,
    protocol: ConfirmationProtocolRecord,
) -> CausalVariableSpec:
    context = JCIContextSpec.from_protocol(protocol)
    producer_sha256 = _canonical_sha256(
        {
            "schema_version": "1.0",
            "producer": "jci.assigned_arm_context.v1",
            "arm_protocol_id": protocol.arm_protocol_id,
            "arm_roles": [role.value for role in context.arm_roles],
        }
    )
    return CausalVariableSpec(
        schema_version="1.0",
        variable_id=context.variable_id,
        role=VariableRole.C,
        states=tuple(role.value for role in context.arm_roles),
        source_query_id="assignment.arm_role.v1",
        scope_id=stratum.scope_id,
        temporal_tier=0,
        adjacency_type="jci_context",
        producer_sha256=producer_sha256,
    )


def _declaration_applies(declaration: VariableDeclaration, cwe: str) -> bool:
    return declaration.applicable_cwes == ("*",) or cwe in declaration.applicable_cwes


def _pre_outcome_value(
    declaration: VariableDeclaration,
    variant: PromptVariantRecord,
    graph: PromptTSGRecord,
    live_graph: object,
    motifs: dict[MotifId, bool],
) -> int:
    if declaration.role is VariableRole.W:
        if declaration.variable_id == "w.language_family":
            return declaration.states.index(
                "python" if variant.language.casefold() == "python" else "other"
            )
        if declaration.variable_id == "w.task_family":
            task_family = (
                graph.task_family if graph.task_family in _TASK_FAMILY_STATES[:-1] else "other"
            )
            return declaration.states.index(task_family)
        raise ValueError
    if declaration.role is not VariableRole.X:
        raise ValueError
    if declaration.variable_id.startswith("x.motif."):
        return int(motifs[MotifId(declaration.variable_id.removeprefix("x.motif."))])
    state = feature_state(live_graph, declaration.variable_id.removeprefix("x."))
    if state is FeatureState.ABSENT:
        return 0
    if state is FeatureState.PRESENT:
        return 1
    raise ValueError


def _outcome_value(
    declaration: VariableDeclaration,
    outcome: AssignmentOutcomeRecord,
) -> int:
    if declaration == PRIMARY_OUTCOME:
        return outcome.secure_functional_success
    if declaration == CWE_SECURITY_OUTCOME:
        return declaration.states.index(outcome.cwe_security_outcome.value)
    raise ValueError


def _validate_protocol_block(
    assignments: tuple[AssignmentRecord, ...],
    protocol: ConfirmationProtocolRecord,
) -> None:
    instances = {(item.target_instance_id, item.protocol_instance_id) for item in assignments}
    counts = Counter(item.arm_role for item in assignments)
    expected_roles = protocol.arm_roles
    if (
        len(instances) != 1
        or tuple(role for role in expected_roles if counts[role]) != expected_roles
        or set(counts) != set(expected_roles)
        or len(set(counts.values())) != 1
        or next(iter(counts.values()), 0) < 1
    ):
        raise ValueError


def _build_jci_tables(
    assignments: Sequence[AssignmentRecord],
    outcomes: Sequence[AssignmentOutcomeRecord],
    variant_graphs: Sequence[PromptTSGRecord],
    *,
    variants: Sequence[PromptVariantRecord],
    hypotheses: Sequence[FrozenHypothesisRecord],
    protocols: Sequence[ConfirmationProtocolRecord],
    min_independent_tasks: int,
) -> tuple[tuple[CausalTableRecord, ...], tuple[JCIObservationRecord, ...]]:
    if type(min_independent_tasks) is not int or not 2 <= min_independent_tasks <= _MAX_ROWS:
        raise ValueError
    checked_assignments = _snapshots(assignments, AssignmentRecord, "assignment_id")
    checked_outcomes = _snapshots(outcomes, AssignmentOutcomeRecord, "outcome_id")
    checked_graphs = _snapshots(variant_graphs, PromptTSGRecord, "graph_id")
    checked_variants = _snapshots(variants, PromptVariantRecord, "variant_id")
    checked_hypotheses = _snapshots(
        hypotheses,
        FrozenHypothesisRecord,
        "hypothesis_id",
        maximum=_MAX_ROWS,
    )
    checked_protocols = _snapshots(
        protocols,
        ConfirmationProtocolRecord,
        "arm_protocol_id",
        maximum=_MAX_ROWS,
    )

    assignment_by_id = {item.assignment_id: item for item in checked_assignments}
    outcome_by_assignment = {item.assignment_id: item for item in checked_outcomes}
    variant_by_id = {item.variant_id: item for item in checked_variants}
    graph_by_id = {item.graph_id: item for item in checked_graphs}
    hypothesis_by_id = {item.hypothesis_id: item for item in checked_hypotheses}
    protocol_by_id = {item.arm_protocol_id: item for item in checked_protocols}
    referenced_hypotheses = {item.experimental_unit.hypothesis_id for item in checked_assignments}
    referenced_protocols = {item.arm_protocol_id for item in checked_assignments}
    referenced_variants = {item.variant_id for item in checked_assignments}
    if (
        set(outcome_by_assignment) != set(assignment_by_id)
        or set(variant_by_id) != referenced_variants
        or set(hypothesis_by_id) != referenced_hypotheses
        or set(protocol_by_id) != referenced_protocols
        or {item.graph_id for item in checked_variants} != set(graph_by_id)
        or len(outcome_by_assignment) != len(checked_outcomes)
    ):
        raise ValueError

    live_by_graph_id: dict[str, object] = {}
    for graph in checked_graphs:
        live_by_graph_id[graph.graph_id] = record_to_multidigraph(graph)

    strata: dict[JCIStratum, list[AssignmentRecord]] = defaultdict(list)
    target_owner: dict[str, tuple[str, str, str]] = {}
    protocol_owner: dict[str, tuple[str, str, str, str]] = {}
    target_instance_by_coordinate: dict[tuple[str, str, str], str] = {}
    protocol_instance_by_coordinate: dict[tuple[str, str, str, str], str] = {}
    for assignment in checked_assignments:
        unit = assignment.experimental_unit
        outcome = outcome_by_assignment[assignment.assignment_id]
        variant = variant_by_id[assignment.variant_id]
        graph = graph_by_id[variant.graph_id]
        hypothesis = hypothesis_by_id[unit.hypothesis_id]
        protocol = protocol_by_id[assignment.arm_protocol_id]
        if (
            not _same_outcome_coordinates(assignment, outcome)
            or not _same_variant_coordinates(assignment, variant)
            or graph.prompt_id != variant.variant_prompt_id
            or graph.task_id != variant.task_id
            or graph.extractor_policy_sha256 != variant.extractor_policy_sha256
            or graph.proposal_id != variant.proposal_id
            or graph.cwe != hypothesis.cwe
            or protocol.hypothesis_id != hypothesis.hypothesis_id
            or protocol.frozen_hypothesis_sha256 != hypothesis.hypothesis_sha256
            or protocol.target_spec_id != assignment.target_spec_id
            or protocol.feature_family is not hypothesis.feature_family
            or protocol.operation not in hypothesis.permitted_operations
            or _target_feature_from_protocol(protocol) != hypothesis.target_feature_id
            or assignment.arm_role not in protocol.arm_roles
        ):
            raise ValueError
        target_coordinate = (unit.task_id, unit.hypothesis_id, assignment.target_spec_id)
        protocol_coordinate = (
            unit.task_id,
            unit.hypothesis_id,
            assignment.target_spec_id,
            assignment.arm_protocol_id,
        )
        prior_target = target_owner.setdefault(assignment.target_instance_id, target_coordinate)
        prior_protocol = protocol_owner.setdefault(
            assignment.protocol_instance_id,
            protocol_coordinate,
        )
        coordinate_target_instance = target_instance_by_coordinate.setdefault(
            target_coordinate,
            assignment.target_instance_id,
        )
        coordinate_protocol_instance = protocol_instance_by_coordinate.setdefault(
            protocol_coordinate,
            assignment.protocol_instance_id,
        )
        if (
            prior_target != target_coordinate
            or prior_protocol != protocol_coordinate
            or coordinate_target_instance != assignment.target_instance_id
            or coordinate_protocol_instance != assignment.protocol_instance_id
        ):
            raise ValueError
        strata[jci_stratum_key(assignment, hypothesis)].append(assignment)

    tables: list[CausalTableRecord] = []
    rows: list[JCIObservationRecord] = []
    for stratum in sorted(
        strata,
        key=lambda item: (
            item.scope_id,
            item.model_id,
            item.hypothesis_id,
            item.target_spec_id,
            item.arm_protocol_id,
        ),
    ):
        local_assignments = tuple(sorted(strata[stratum], key=lambda item: item.assignment_id))
        hypothesis = hypothesis_by_id[stratum.hypothesis_id]
        protocol = protocol_by_id[stratum.arm_protocol_id]
        by_task: dict[str, list[AssignmentRecord]] = defaultdict(list)
        for assignment in local_assignments:
            by_task[assignment.experimental_unit.task_id].append(assignment)
        if len(by_task) < min_independent_tasks:
            raise ValueError
        for task_assignments in by_task.values():
            _validate_protocol_block(tuple(task_assignments), protocol)

        declarations = tuple(
            item for item in PROMPT_CAUSAL_VARIABLES if _declaration_applies(item, hypothesis.cwe)
        )
        variables = tuple(
            sorted(
                (
                    *(_variable_spec(item, stratum.scope_id) for item in declarations),
                    _context_variable(stratum, protocol),
                ),
                key=lambda item: item.variable_id,
            )
        )
        if not 2 <= len(variables) <= _MAX_VARIABLES:
            raise ValueError
        variable_ids = tuple(item.variable_id for item in variables)
        context_code = {role: index for index, role in enumerate(protocol.arm_roles)}
        payloads: list[tuple[str, str, str, str, str, str, str, tuple[int, ...]]] = []
        pending_rows: list[
            tuple[
                AssignmentRecord,
                tuple[int, ...],
            ]
        ] = []
        for assignment in local_assignments:
            variant = variant_by_id[assignment.variant_id]
            graph = graph_by_id[variant.graph_id]
            live = live_by_graph_id[graph.graph_id]
            needs_motifs = any(item.variable_id.startswith("x.motif.") for item in declarations)
            motifs = dict(motif_query_vector(live)) if needs_motifs else {}
            outcome = outcome_by_assignment[assignment.assignment_id]
            value_by_id: dict[str, int] = {"c.arm": context_code[assignment.arm_role]}
            for declaration in declarations:
                value_by_id[declaration.variable_id] = (
                    _outcome_value(declaration, outcome)
                    if declaration.role is VariableRole.Y
                    else _pre_outcome_value(declaration, variant, graph, live, motifs)
                )
            values = tuple(value_by_id[variable_id] for variable_id in variable_ids)
            unit = assignment.experimental_unit
            row_id = jci_row_id_from_content(
                assignment_id=assignment.assignment_id,
                task_id=unit.task_id,
                target_spec_id=assignment.target_spec_id,
                target_instance_id=assignment.target_instance_id,
                arm_protocol_id=assignment.arm_protocol_id,
                protocol_instance_id=assignment.protocol_instance_id,
                values=values,
            )
            payloads.append(
                (
                    row_id,
                    assignment.assignment_id,
                    unit.task_id,
                    assignment.target_spec_id,
                    assignment.target_instance_id,
                    assignment.arm_protocol_id,
                    assignment.protocol_instance_id,
                    values,
                )
            )
            pending_rows.append((assignment, values))
        table = CausalTableRecord.from_jci_content(
            scope_id=stratum.scope_id,
            cwe=hypothesis.cwe,
            model_id=stratum.model_id,
            variables=variables,
            independent_task_count=len(by_task),
            observation_payload=payloads,
        )
        tables.append(table)
        for assignment, values in pending_rows:
            unit = assignment.experimental_unit
            rows.append(
                JCIObservationRecord.from_content(
                    table_id=table.table_id,
                    assignment_id=assignment.assignment_id,
                    task_id=unit.task_id,
                    target_spec_id=assignment.target_spec_id,
                    target_instance_id=assignment.target_instance_id,
                    arm_protocol_id=assignment.arm_protocol_id,
                    protocol_instance_id=assignment.protocol_instance_id,
                    values=values,
                )
            )
    return (
        tuple(sorted(tables, key=lambda item: (item.scope_id, item.model_id, item.table_id))),
        tuple(sorted(rows, key=lambda item: (item.table_id, item.row_id))),
    )


def build_jci_tables(
    assignments: Sequence[AssignmentRecord],
    outcomes: Sequence[AssignmentOutcomeRecord],
    variant_graphs: Sequence[PromptTSGRecord],
    *,
    variants: Sequence[PromptVariantRecord],
    hypotheses: Sequence[FrozenHypothesisRecord],
    protocols: Sequence[ConfirmationProtocolRecord],
    min_independent_tasks: int,
) -> tuple[tuple[CausalTableRecord, ...], tuple[JCIObservationRecord, ...]]:
    """Assemble exact JCI strata after all producer-closure checks."""
    try:
        return _build_jci_tables(
            assignments,
            outcomes,
            variant_graphs,
            variants=variants,
            hypotheses=hypotheses,
            protocols=protocols,
            min_independent_tasks=min_independent_tasks,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _jci_error() from None


def _checked_jci_table_bundle(
    tables: Sequence[CausalTableRecord],
    rows: Sequence[JCIObservationRecord],
) -> tuple[tuple[CausalTableRecord, ...], tuple[JCIObservationRecord, ...]]:
    checked_tables = _snapshots_in_order(tables, CausalTableRecord, "table_id")
    checked_rows = _snapshots_in_order(rows, JCIObservationRecord, "row_id")
    if not _strictly_increasing(
        checked_tables,
        lambda item: (item.scope_id, item.model_id, item.table_id),
    ) or not _strictly_increasing(
        checked_rows,
        lambda item: (item.table_id, item.row_id),
    ):
        raise ValueError
    rows_by_table: dict[str, list[JCIObservationRecord]] = {
        item.table_id: [] for item in checked_tables
    }
    assignment_ids: set[str] = set()
    for row in checked_rows:
        local = rows_by_table.get(row.table_id)
        if local is None or row.assignment_id in assignment_ids:
            raise ValueError
        assignment_ids.add(row.assignment_id)
        local.append(row)
    if any(not local for local in rows_by_table.values()):
        raise ValueError
    for table in checked_tables:
        local = tuple(rows_by_table[table.table_id])
        context_indices = tuple(
            index
            for index, variable in enumerate(table.variables)
            if variable.role is VariableRole.C
        )
        if (
            len(context_indices) != 1
            or table.row_count != len(local)
            or table.independent_task_count != len({item.task_id for item in local})
            or len({item.target_spec_id for item in local}) != 1
            or len({item.arm_protocol_id for item in local}) != 1
        ):
            raise ValueError
        context_index = context_indices[0]
        by_task: dict[str, list[JCIObservationRecord]] = defaultdict(list)
        for row in local:
            if len(row.values) != len(table.variables) or any(
                not 0 <= value < len(variable.states)
                for value, variable in zip(row.values, table.variables, strict=True)
            ):
                raise ValueError
            by_task[row.task_id].append(row)
        expected_codes = set(range(len(table.variables[context_index].states)))
        for task_rows in by_task.values():
            pairs = {(item.target_instance_id, item.protocol_instance_id) for item in task_rows}
            counts = Counter(item.values[context_index] for item in task_rows)
            if len(pairs) != 1 or set(counts) != expected_codes or len(set(counts.values())) != 1:
                raise ValueError
        rebuilt = CausalTableRecord.from_jci_content(
            scope_id=table.scope_id,
            cwe=table.cwe,
            model_id=table.model_id,
            variables=table.variables,
            independent_task_count=table.independent_task_count,
            observation_payload=tuple(
                (
                    item.row_id,
                    item.assignment_id,
                    item.task_id,
                    item.target_spec_id,
                    item.target_instance_id,
                    item.arm_protocol_id,
                    item.protocol_instance_id,
                    item.values,
                )
                for item in local
            ),
        )
        if rebuilt != table:
            raise ValueError
    return checked_tables, checked_rows


def _validate_jci_table_bundle(
    tables: Sequence[CausalTableRecord],
    rows: Sequence[JCIObservationRecord],
) -> None:
    _checked_jci_table_bundle(tables, rows)


def validate_jci_table_bundle(
    tables: Sequence[CausalTableRecord],
    rows: Sequence[JCIObservationRecord],
) -> None:
    """Rebuild persisted JCI tables from exact assignment-bound observations."""
    try:
        _validate_jci_table_bundle(tables, rows)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _jci_error() from None


def _validate_jci_relations(
    assignments: Sequence[AssignmentRecord],
    outcomes: Sequence[AssignmentOutcomeRecord],
    variant_graphs: Sequence[PromptTSGRecord],
    *,
    variants: Sequence[PromptVariantRecord],
    hypotheses: Sequence[FrozenHypothesisRecord],
    protocols: Sequence[ConfirmationProtocolRecord],
    min_independent_tasks: int,
    tables: Sequence[CausalTableRecord],
    rows: Sequence[JCIObservationRecord],
) -> None:
    checked_tables, checked_rows = _checked_jci_table_bundle(tables, rows)
    expected_tables, expected_rows = _build_jci_tables(
        assignments,
        outcomes,
        variant_graphs,
        variants=variants,
        hypotheses=hypotheses,
        protocols=protocols,
        min_independent_tasks=min_independent_tasks,
    )
    if checked_tables != expected_tables or checked_rows != expected_rows:
        raise ValueError


def validate_jci_relations(
    assignments: Sequence[AssignmentRecord],
    outcomes: Sequence[AssignmentOutcomeRecord],
    variant_graphs: Sequence[PromptTSGRecord],
    *,
    variants: Sequence[PromptVariantRecord],
    hypotheses: Sequence[FrozenHypothesisRecord],
    protocols: Sequence[ConfirmationProtocolRecord],
    min_independent_tasks: int,
    tables: Sequence[CausalTableRecord],
    rows: Sequence[JCIObservationRecord],
) -> None:
    """Prove exact persisted-table closure against every upstream producer."""
    try:
        _validate_jci_relations(
            assignments,
            outcomes,
            variant_graphs,
            variants=variants,
            hypotheses=hypotheses,
            protocols=protocols,
            min_independent_tasks=min_independent_tasks,
            tables=tables,
            rows=rows,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _jci_error() from None


def _build_jci_background(
    table: CausalTableRecord,
) -> tuple[BackgroundKnowledgeRecord, JCIBackgroundKnowledgeRecord]:
    checked = CausalTableRecord.model_validate(table, strict=True)
    context = tuple(item for item in checked.variables if item.role is VariableRole.C)
    system = tuple(item for item in checked.variables if item.role is not VariableRole.C)
    if (
        len(context) != 1
        or context[0].variable_id != "c.arm"
        or not 2 <= len(context[0].states) <= 4
        or any(item.variable_id.startswith("c.") for item in system)
    ):
        raise ValueError
    if any(
        item != _variable_spec(declaration_by_id(item.variable_id), checked.scope_id)
        or not _declaration_applies(declaration_by_id(item.variable_id), checked.cwe)
        for item in system
    ):
        raise ValueError
    # Every category must be an exact ArmRole and duplicate-free; arbitrary or
    # one-hot context domains fail closed.
    try:
        roles = tuple(ArmRole(state) for state in context[0].states)
    except Exception:
        raise ValueError from None
    JCIContextSpec(arm_roles=roles, category_codes=tuple(range(len(roles))))
    if (
        context[0].source_query_id != "assignment.arm_role.v1"
        or context[0].temporal_tier != 0
        or context[0].adjacency_type != "jci_context"
    ):
        raise ValueError
    tiers = tuple(sorted((item.variable_id, item.temporal_tier) for item in system))
    forbidden = tuple(
        sorted(
            (later.variable_id, earlier.variable_id)
            for later in system
            for earlier in system
            if later.temporal_tier > earlier.temporal_tier
        )
    )
    base = BackgroundKnowledgeRecord.from_content(
        table_id=checked.table_id,
        variable_ids=tuple(item.variable_id for item in checked.variables),
        tiers=tiers,
        unconstrained_variable_ids=("c.arm",),
        forbidden_directions=forbidden,
        forbidden_adjacencies=typed_adjacency_exclusions(system),
        required_directions=(),
    )
    additions = tuple(sorted((item.variable_id, "c.arm") for item in system))
    provenance = JCIBackgroundKnowledgeRecord.from_base(
        base,
        assumption_ids=(JCI_CONTEXT_EXOGENEITY,),
        added_forbidden_directions=additions,
        required_directions=(),
    )
    return base, provenance


def build_jci_background(
    table: CausalTableRecord,
) -> tuple[BackgroundKnowledgeRecord, JCIBackgroundKnowledgeRecord]:
    """Return raw-C-free and explicitly constrained JCI knowledge artifacts."""
    try:
        return _build_jci_background(table)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _jci_error() from None


def _validate_jci_background_bundle(
    table: CausalTableRecord,
    base: BackgroundKnowledgeRecord,
    jci: JCIBackgroundKnowledgeRecord,
) -> None:
    checked_table = _snapshots_in_order((table,), CausalTableRecord, "table_id")[0]
    checked_base = _snapshots_in_order((base,), BackgroundKnowledgeRecord, "knowledge_id")[0]
    checked_jci = _snapshots_in_order((jci,), JCIBackgroundKnowledgeRecord, "knowledge_id")[0]
    expected_base, expected_jci = _build_jci_background(checked_table)
    if checked_base != expected_base or checked_jci != expected_jci:
        raise ValueError


def validate_jci_background_bundle(
    table: CausalTableRecord,
    base: BackgroundKnowledgeRecord,
    jci: JCIBackgroundKnowledgeRecord,
) -> None:
    """Validate exact table-bound knowledge before backend conversion."""
    try:
        _validate_jci_background_bundle(table, base, jci)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _jci_error() from None


__all__ = [
    "JCI_CONTEXT_EXOGENEITY",
    "build_jci_background",
    "build_jci_tables",
    "jci_stratum_key",
    "validate_jci_background_bundle",
    "validate_jci_relations",
    "validate_jci_table_bundle",
]
