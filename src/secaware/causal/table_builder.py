"""Exact Prompt-TSG/Oracle joins and bounded local categorical tables."""

from __future__ import annotations

from collections.abc import Sequence

from secaware.causal.variable_catalog import (
    CWE_SECURITY_OUTCOME,
    PRIMARY_OUTCOME,
    VariableDeclaration,
    declaration_by_id,
    declaration_sha256,
)
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.causal import (
    CausalExclusionReason,
    CausalExclusionRecord,
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    VariableRole,
)
from secaware.schema.common import model_shape_is_intact
from secaware.schema.features import FeatureState
from secaware.schema.oracle import OracleRecord, SecurityLabel
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import MotifId, PromptTSGRecord
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.motifs import motif_query_vector
from secaware.tsg.queries import feature_state


_MAX_VARIABLES = 64
_MAX_ROWS = 100_000
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


def _error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal_table",
        message="causal table assembly failed validation",
    )


def _bounded_tuple(value: object, *, maximum: int) -> tuple[object, ...]:
    if type(value) not in {list, tuple} or not 1 <= len(value) <= maximum:
        raise _error() from None
    return tuple(value)


def _scope_id(cwe: str) -> str:
    return f"scope.cwe_{cwe.removeprefix('CWE-')}"


def _snapshot_prompts(value: object) -> tuple[PromptRecord, ...]:
    raw = _bounded_tuple(value, maximum=_MAX_ROWS)
    result: list[PromptRecord] = []
    prompt_ids: set[str] = set()
    task_ids: set[str] = set()
    try:
        for item in raw:
            if type(item) is not PromptRecord or not model_shape_is_intact(item):
                raise ValueError
            snapshot = PromptRecord.model_validate(
                item.model_dump(mode="python", round_trip=True, warnings=False),
                strict=True,
            )
            if snapshot.split != "discover":
                continue
            if snapshot.prompt_id in prompt_ids or snapshot.task_id in task_ids:
                raise ValueError
            prompt_ids.add(snapshot.prompt_id)
            task_ids.add(snapshot.task_id)
            result.append(snapshot)
        if not result:
            raise ValueError
        return tuple(sorted(result, key=lambda item: item.prompt_id))
    except SecAwareError:
        raise
    except Exception:
        raise _error() from None


def _snapshot_graphs(
    value: object,
    prompts: tuple[PromptRecord, ...],
) -> dict[str, tuple[PromptTSGRecord, object]]:
    raw = _bounded_tuple(value, maximum=_MAX_ROWS)
    expected = {item.prompt_id: item for item in prompts}
    result: dict[str, tuple[PromptTSGRecord, object]] = {}
    try:
        for item in raw:
            if type(item) is not PromptTSGRecord or not model_shape_is_intact(item):
                raise ValueError
            snapshot = PromptTSGRecord.model_validate(
                item.model_dump(mode="python", round_trip=True, warnings=False)
            )
            source = expected.get(snapshot.prompt_id)
            if (
                source is None
                or snapshot.prompt_id in result
                or snapshot.task_id != source.task_id
                or snapshot.task_family != source.task_family
                or snapshot.cwe != source.cwe
            ):
                raise ValueError
            result[snapshot.prompt_id] = (snapshot, record_to_multidigraph(snapshot))
        if set(result) != set(expected):
            raise ValueError
        return result
    except SecAwareError:
        raise _error() from None
    except Exception:
        raise _error() from None


def _snapshot_oracles(
    value: object,
    prompts: tuple[PromptRecord, ...],
) -> dict[tuple[str, str, int], OracleRecord]:
    raw = _bounded_tuple(value, maximum=_MAX_ROWS)
    expected_prompts = {item.prompt_id for item in prompts}
    result: dict[tuple[str, str, int], OracleRecord] = {}
    request_ids: set[str] = set()
    unit_sets: dict[str, set[tuple[str, int]]] = {item: set() for item in expected_prompts}
    try:
        for item in raw:
            if type(item) is not OracleRecord or not model_shape_is_intact(item):
                raise ValueError
            snapshot = OracleRecord.model_validate(
                item.model_dump(mode="python", round_trip=True, warnings=False)
            )
            coordinate = (snapshot.prompt_id, snapshot.model_id, snapshot.seed_id)
            if (
                snapshot.condition != "observed"
                or snapshot.prompt_id not in expected_prompts
                or coordinate in result
                or snapshot.request_id in request_ids
            ):
                raise ValueError
            result[coordinate] = snapshot
            request_ids.add(snapshot.request_id)
            unit_sets[snapshot.prompt_id].add((snapshot.model_id, snapshot.seed_id))
        first = unit_sets[prompts[0].prompt_id]
        if not first or any(units != first for units in unit_sets.values()):
            raise ValueError
        exact = {
            (prompt_id, model_id, seed_id)
            for prompt_id in expected_prompts
            for model_id, seed_id in first
        }
        if set(result) != exact:
            raise ValueError
        return result
    except Exception:
        raise _error() from None


def _snapshot_declarations(value: object) -> tuple[VariableDeclaration, ...]:
    raw = _bounded_tuple(value, maximum=_MAX_VARIABLES)
    result: list[VariableDeclaration] = []
    try:
        for item in raw:
            if type(item) is not VariableDeclaration or declaration_by_id(item.variable_id) != item:
                raise ValueError
            result.append(item)
        ordered = tuple(sorted(result, key=lambda item: item.variable_id))
        if len({item.variable_id for item in ordered}) != len(ordered):
            raise ValueError
        if PRIMARY_OUTCOME not in ordered or CWE_SECURITY_OUTCOME not in ordered:
            raise ValueError
        return ordered
    except Exception:
        raise _error() from None


def secure_functional_value(oracle: OracleRecord) -> int:
    """Encode the primary outcome from typed Oracle fields only."""
    return int(
        oracle.parse_ok and oracle.functional_ok and oracle.security_label is SecurityLabel.SECURE
    )


def _declaration_applies(item: VariableDeclaration, cwe: str) -> bool:
    return item.applicable_cwes == ("*",) or cwe in item.applicable_cwes


def _variable_specs(
    declarations: tuple[VariableDeclaration, ...],
    *,
    scope_id: str,
    cwe: str,
) -> tuple[CausalVariableSpec, ...]:
    return tuple(
        CausalVariableSpec(
            schema_version="1.0",
            variable_id=item.variable_id,
            role=item.role,
            states=item.states,
            source_query_id=item.query_id,
            scope_id=scope_id,
            temporal_tier=item.tier,
            adjacency_type=item.adjacency_type,
            producer_sha256=declaration_sha256(item),
        )
        for item in declarations
        if _declaration_applies(item, cwe)
    )


def _pre_outcome_value(
    item: VariableDeclaration,
    source: PromptRecord,
    graph: object,
    motif_values: dict[MotifId, bool],
) -> int | FeatureState:
    if item.role is VariableRole.W:
        if item.variable_id == "w.language_family":
            return item.states.index(
                "python" if source.language.casefold() == "python" else "other"
            )
        if item.variable_id == "w.task_family":
            value = (
                source.task_family if source.task_family in _TASK_FAMILY_STATES[:-1] else "other"
            )
            return item.states.index(value)
        raise _error() from None
    if item.role is not VariableRole.X:
        raise _error() from None
    if item.variable_id.startswith("x.motif."):
        motif = MotifId(item.variable_id.removeprefix("x.motif."))
        return int(motif_values[motif])
    state = feature_state(graph, item.variable_id.removeprefix("x."))
    if state is FeatureState.ABSENT:
        return 0
    if state is FeatureState.PRESENT:
        return 1
    return state


def _outcome_value(item: VariableDeclaration, oracle: OracleRecord) -> int:
    if item == PRIMARY_OUTCOME:
        return secure_functional_value(oracle)
    if item == CWE_SECURITY_OUTCOME:
        return item.states.index(oracle.security_label.value)
    raise _error() from None


def _assemble_table(
    *,
    cwe: str,
    model_id: str,
    prompts: tuple[PromptRecord, ...],
    graphs: dict[str, tuple[PromptTSGRecord, object]],
    oracles: dict[tuple[str, str, int], OracleRecord],
    declarations: tuple[VariableDeclaration, ...],
    max_variables: int,
    max_rows: int,
    min_independent_tasks: int,
) -> tuple[
    CausalTableRecord, tuple[CausalObservationRecord, ...], tuple[CausalExclusionRecord, ...]
]:
    scope_id = _scope_id(cwe)
    selected_declarations = tuple(item for item in declarations if _declaration_applies(item, cwe))
    variables = _variable_specs(declarations, scope_id=scope_id, cwe=cwe)
    if not 2 <= len(variables) <= max_variables:
        raise _error() from None
    prompts_by_id = {item.prompt_id: item for item in prompts}
    coordinates = sorted(
        coordinate
        for coordinate in oracles
        if coordinate[1] == model_id and prompts_by_id[coordinate[0]].cwe == cwe
    )
    if not 2 <= len(coordinates) <= max_rows:
        raise _error() from None
    payloads: list[tuple[str, str, str, int, tuple[int, ...]]] = []
    exclusions: list[CausalExclusionRecord] = []
    for prompt_id, _model_id, seed_id in coordinates:
        source = prompts_by_id[prompt_id]
        graph_record, graph = graphs[prompt_id]
        motif_values = dict(motif_query_vector(graph))
        values: list[int] = []
        row_excluded = False
        for declaration in selected_declarations:
            if declaration.role is VariableRole.Y:
                continue
            encoded = _pre_outcome_value(declaration, source, graph, motif_values)
            if isinstance(encoded, FeatureState):
                reason = (
                    CausalExclusionReason.UNRESOLVED_FEATURE
                    if encoded is FeatureState.UNRESOLVED
                    else CausalExclusionReason.NOT_APPLICABLE_FEATURE
                )
                exclusions.append(
                    CausalExclusionRecord.from_content(
                        scope_id=scope_id,
                        cwe=cwe,
                        model_id=model_id,
                        task_id=source.task_id,
                        prompt_id=source.prompt_id,
                        seed_id=seed_id,
                        variable_id=declaration.variable_id,
                        reason_code=reason,
                        producer_sha256=graph_record.graph_sha256,
                    )
                )
                row_excluded = True
            else:
                values.append(encoded)
        if row_excluded:
            continue
        outcome = oracles[(prompt_id, model_id, seed_id)]
        values.extend(
            _outcome_value(declaration, outcome)
            for declaration in selected_declarations
            if declaration.role is VariableRole.Y
        )
        encoded_values = tuple(values)
        row_id = CausalObservationRecord.row_id_from_content(
            task_id=source.task_id,
            prompt_id=source.prompt_id,
            model_id=model_id,
            seed_id=seed_id,
            values=encoded_values,
        )
        payloads.append((row_id, source.task_id, source.prompt_id, seed_id, encoded_values))
    independent_tasks = len({item[1] for item in payloads})
    if not 2 <= len(payloads) <= max_rows or independent_tasks < min_independent_tasks:
        raise _error() from None
    table = CausalTableRecord.from_content(
        scope_id=scope_id,
        cwe=cwe,
        model_id=model_id,
        variables=variables,
        row_count=len(payloads),
        independent_task_count=independent_tasks,
        observation_payload=payloads,
    )
    rows = tuple(
        CausalObservationRecord.from_content(
            table=table,
            task_id=task_id,
            prompt_id=prompt_id,
            model_id=model_id,
            seed_id=seed_id,
            values=values,
        )
        for _row_id, task_id, prompt_id, seed_id, values in sorted(payloads)
    )
    return table, rows, tuple(exclusions)


def build_local_tables(
    prompts: Sequence[PromptRecord],
    prompt_tsgs: Sequence[PromptTSGRecord],
    oracles: Sequence[OracleRecord],
    declarations: Sequence[VariableDeclaration],
    *,
    max_variables: int = _MAX_VARIABLES,
    max_rows: int = _MAX_ROWS,
    min_independent_tasks: int = 2,
) -> tuple[
    tuple[CausalTableRecord, ...],
    tuple[CausalObservationRecord, ...],
    tuple[CausalExclusionRecord, ...],
]:
    """Build deterministic local tables after exact graph and Oracle coverage checks."""
    if (
        type(max_variables) is not int
        or not 2 <= max_variables <= _MAX_VARIABLES
        or type(max_rows) is not int
        or not 2 <= max_rows <= _MAX_ROWS
        or type(min_independent_tasks) is not int
        or not 2 <= min_independent_tasks <= max_rows
    ):
        raise _error() from None
    source_prompts = _snapshot_prompts(prompts)
    source_graphs = _snapshot_graphs(prompt_tsgs, source_prompts)
    source_oracles = _snapshot_oracles(oracles, source_prompts)
    source_declarations = _snapshot_declarations(declarations)
    tables: list[CausalTableRecord] = []
    rows: list[CausalObservationRecord] = []
    exclusions: list[CausalExclusionRecord] = []
    cwes = sorted({item.cwe for item in source_prompts})
    models = sorted({coordinate[1] for coordinate in source_oracles})
    try:
        for cwe in cwes:
            for model_id in models:
                table, local_rows, local_exclusions = _assemble_table(
                    cwe=cwe,
                    model_id=model_id,
                    prompts=source_prompts,
                    graphs=source_graphs,
                    oracles=source_oracles,
                    declarations=source_declarations,
                    max_variables=max_variables,
                    max_rows=max_rows,
                    min_independent_tasks=min_independent_tasks,
                )
                tables.append(table)
                rows.extend(local_rows)
                exclusions.extend(local_exclusions)
        result = (
            tuple(sorted(tables, key=lambda item: (item.scope_id, item.model_id))),
            tuple(sorted(rows, key=lambda item: (item.table_id, item.row_id))),
            tuple(sorted(exclusions, key=lambda item: item.exclusion_id)),
        )
        validate_local_table_bundle(*result)
        return result
    except SecAwareError:
        raise
    except Exception:
        raise _error() from None


def validate_local_table_bundle(
    tables: Sequence[CausalTableRecord],
    rows: Sequence[CausalObservationRecord],
    exclusions: Sequence[CausalExclusionRecord],
) -> None:
    """Jointly verify table commitments, row IDs, exact coverage, and exclusions."""
    try:
        checked_tables = tuple(CausalTableRecord.model_validate(item) for item in tables)
        checked_rows = tuple(CausalObservationRecord.model_validate(item) for item in rows)
        checked_exclusions = tuple(
            CausalExclusionRecord.model_validate(item) for item in exclusions
        )
        exclusion_keys = tuple(
            (
                item.scope_id,
                item.cwe,
                item.model_id,
                item.task_id,
                item.prompt_id,
                item.seed_id,
                item.variable_id,
            )
            for item in checked_exclusions
        )
        row_coordinates = {
            (item.model_id, item.task_id, item.prompt_id, item.seed_id) for item in checked_rows
        }
        if (
            not checked_tables
            or not checked_rows
            or checked_tables
            != tuple(sorted(checked_tables, key=lambda item: (item.scope_id, item.model_id)))
            or checked_rows
            != tuple(sorted(checked_rows, key=lambda item: (item.table_id, item.row_id)))
            or checked_exclusions
            != tuple(sorted(checked_exclusions, key=lambda item: item.exclusion_id))
            or len({item.table_id for item in checked_tables}) != len(checked_tables)
            or len({item.row_id for item in checked_rows}) != len(checked_rows)
            or len({item.exclusion_id for item in checked_exclusions}) != len(checked_exclusions)
            or len(set(exclusion_keys)) != len(exclusion_keys)
            or any(
                (item.model_id, item.task_id, item.prompt_id, item.seed_id) in row_coordinates
                for item in checked_exclusions
            )
        ):
            raise ValueError
        table_by_id = {item.table_id: item for item in checked_tables}
        for row in checked_rows:
            table = table_by_id.get(row.table_id)
            if (
                table is None
                or CausalObservationRecord.from_content(
                    table=table,
                    task_id=row.task_id,
                    prompt_id=row.prompt_id,
                    model_id=row.model_id,
                    seed_id=row.seed_id,
                    values=row.values,
                )
                != row
            ):
                raise ValueError
        for table in checked_tables:
            local_rows = tuple(item for item in checked_rows if item.table_id == table.table_id)
            payload = tuple(
                (item.row_id, item.task_id, item.prompt_id, item.seed_id, item.values)
                for item in local_rows
            )
            rebuilt = CausalTableRecord.from_content(
                scope_id=table.scope_id,
                cwe=table.cwe,
                model_id=table.model_id,
                variables=table.variables,
                row_count=len(local_rows),
                independent_task_count=len({item.task_id for item in local_rows}),
                observation_payload=payload,
            )
            if rebuilt != table:
                raise ValueError
        coordinates = {(item.scope_id, item.cwe, item.model_id) for item in checked_tables}
        if any(
            (item.scope_id, item.cwe, item.model_id) not in coordinates
            for item in checked_exclusions
        ):
            raise ValueError
    except Exception:
        raise _error() from None


__all__ = [
    "build_local_tables",
    "secure_functional_value",
    "validate_local_table_bundle",
]
