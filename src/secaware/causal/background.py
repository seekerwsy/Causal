"""TSG-derived causal background knowledge and fail-closed PAG checks."""

from __future__ import annotations

from collections.abc import Sequence

from causallearn.graph.GraphNode import GraphNode
from causallearn.utils.PCUtils.BackgroundKnowledge import BackgroundKnowledge

from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    CausalVariableSpec,
    EndpointMark,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
    VariableRole,
)


_MAX_VARIABLES = 64
_TEMPORAL_TIER_BY_ROLE = {
    VariableRole.W: 0,
    VariableRole.X: 1,
    VariableRole.Y: 2,
}
_OBSERVATIONAL_RUN_KINDS = frozenset(
    {
        PAGRunKind.OBSERVATIONAL_REFERENCE,
        PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
        PAGRunKind.RFCI_SENSITIVITY,
    }
)

_TypedEndpoint = tuple[VariableRole, str]

# This is a finite reviewed contract, not a rule synthesized from variable labels.
# Task metadata and prompt security controls are kept nonadjacent because their
# relationship must be represented through the intervening task/prompt structure.
_REVIEWED_TYPED_ADJACENCY_EXCLUSIONS: frozenset[frozenset[_TypedEndpoint]] = frozenset(
    {
        frozenset(
            {
                (VariableRole.W, "task_metadata"),
                (VariableRole.X, "prompt_safety_control"),
            }
        ),
    }
)


def _background_error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.background",
        message="causal background knowledge failed validation",
    )


def canonical_pair(left: str, right: str) -> tuple[str, str]:
    """Return one canonical representation of an undirected variable pair."""
    if type(left) is not str or type(right) is not str or not left or not right or left == right:
        raise ValueError("causal variable pair failed validation")
    return (left, right) if left < right else (right, left)


def _typed_adjacency_exclusions(
    variables: Sequence[CausalVariableSpec],
) -> tuple[tuple[str, str], ...]:
    if type(variables) not in {list, tuple} or not 2 <= len(variables) <= _MAX_VARIABLES:
        raise ValueError
    checked = tuple(CausalVariableSpec.model_validate(item) for item in variables)
    if len({item.variable_id for item in checked}) != len(checked):
        raise ValueError
    exclusions = {
        canonical_pair(left.variable_id, right.variable_id)
        for index, left in enumerate(checked)
        for right in checked[index + 1 :]
        if frozenset(
            {
                (left.role, left.adjacency_type),
                (right.role, right.adjacency_type),
            }
        )
        in _REVIEWED_TYPED_ADJACENCY_EXCLUSIONS
    }
    return tuple(sorted(exclusions))


def _typed_adjacency_exclusions_from_ids(
    variable_ids: Sequence[str],
) -> tuple[tuple[str, str], ...]:
    declarations = tuple(declaration_by_id(variable_id) for variable_id in variable_ids)
    exclusions = {
        canonical_pair(left.variable_id, right.variable_id)
        for index, left in enumerate(declarations)
        for right in declarations[index + 1 :]
        if frozenset(
            {
                (left.role, left.adjacency_type),
                (right.role, right.adjacency_type),
            }
        )
        in _REVIEWED_TYPED_ADJACENCY_EXCLUSIONS
    }
    return tuple(sorted(exclusions))


def typed_adjacency_exclusions(
    variables: Sequence[CausalVariableSpec],
) -> tuple[tuple[str, str], ...]:
    """Apply only the finite reviewed role/type incompatibility mapping."""
    result: tuple[tuple[str, str], ...] | None = None
    failed = False
    try:
        result = _typed_adjacency_exclusions(variables)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    finally:
        variables = ()
    if failed or result is None:
        raise _background_error() from None
    return result


def _build_background_knowledge(table: CausalTableRecord) -> BackgroundKnowledgeRecord:
    checked = CausalTableRecord.model_validate(table)
    variables = checked.variables
    expected_scope_id = f"scope.cwe_{checked.cwe.removeprefix('CWE-')}"
    if (
        any(
            not _variable_matches_declaration(
                variable,
                scope_id=checked.scope_id,
                cwe=checked.cwe,
            )
            for variable in variables
        )
        or checked.scope_id != expected_scope_id
    ):
        raise ValueError
    tiers = tuple((variable.variable_id, variable.temporal_tier) for variable in variables)
    forbidden = tuple(
        sorted(
            (later.variable_id, earlier.variable_id)
            for later in variables
            for earlier in variables
            if later.temporal_tier > earlier.temporal_tier
        )
    )
    return BackgroundKnowledgeRecord.from_content(
        table_id=checked.table_id,
        variable_ids=tuple(variable.variable_id for variable in variables),
        tiers=tiers,
        unconstrained_variable_ids=(),
        forbidden_directions=forbidden,
        forbidden_adjacencies=_typed_adjacency_exclusions(variables),
        required_directions=(),
    )


def _variable_matches_declaration(
    variable: CausalVariableSpec,
    *,
    scope_id: str,
    cwe: str,
) -> bool:
    declaration = declaration_by_id(variable.variable_id)
    if declaration.applicable_cwes != ("*",) and cwe not in declaration.applicable_cwes:
        return False
    expected = CausalVariableSpec(
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
    return variable == expected


def build_background_knowledge(table: CausalTableRecord) -> BackgroundKnowledgeRecord:
    """Derive exact observational tiers and reviewed exclusions from one table."""
    result: BackgroundKnowledgeRecord | None = None
    failed = False
    try:
        result = _build_background_knowledge(table)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    finally:
        table = None  # type: ignore[assignment]
    if failed or result is None:
        raise _background_error() from None
    return result


def _tier_reversals(knowledge: BackgroundKnowledgeRecord) -> set[tuple[str, str]]:
    return {
        (later_variable, earlier_variable)
        for later_variable, later_tier in knowledge.tiers
        for earlier_variable, earlier_tier in knowledge.tiers
        if later_tier > earlier_tier
    }


def _validate_knowledge_structure(
    knowledge: BackgroundKnowledgeRecord,
    *,
    observational: bool,
) -> None:
    tiered = {variable_id for variable_id, _tier in knowledge.tiers}
    unconstrained = set(knowledge.unconstrained_variable_ids)
    known = tiered | unconstrained
    tier_declarations = tuple(
        (declaration_by_id(variable_id), tier) for variable_id, tier in knowledge.tiers
    )
    tiers_match_roles = all(
        declaration.role in _TEMPORAL_TIER_BY_ROLE
        and declaration.variable_id.startswith(f"{declaration.role.value}.")
        and tier == declaration.tier == _TEMPORAL_TIER_BY_ROLE[declaration.role]
        for declaration, tier in tier_declarations
    )
    expected_directions = _tier_reversals(knowledge)
    expected_adjacencies = set(
        _typed_adjacency_exclusions_from_ids(
            tuple(variable_id for variable_id, _ in knowledge.tiers)
        )
    )
    actual_directions = set(knowledge.forbidden_directions)
    actual_adjacencies = set(knowledge.forbidden_adjacencies)
    is_jci_escape = bool(unconstrained)
    if (
        tiered & unconstrained
        or not 2 <= len(known) <= _MAX_VARIABLES
        or not tiers_match_roles
        or any(not variable_id.startswith("c.") for variable_id in unconstrained)
        or (observational and unconstrained)
        or knowledge.required_directions
        or (
            is_jci_escape
            and (
                not expected_directions <= actual_directions
                or not expected_adjacencies <= actual_adjacencies
            )
        )
        or (
            not is_jci_escape
            and (
                actual_directions != expected_directions
                or actual_adjacencies != expected_adjacencies
            )
        )
    ):
        raise ValueError


def _to_causal_learn_background(
    knowledge: BackgroundKnowledgeRecord,
) -> BackgroundKnowledge:
    checked = BackgroundKnowledgeRecord.model_validate(knowledge)
    _validate_knowledge_structure(checked, observational=False)
    node_by_id = {
        variable_id: GraphNode(variable_id)
        for variable_id in (
            *(item for item, _tier in checked.tiers),
            *checked.unconstrained_variable_ids,
        )
    }
    backend = BackgroundKnowledge()
    for variable_id, tier in checked.tiers:
        backend.add_node_to_tier(node_by_id[variable_id], tier)
    for source, target in checked.forbidden_directions:
        backend.add_forbidden_by_node(node_by_id[source], node_by_id[target])
    for left, right in checked.forbidden_adjacencies:
        backend.add_forbidden_by_node(node_by_id[left], node_by_id[right])
        backend.add_forbidden_by_node(node_by_id[right], node_by_id[left])
    expected_tiers = {node_by_id[variable_id]: tier for variable_id, tier in checked.tiers}
    expected_tier_entries = {(variable_id, tier) for variable_id, tier in checked.tiers}
    actual_tier_entries = tuple(
        (node.get_name(), tier) for tier, nodes in backend.tier_map.items() for node in nodes
    )
    expected_forbidden = {
        (node_by_id[source], node_by_id[target]) for source, target in checked.forbidden_directions
    } | {
        pair
        for left, right in checked.forbidden_adjacencies
        for pair in (
            (node_by_id[left], node_by_id[right]),
            (node_by_id[right], node_by_id[left]),
        )
    }
    if (
        backend.tier_value_map != expected_tiers
        or len(actual_tier_entries) != len(expected_tier_entries)
        or set(actual_tier_entries) != expected_tier_entries
        or backend.forbidden_rules_specs != expected_forbidden
        or backend.forbidden_pattern_rules_specs
        or backend.required_rules_specs
        or backend.required_pattern_rules_specs
        or backend.forbidden_within_tiers
    ):
        raise ValueError
    return backend


def to_causal_learn_background(
    knowledge: BackgroundKnowledgeRecord,
) -> BackgroundKnowledge:
    """Translate exact IDs to causal-learn without adding required edges."""
    result: BackgroundKnowledge | None = None
    failed = False
    try:
        result = _to_causal_learn_background(knowledge)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    finally:
        knowledge = None  # type: ignore[assignment]
    if failed or result is None:
        raise _background_error() from None
    return result


def _pag_permits_direction(edge: PAGEdgeRecord, source: str, target: str) -> bool:
    checked = PAGEdgeRecord.model_validate(edge)
    source_mark, target_mark = checked.marks_from(source, target)
    return source_mark in {EndpointMark.TAIL, EndpointMark.CIRCLE} and target_mark in {
        EndpointMark.ARROW,
        EndpointMark.CIRCLE,
    }


def pag_permits_direction(edge: PAGEdgeRecord, source: str, target: str) -> bool:
    """Return whether a PAG edge permits ``source`` to cause ``target``."""
    result: bool | None = None
    failed = False
    try:
        result = _pag_permits_direction(edge, source, target)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    finally:
        edge = None  # type: ignore[assignment]
        source = ""
        target = ""
    if failed or result is None:
        raise _background_error() from None
    return result


def _validate_pag_against_background(
    pag: PAGRecord,
    knowledge: BackgroundKnowledgeRecord,
) -> None:
    checked_pag = PAGRecord.model_validate(pag)
    checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
    _validate_knowledge_structure(
        checked_knowledge,
        observational=checked_pag.run_kind in _OBSERVATIONAL_RUN_KINDS,
    )
    knowledge_variables = {
        *(variable_id for variable_id, _tier in checked_knowledge.tiers),
        *checked_knowledge.unconstrained_variable_ids,
    }
    if (
        checked_pag.table_id != checked_knowledge.table_id
        or checked_pag.background_knowledge_sha256 != checked_knowledge.knowledge_sha256
        or set(checked_pag.variable_ids) != knowledge_variables
    ):
        raise ValueError
    edges = {canonical_pair(edge.left, edge.right): edge for edge in checked_pag.edges}
    for left, right in checked_knowledge.forbidden_adjacencies:
        if canonical_pair(left, right) in edges:
            raise ValueError
    for source, target in checked_knowledge.forbidden_directions:
        edge = edges.get(canonical_pair(source, target))
        if edge is not None and _pag_permits_direction(edge, source, target):
            raise ValueError


def validate_pag_against_background(
    pag: PAGRecord,
    knowledge: BackgroundKnowledgeRecord,
) -> None:
    """Revalidate a PAG and reject every possible background violation."""
    failed = False
    try:
        _validate_pag_against_background(pag, knowledge)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    finally:
        pag = None  # type: ignore[assignment]
        knowledge = None  # type: ignore[assignment]
    if failed:
        raise _background_error() from None


__all__ = [
    "build_background_knowledge",
    "canonical_pair",
    "pag_permits_direction",
    "to_causal_learn_background",
    "typed_adjacency_exclusions",
    "validate_pag_against_background",
]
