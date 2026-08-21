"""Bounded endpoint-aware Prompt-side PAG path extraction and support."""

from __future__ import annotations

from collections.abc import Sequence

from secaware.causal.background import validate_pag_against_background
from secaware.causal.bootstrap import BootstrapDrawReplay, replay_bootstrap_draws
from secaware.causal.variable_catalog import (
    CWE_SECURITY_OUTCOME,
    PRIMARY_OUTCOME,
    declaration_by_id,
)
from secaware.config import FCIDiscoveryConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    BootstrapDrawRecord,
    BootstrapFailureRecord,
    BootstrapPAGRecord,
    CausalTableRecord,
    CausalObservationRecord,
    EndpointMark,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
    PathPatternRecord,
    PathSupportRecord,
    VariableRole,
)
from secaware.tsg.feature_catalog import prompt_feature_spec


_MAX_PATH_LENGTH = 16
_MAX_CANDIDATE_PATHS = 4096
_PREREGISTERED_OUTCOMES = frozenset(
    {
        PRIMARY_OUTCOME.variable_id,
        CWE_SECURITY_OUTCOME.variable_id,
        "y.discovery_cwe_secure",
        "y.discovery_secure_functional",
        "y.discovery_functional",
    }
)


def _path_error(message: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.paths",
        message=message,
    )


def edge_allows_possible_direction(
    edge: PAGEdgeRecord,
    source: str,
    target: str,
) -> bool:
    """Return whether endpoint marks permit the ordered source-to-target direction."""
    try:
        checked = PAGEdgeRecord.model_validate(edge)
        source_mark, target_mark = checked.marks_from(source, target)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _path_error("path edge failed validation") from None
    return source_mark in {EndpointMark.TAIL, EndpointMark.CIRCLE} and target_mark in {
        EndpointMark.ARROW,
        EndpointMark.CIRCLE,
    }


def endpoint_marks_compatible(reference: EndpointMark, replicate: EndpointMark) -> bool:
    """Preserve PAG uncertainty when matching one source-oriented endpoint mark."""
    try:
        reference_mark = EndpointMark(reference)
        replicate_mark = EndpointMark(replicate)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _path_error("path endpoint mark failed validation") from None
    return reference_mark is replicate_mark or EndpointMark.CIRCLE in {
        reference_mark,
        replicate_mark,
    }


def _is_intervenable_feature(variable_id: str) -> bool:
    if not variable_id.startswith("x."):
        return False
    try:
        return prompt_feature_spec(variable_id.removeprefix("x.")).intervenable
    except KeyError:
        return False


def _is_allowed_internal(variable_id: str) -> bool:
    try:
        return declaration_by_id(variable_id).role in {
            VariableRole.W,
            VariableRole.X,
            VariableRole.Z,
        }
    except KeyError:
        return False


def _edge_by_pair(pag: PAGRecord) -> dict[tuple[str, str], PAGEdgeRecord]:
    return {(edge.left, edge.right): edge for edge in pag.edges}


def _edge_for(
    edges: dict[tuple[str, str], PAGEdgeRecord], source: str, target: str
) -> PAGEdgeRecord:
    pair = (source, target) if source < target else (target, source)
    return edges[pair]


def enumerate_possible_prompt_paths(
    pag: PAGRecord,
    *,
    max_path_length: int,
    max_candidate_paths: int,
) -> tuple[PathPatternRecord, ...]:
    """Enumerate all bounded simple possible X-to-Y paths in canonical order."""
    try:
        checked = PAGRecord.model_validate(pag)
        if (
            type(max_path_length) is not int
            or not 1 <= max_path_length <= _MAX_PATH_LENGTH
            or type(max_candidate_paths) is not int
            or not 1 <= max_candidate_paths <= _MAX_CANDIDATE_PATHS
        ):
            raise _path_error("path bounds failed validation")

        edges = _edge_by_pair(checked)
        neighbors: dict[str, tuple[str, ...]] = {}
        for variable_id in checked.variable_ids:
            adjacent = [
                right if left == variable_id else left
                for left, right in edges
                if left == variable_id or right == variable_id
            ]
            neighbors[variable_id] = tuple(sorted(adjacent))

        candidates: list[PathPatternRecord] = []
        search_expansions = 0
        search_expansion_budget = max_candidate_paths * max_path_length
        starts = tuple(
            sorted(item for item in checked.variable_ids if _is_intervenable_feature(item))
        )

        def walk(variable_ids: tuple[str, ...]) -> None:
            nonlocal search_expansions
            current = variable_ids[-1]
            edge_count = len(variable_ids) - 1
            if edge_count >= max_path_length:
                return
            for target in neighbors[current]:
                if target in variable_ids:
                    continue
                edge = _edge_for(edges, current, target)
                if not edge_allows_possible_direction(edge, current, target):
                    continue
                extended = (*variable_ids, target)
                if target in _PREREGISTERED_OUTCOMES:
                    marks = tuple(
                        _edge_for(edges, source, destination).marks_from(source, destination)
                        for source, destination in zip(extended[:-1], extended[1:], strict=True)
                    )
                    candidates.append(
                        PathPatternRecord.from_content(
                            variable_ids=extended,
                            endpoint_marks=marks,
                        )
                    )
                    if len(candidates) > max_candidate_paths:
                        raise _path_error("candidate path limit exceeded")
                    continue
                if _is_allowed_internal(target):
                    search_expansions += 1
                    if search_expansions > search_expansion_budget:
                        raise _path_error("candidate path search limit exceeded")
                    walk(extended)

        for start in starts:
            walk((start,))
        by_semantics = {(item.variable_ids, item.endpoint_marks): item for item in candidates}
        if len(by_semantics) != len(candidates):
            raise _path_error("duplicate candidate path detected")
        return tuple(
            sorted(
                by_semantics.values(),
                key=lambda item: (
                    item.variable_ids,
                    tuple((left.value, right.value) for left, right in item.endpoint_marks),
                ),
            )
        )
    except (KeyboardInterrupt, SystemExit, SecAwareError):
        raise
    except Exception:
        raise _path_error("path enumeration failed validation") from None


def _marks_match(reference: PathPatternRecord, replicate: PathPatternRecord) -> bool:
    return reference.variable_ids == replicate.variable_ids and all(
        endpoint_marks_compatible(reference_mark, replicate_mark)
        for reference_pair, replicate_pair in zip(
            reference.endpoint_marks, replicate.endpoint_marks, strict=True
        )
        for reference_mark, replicate_mark in zip(reference_pair, replicate_pair, strict=True)
    )


def _validate_support_coordinates(
    *,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    reference_pag: PAGRecord,
    bootstrap_draws: tuple[BootstrapDrawRecord, ...],
    bootstrap_pags: tuple[BootstrapPAGRecord, ...],
    bootstrap_failures: tuple[BootstrapFailureRecord, ...],
    expected_replays: tuple[BootstrapDrawReplay, ...],
) -> str:
    config_sha256 = canonical_sha256(config.model_dump(mode="json"))
    variable_ids = tuple(item.variable_id for item in table.variables)
    if (
        reference_pag.run_kind is not PAGRunKind.OBSERVATIONAL_REFERENCE
        or reference_pag.table_id != table.table_id
        or reference_pag.backend != config.backend
        or reference_pag.backend_version != config.backend_version
        or reference_pag.ci_test != config.ci_test
        or reference_pag.variable_ids != variable_ids
        or reference_pag.config_sha256 != config_sha256
        or reference_pag.background_knowledge_sha256 != knowledge.knowledge_sha256
        or knowledge.table_id != table.table_id
        or len(bootstrap_draws) != config.bootstrap_samples
        or tuple(item.replicate_index for item in bootstrap_draws)
        != tuple(range(config.bootstrap_samples))
        or bootstrap_draws != tuple(item.draw for item in expected_replays)
        or any(
            draw.table_id != table.table_id
            or draw.run_kind is not PAGRunKind.OBSERVATIONAL_BOOTSTRAP
            for draw in bootstrap_draws
        )
    ):
        raise ValueError
    validate_pag_against_background(reference_pag, knowledge)

    result_by_replicate: dict[int, BootstrapPAGRecord | BootstrapFailureRecord] = {}
    for envelope in bootstrap_pags:
        index = envelope.replicate_index
        pag = envelope.pag
        if (
            index in result_by_replicate
            or not 0 <= index < config.bootstrap_samples
            or envelope.table_id != table.table_id
            or envelope.draw_id != bootstrap_draws[index].draw_id
            or envelope.matrix_sha256 != expected_replays[index].matrix_sha256
            or pag.run_kind is not PAGRunKind.OBSERVATIONAL_BOOTSTRAP
            or pag.table_id != table.table_id
            or pag.backend != config.backend
            or pag.backend_version != config.backend_version
            or pag.ci_test != config.ci_test
            or pag.variable_ids != variable_ids
            or pag.config_sha256 != config_sha256
            or pag.background_knowledge_sha256 != knowledge.knowledge_sha256
        ):
            raise ValueError
        validate_pag_against_background(pag, knowledge)
        result_by_replicate[index] = envelope
    for failure in bootstrap_failures:
        index = failure.replicate_index
        if (
            index in result_by_replicate
            or not 0 <= index < config.bootstrap_samples
            or failure.table_id != table.table_id
            or failure.draw_id != bootstrap_draws[index].draw_id
            or failure.fci_config_sha256 != config_sha256
        ):
            raise ValueError
        result_by_replicate[index] = failure
    if tuple(sorted(result_by_replicate)) != tuple(range(config.bootstrap_samples)):
        raise ValueError
    return config_sha256


def compute_bootstrap_path_support(
    *,
    table: CausalTableRecord,
    observations: Sequence[CausalObservationRecord],
    global_seed: int,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    reference_pag: PAGRecord,
    bootstrap_draws: Sequence[BootstrapDrawRecord],
    bootstrap_pags: Sequence[BootstrapPAGRecord],
    bootstrap_failures: Sequence[BootstrapFailureRecord],
) -> tuple[PathSupportRecord, ...]:
    """Count compatible exact paths over all configured bootstrap replicates."""
    try:
        checked_table = CausalTableRecord.model_validate(table)
        checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
        checked_config = FCIDiscoveryConfig.model_validate(config)
        expected_replays = replay_bootstrap_draws(
            table,
            observations,
            global_seed,
            checked_config.bootstrap_samples,
        )
        checked_reference = PAGRecord.model_validate(reference_pag)
        draws = tuple(BootstrapDrawRecord.model_validate(item) for item in bootstrap_draws)
        envelopes = tuple(BootstrapPAGRecord.model_validate(item) for item in bootstrap_pags)
        failures = tuple(BootstrapFailureRecord.model_validate(item) for item in bootstrap_failures)
        config_sha256 = _validate_support_coordinates(
            table=checked_table,
            knowledge=checked_knowledge,
            config=checked_config,
            reference_pag=checked_reference,
            bootstrap_draws=draws,
            bootstrap_pags=envelopes,
            bootstrap_failures=failures,
            expected_replays=expected_replays,
        )
        references = enumerate_possible_prompt_paths(
            checked_reference,
            max_path_length=checked_config.max_path_length,
            max_candidate_paths=checked_config.max_candidate_paths,
        )
        paths_by_replicate = {
            envelope.replicate_index: enumerate_possible_prompt_paths(
                envelope.pag,
                max_path_length=checked_config.max_path_length,
                max_candidate_paths=checked_config.max_candidate_paths,
            )
            for envelope in envelopes
        }
        return tuple(
            PathSupportRecord.from_content(
                table_id=checked_table.table_id,
                reference_pag_id=checked_reference.pag_id,
                path=reference,
                support_numerator=sum(
                    any(_marks_match(reference, replicate) for replicate in replicate_paths)
                    for replicate_paths in paths_by_replicate.values()
                ),
                support_denominator=checked_config.bootstrap_samples,
                bootstrap_config_sha256=config_sha256,
            )
            for reference in references
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _path_error("bootstrap support inputs failed validation") from None


__all__ = [
    "compute_bootstrap_path_support",
    "edge_allows_possible_direction",
    "endpoint_marks_compatible",
    "enumerate_possible_prompt_paths",
]
