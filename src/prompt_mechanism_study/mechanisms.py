"""Data-driven, context-conditioned mechanism specifications."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prompt_mechanism_study.prompt_tsg import (
    PromptTSG,
    FeatureScope,
    PromptTSGError,
    QueryState,
    feature_state,
    scoped_feature_assessment,
    validate_feature_scope,
    prompt_tsg_from_record,
    query_context,
    query_for_realization,
    query_bindings,
    validate_prompt_tsg,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text


class MechanismRegistryError(ValueError):
    """Raised when a mechanism registry or task binding is invalid."""


@dataclass(frozen=True, slots=True)
class TaskHypothesisBinding:
    """One local subgraph follows the policy from candidate support to prompt editing."""

    task_id: str
    source_tsg_id: str
    policy_id: str
    context_query_id: str
    target_operation_node_id: str | None
    factor_feature_ids: tuple[str, ...]
    factor_operations: tuple[str, ...]
    feature_states: tuple[str, ...]
    target_subgraph_node_ids: tuple[str, ...]
    target_subgraph_edge_ids: tuple[str, ...]
    non_target_requirement_node_ids: tuple[str, ...]
    # A factor can address one data object at the operation, or the operation
    # itself. Task-local subject identities never become global factor IDs.
    factor_subject_node_ids: tuple[str | None, ...] = ()
    factor_scopes: tuple[FeatureScope, ...] = ()

    def __post_init__(self) -> None:
        if (
            len(self.factor_feature_ids) != 1
            or len(self.factor_operations) != 1
            or len(self.feature_states) != 1
            or self.factor_operations[0] not in {"add", "remove"}
            or len(self.factor_scopes) > 1
            or len(self.factor_subject_node_ids) > 1
        ):
            raise MechanismRegistryError("main requires one Atomic factor per binding")

    @property
    def binding_id(self) -> str:
        from dataclasses import asdict
        value = asdict(self)
        if not self.factor_subject_node_ids:
            value.pop("factor_subject_node_ids")  # Preserve frozen operation-only identities.
        if not self.factor_scopes:
            value.pop("factor_scopes")
        return content_id("task_hypothesis_binding_", value)


def bind_task_hypothesis(
    graph: PromptTSG,
    *,
    query: Mapping[str, Any],
    policy_id: str,
    target_operation_node_id: str | None = None,
    factor_feature_ids: tuple[str, ...],
    factor_operations: tuple[str, ...],
    factor_subject_node_ids: tuple[str | None, ...] = (),
    factor_scopes: tuple[FeatureScope, ...] = (),
) -> TaskHypothesisBinding:
    """Bind one Atomic factor directly to its source operation."""
    if graph.schema_version != "3.0":
        raise MechanismRegistryError("instance hypotheses require the active open graph schema")
    if (
        len(factor_feature_ids) != 1
        or len(set(factor_feature_ids)) != len(factor_feature_ids)
        or len(factor_operations) != len(factor_feature_ids)
        or any(op not in {"add", "remove"} for op in factor_operations)
    ):
        raise MechanismRegistryError(
            "a local hypothesis needs one explicit factor and edit operations"
        )
    context_semantics = set(query["required_semantics"]) | set(query["forbidden_semantics"])
    context_semantics |= {
        semantic
        for source, _, target in query["required_relations"]
        for semantic in (source, target)
    }
    if context_semantics & set(factor_feature_ids):
        raise MechanismRegistryError("hypothesis context must be invariant to its target features")
    if factor_scopes:
        if len(factor_scopes) != len(factor_feature_ids) or factor_subject_node_ids:
            raise MechanismRegistryError(
                "each factor needs one exact scope, without legacy subject coordinates"
            )
        if target_operation_node_id is not None and any(
            scope.operation_node_id != target_operation_node_id for scope in factor_scopes
        ):
            raise MechanismRegistryError(
                "factor scopes conflict with the shared operation coordinate"
            )
        try:
            for scope in factor_scopes:
                validate_feature_scope(graph, scope)
        except PromptTSGError as error:
            raise MechanismRegistryError(str(error)) from error
        operations = {scope.operation_node_id for scope in factor_scopes}
        target_operation_node_id = next(iter(operations)) if len(operations) == 1 else None
    else:
        target = next(
            (node for node in graph.nodes if node.node_id == target_operation_node_id), None
        )
        if target is None or target.node_type != "task_operation":
            raise MechanismRegistryError("hypothesis target must identify one operation instance")
        operations = {target_operation_node_id}
    context = query_context(graph, query=query, cwe="", task_family="")
    matches = [
        (nodes, edges)
        for nodes, edges in query_bindings(graph, query=query)
        if operations & set(nodes)
    ]
    if context.state is not QueryState.PRESENT or not operations <= {
        node for nodes, _ in matches for node in nodes
    }:
        raise MechanismRegistryError(
            "hypothesis has no source-supported coherent context at this operation"
        )
    nodes = {node for binding, _ in matches for node in binding}
    edges = {edge for _, binding in matches for edge in binding}
    by_id = {node.node_id: node for node in graph.nodes}
    if factor_subject_node_ids and len(factor_subject_node_ids) != len(factor_feature_ids):
        raise MechanismRegistryError("each factor needs exactly one subject coordinate")
    for subject, edit in zip(factor_subject_node_ids, factor_operations):
        if subject is None:
            continue
        subject_edges = [
            edge
            for edge in graph.edges
            if edge.source_id == subject
            and edge.target_id == target_operation_node_id
            and edge.edge_type == "used_by"
        ]
        if subject not in by_id or by_id[subject].node_type != "data_object" or not subject_edges:
            raise MechanismRegistryError(
                "factor subject must be a source-bound input of this operation"
            )
        if edit != "add":
            raise MechanismRegistryError(
                "subject-specific REMOVE needs a separately qualified source-scope rule"
            )
        nodes.add(subject)
        edges.update(edge.edge_id for edge in subject_edges)
    requirements = {
        edge.source_id
        for edge in graph.edges
        if edge.target_id in operations and edge.edge_type == "constrains"
    }
    if factor_scopes:
        assessments = [
            scoped_feature_assessment(graph, feature, scope)
            for feature, scope in zip(factor_feature_ids, factor_scopes, strict=True)
        ]
        target_requirements = {
            key for item in assessments if item for key in item.requirement_node_ids
        }
        for scope in factor_scopes:
            nodes.update(
                (scope.operation_node_id, *scope.subject_node_ids, *scope.condition_node_ids)
            )
        states = tuple(item.state if item else "unresolved" for item in assessments)
    else:
        target_requirements = {
            node for node in requirements if by_id[node].semantic_id in factor_feature_ids
        }
        states = tuple(
            feature_state(graph, feature, target_operation_node_id).value
            for feature in factor_feature_ids
        )
    nodes |= target_requirements
    if factor_scopes:
        edges |= {
            edge.edge_id
            for edge in graph.edges
            if edge.source_id in nodes and edge.target_id in nodes
        }
    else:
        edges |= {
            edge.edge_id
            for edge in graph.edges
            if edge.source_id in target_requirements
            and edge.target_id == target_operation_node_id
            and edge.edge_type == "constrains"
        }
    return TaskHypothesisBinding(
        graph.task_id,
        graph.tsg_id,
        policy_id,
        query["query_id"],
        target_operation_node_id,
        factor_feature_ids,
        factor_operations,
        states,
        tuple(sorted(nodes)),
        tuple(sorted(edges)),
        tuple(
            sorted(
                node.node_id
                for node in graph.nodes
                if node.node_type
                in {"task_requirement", "safety_requirement", "constraint", "presentation_control"}
                and node.node_id not in target_requirements
            )
        ),
        factor_subject_node_ids,
        factor_scopes,
    )


def render_task_hypothesis(
    binding: TaskHypothesisBinding, graph: PromptTSG, *, prompt: str,
    catalog: Mapping[str, Any], enabled: tuple[bool, ...], additions: Mapping[str, str],
    reviewed_variant: Mapping[str, Any] | None = None,
    inactive_texts: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Render the same operation-bound factors; unresolved source states never become absence."""
    validate_prompt_tsg(graph, prompt=prompt, catalog=catalog)
    if graph.tsg_id != binding.source_tsg_id or graph.task_id != binding.task_id:
        raise MechanismRegistryError("hypothesis binding does not match the exact source graph")
    subjects = binding.factor_subject_node_ids or (None,) * len(binding.factor_feature_ids)
    factor_scopes = binding.factor_scopes or tuple(FeatureScope(binding.target_operation_node_id,
        (subject,) if subject else ()) for subject in subjects)
    states = tuple(feature_state(graph, feature, scope=scope).value if binding.factor_scopes
                   else feature_state(graph, feature, binding.target_operation_node_id).value
                   for feature, scope in zip(binding.factor_feature_ids, factor_scopes, strict=True))
    if binding.feature_states != states:
        raise MechanismRegistryError("binding feature states differ from the explicit source graph assessments")
    if len(enabled) != len(binding.factor_feature_ids) or any(type(flag) is not bool for flag in enabled):
        raise MechanismRegistryError("arm must specify every frozen factor")
    if reviewed_variant is not None:
        return _render_reviewed_variant(binding, graph, prompt=prompt, catalog=catalog,
                                        enabled=enabled, variant=reviewed_variant, inactive_texts=inactive_texts or {})
    by_id = {node.node_id: node for node in graph.nodes}
    scopes = []
    for scope in factor_scopes:
        validate_feature_scope(graph, scope)
        if not {scope.operation_node_id, *scope.subject_node_ids, *scope.condition_node_ids} <= set(binding.target_subgraph_node_ids):
            raise MechanismRegistryError("factor scope binding changed before rendering")
        quote = lambda key: json.dumps(prompt[by_id[key].evidence_start:by_id[key].evidence_end], ensure_ascii=False)
        text = ""
        if scope.subject_node_ids:
            text += ("For the input described by " if len(scope.subject_node_ids) == 1 else "For the inputs described by ")
            text += ", ".join(quote(key) for key in scope.subject_node_ids) + ": "
        if scope.condition_node_ids:
            text += "Under the unchanged source conditions " + ", ".join(quote(key) for key in scope.condition_node_ids) + ": "
        scopes.append(text)
    removals, instructions, expected = [], [], []
    for feature, edit, state, active, subject_scope, scope in zip(binding.factor_feature_ids, binding.factor_operations,
                                            binding.feature_states, enabled, scopes, factor_scopes, strict=True):
        operation = by_id[scope.operation_node_id]
        required = "absent" if edit == "add" else "present"
        if state != required:
            raise MechanismRegistryError(f"{edit} requires explicit {required} at the exact target scope; got {state}")
        expected.append((feature, ("present" if edit == "add" else "absent") if active else state))
        if not active:
            if inactive_texts is not None and feature in inactive_texts:
                text = inactive_texts[feature]
                require_text(text, "frozen inactive factor text")
                instructions.append((operation.node_id, subject_scope + text))
            continue
        if edit == "add":
            text = additions.get(feature)
            require_text(text, "frozen addition text")
            instructions.append((operation.node_id, subject_scope + text))
        else:
            if binding.factor_scopes:
                assessment = scoped_feature_assessment(graph, feature, scope)
                requirements = [by_id[key] for key in assessment.requirement_node_ids]
            else:
                requirements = [by_id[edge.source_id] for edge in graph.edges
                                if edge.target_id == operation.node_id and edge.edge_type == "constrains"
                                and by_id[edge.source_id].semantic_id == feature]
            if len(requirements) != 1:
                raise MechanismRegistryError("removal needs one identifiable source requirement")
            node = requirements[0]
            allowed_targets = {operation.node_id, *scope.subject_node_ids}
            if any(edge.source_id == node.node_id and edge.target_id not in allowed_targets for edge in graph.edges):
                raise MechanismRegistryError("removal would change a requirement on another object")
            if binding.factor_scopes and any(item.feature_id == feature and item.scope != scope
                    and node.node_id in item.requirement_node_ids for item in graph.scoped_feature_assessments):
                raise MechanismRegistryError("removal would change a requirement assessed at another scope; needs a reviewed neutral rewrite")
            if any(other.node_id not in {node.node_id} and other.semantic_id != "task.root"
                   and max(node.evidence_start, other.evidence_start) < min(node.evidence_end, other.evidence_end)
                   for other in graph.nodes):
                raise MechanismRegistryError("removal overlaps non-target source evidence")
            removals.append((node.evidence_start, node.evidence_end))
    variant = prompt
    for start, end in sorted(set(removals), reverse=True):
        variant = variant[:start] + variant[end:]
    if instructions:
        for operation_id in dict.fromkeys(key for key, _ in instructions):
            operation = by_id[operation_id]
            operation_text = prompt[operation.evidence_start:operation.evidence_end]
            variant += "\n\nFor the operation described by " + json.dumps(operation_text, ensure_ascii=False) + ":\n"
            variant += "\n".join("- " + text for key, text in instructions if key == operation_id)
    result = {"binding_id": binding.binding_id, "task_id": binding.task_id, "policy_id": binding.policy_id,
            "source_tsg_id": binding.source_tsg_id, "target_operation_node_id": binding.target_operation_node_id,
            "enabled": list(enabled), "expected_feature_states": dict(expected), "prompt": variant,
            "prompt_sha256": content_hash(variant), "removed_source_spans": [list(span) for span in removals],
            "factor_subject_node_ids": list(subjects), "factor_scope_texts": scopes,
            "non_target_source_bytes_preserved": True}
    if binding.factor_scopes:
        from dataclasses import asdict
        result["factor_scopes"] = [asdict(scope) for scope in factor_scopes]
        result["expected_scoped_feature_states"] = [dict(scope=asdict(scope), feature_id=feature, state=state)
            for scope, (feature, state) in zip(factor_scopes, expected, strict=True)]
    return result


def _render_reviewed_variant(binding, graph, *, prompt, catalog, enabled, variant, inactive_texts):
    """Check a source-reviewed full realization, including shared-clause neutral rewrites.

    Projection and four-state checks constrain the review; they do not establish
    semantic accuracy. A frozen review record and later independent qualification
    are still needed. A reviewed realization preserves all non-target requirements.
    """
    from dataclasses import asdict

    if (
        not binding.factor_scopes
        or variant.get("binding_id") != binding.binding_id
        or variant.get("source_prompt_sha256") != content_hash(prompt)
        or variant.get("enabled") != list(enabled)
    ):
        raise MechanismRegistryError(
            "reviewed variant must bind the exact source, scopes and full arm"
        )
    review = variant.get("source_review", {})
    if review.get("outcomes_used") is not False:
        raise MechanismRegistryError("neutral rewrite requires an outcome-blind source review")
    for field in ("reviewer_id", "rationale"):
        require_text(review.get(field), "neutral rewrite source review " + field)
    for edit, state in zip(binding.factor_operations, binding.feature_states, strict=True):
        if state != ("absent" if edit == "add" else "present"):
            raise MechanismRegistryError(
                "reviewed edits cannot bypass the explicit source-state gate"
            )
    target_prompt = variant["prompt"]
    require_text(target_prompt, "reviewed variant prompt")
    target = prompt_tsg_from_record(variant["graph"])
    validate_prompt_tsg(target, prompt=target_prompt, catalog=catalog)
    if target.task_id != graph.task_id:
        raise MechanismRegistryError("reviewed variant changes task identity")
    node_map = variant["source_to_variant_nodes"]
    old = {node.node_id: node for node in graph.nodes if node.node_type != "task"}
    new = {node.node_id: node for node in target.nodes if node.node_type != "task"}
    neutral_nodes = variant.get("neutral_control_nodes", {})
    if set(neutral_nodes) != set(inactive_texts):
        raise MechanismRegistryError(
            "reviewed joint realization must identify every frozen neutral control"
        )
    for feature, key in neutral_nodes.items():
        if (
            key not in new
            or new[key].node_type != "presentation_control"
            or target_prompt[new[key].evidence_start : new[key].evidence_end]
            != inactive_texts[feature]
        ):
            raise MechanismRegistryError(
                "reviewed neutral control differs from its frozen source-bound text"
            )
    targeted_requirements = {
        key
        for feature, scope in zip(binding.factor_feature_ids, binding.factor_scopes, strict=True)
        for key in scoped_feature_assessment(graph, feature, scope).requirement_node_ids
    }
    preserved = set(old) - targeted_requirements
    if (
        not preserved <= set(node_map)
        or set(node_map) - set(old)
        or len(set(node_map.values())) != len(node_map)
        or set(node_map.values()) - set(new)
    ):
        raise MechanismRegistryError(
            "neutral rewrite needs a one-to-one map of all non-target source nodes"
        )
    for key in preserved:
        before, after = old[key], new[node_map[key]]
        if (
            before.node_type != after.node_type
            or before.semantic_id != after.semantic_id
            or prompt[before.evidence_start : before.evidence_end]
            != target_prompt[after.evidence_start : after.evidence_end]
        ):
            raise MechanismRegistryError("neutral rewrite changed non-target source evidence")
    source_edges = {
        (node_map[edge.source_id], edge.edge_type, node_map[edge.target_id])
        for edge in graph.edges
        if edge.source_id in preserved and edge.target_id in preserved
    }
    retained = {node_map[key] for key in preserved}
    target_edges = {
        (edge.source_id, edge.edge_type, edge.target_id)
        for edge in target.edges
        if edge.source_id in retained and edge.target_id in retained
    }
    if source_edges != target_edges:
        raise MechanismRegistryError("neutral rewrite changed non-target relation structure")

    def mapped_scope(scope):
        return FeatureScope(
            node_map[scope.operation_node_id],
            tuple(sorted(node_map[key] for key in scope.subject_node_ids)),
            tuple(sorted(node_map[key] for key in scope.condition_node_ids)),
        )

    changes = {
        (scope, feature): ("present" if edit == "add" else "absent") if flag else state
        for scope, feature, edit, state, flag in zip(
            binding.factor_scopes,
            binding.factor_feature_ids,
            binding.factor_operations,
            binding.feature_states,
            enabled,
            strict=True,
        )
    }
    expected = {
        (mapped_scope(item.scope), item.feature_id): changes.get(
            (item.scope, item.feature_id), item.state
        )
        for item in graph.scoped_feature_assessments
    }
    actual = {
        (item.scope, item.feature_id): item.state for item in target.scoped_feature_assessments
    }
    if actual != expected:
        raise MechanismRegistryError(
            "neutral rewrite changed another scope or did not realize its assigned factors"
        )
    # New source objects or requirements outside the declared factor-state table
    # cannot hide behind a correct target-state label.
    covered = (
        retained
        | set(neutral_nodes.values())
        | {key for item in target.scoped_feature_assessments for key in item.requirement_node_ids}
    )
    if set(new) - covered:
        raise MechanismRegistryError("neutral rewrite introduces an unaccounted source node")
    expected_rows = [
        dict(scope=asdict(scope), feature_id=feature, state=changes[scope, feature])
        for scope, feature in zip(binding.factor_scopes, binding.factor_feature_ids, strict=True)
    ]
    return {
        "binding_id": binding.binding_id,
        "task_id": binding.task_id,
        "policy_id": binding.policy_id,
        "source_tsg_id": binding.source_tsg_id,
        "target_operation_node_id": binding.target_operation_node_id,
        "enabled": list(enabled),
        "prompt": target_prompt,
        "prompt_sha256": content_hash(target_prompt),
        "expected_feature_states": {row["feature_id"]: row["state"] for row in expected_rows},
        "factor_scopes": [asdict(scope) for scope in binding.factor_scopes],
        "expected_scoped_feature_states": expected_rows,
        "rendering": "SOURCE_REVIEWED_JOINT_REALIZATION",
        "reviewed_variant_sha256": content_hash(variant),
        "non_target_source_bytes_preserved": False,
        "non_target_graph_projection_preserved": True,
        "semantic_fidelity_status": "SOURCE_REVIEWED_PENDING_INDEPENDENT_QUALIFICATION",
    }


@dataclass(frozen=True, slots=True)
class ControlPath:
    """One canonical directed Prompt-TSG path; it is semantic, not causal."""

    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if len(self.node_ids) < 2 or len(self.edge_ids) != len(self.node_ids) - 1:
            raise ValueError("a control path needs ordered nodes and one edge per step")
        if len(set(self.node_ids)) != len(self.node_ids) or len(set(self.edge_ids)) != len(
            self.edge_ids
        ):
            raise ValueError("a control path cannot repeat nodes or edges")
        for value in (*self.node_ids, *self.edge_ids):
            require_text(value, "control path identifier")

    @property
    def path_id(self) -> str:
        return content_id("prompt_tsg_control_path_", self)


@dataclass(frozen=True, slots=True)
class PromptControlBinding:
    """Outcome-blind binding from one actionable feature to graph evidence."""

    feature_id: str
    task_id: str
    task_unit_id: str
    prompt_tsg_id: str
    control_node_id: str
    source_node_ids: tuple[str, ...]
    sink_node_ids: tuple[str, ...]
    surface_node_ids: tuple[str, ...]
    paths: tuple[ControlPath, ...]
    alternative_group_node_ids: tuple[str, ...] = ()
    outcomes_or_arms_used: bool = False

    def __post_init__(self) -> None:
        for name in (
            "feature_id",
            "task_id",
            "task_unit_id",
            "prompt_tsg_id",
            "control_node_id",
        ):
            require_text(getattr(self, name), name)
        for values, name, required in (
            (self.source_node_ids, "control sources", True),
            (self.sink_node_ids, "control sinks", True),
            (self.surface_node_ids, "control surfaces", True),
            (self.alternative_group_node_ids, "alternative groups", False),
        ):
            if required and not values:
                raise ValueError(f"{name} cannot be empty")
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{name} must be unique and canonical")
            for value in values:
                require_text(value, name)
        if not self.paths or any(type(item) is not ControlPath for item in self.paths):
            raise TypeError("a control binding requires typed canonical paths")
        if tuple(sorted(self.paths, key=lambda item: item.path_id)) != self.paths:
            raise ValueError("control paths must use canonical content order")
        if len({item.path_id for item in self.paths}) != len(self.paths):
            raise ValueError("control binding paths must be unique")
        if any(
            path.node_ids[0] not in self.source_node_ids
            or path.node_ids[-1] not in self.sink_node_ids
            or self.control_node_id not in path.node_ids
            for path in self.paths
        ):
            raise ValueError("every control path must bind a declared source, control, and sink")
        if self.outcomes_or_arms_used is not False:
            raise ValueError("Prompt control bindings cannot use outcomes or assignments")

    @property
    def control_binding_id(self) -> str:
        return content_id("prompt_control_binding_", self)


def validate_prompt_control_binding(
    graph: PromptTSG,
    binding: PromptControlBinding,
) -> None:
    """Recompute every binding coordinate against the frozen Prompt TSG."""

    if type(graph) is not PromptTSG or type(binding) is not PromptControlBinding:
        raise TypeError("control binding validation requires typed graph and binding")
    if binding.prompt_tsg_id != graph.tsg_id or binding.task_id != graph.task_id:
        raise MechanismRegistryError("control binding graph identity drift")
    nodes = {item.node_id: item for item in graph.nodes}
    edges = {item.edge_id: item for item in graph.edges}
    referenced_nodes = {
        binding.control_node_id,
        *binding.source_node_ids,
        *binding.sink_node_ids,
        *binding.surface_node_ids,
        *binding.alternative_group_node_ids,
    }
    if not referenced_nodes <= set(nodes):
        raise MechanismRegistryError("control binding references a missing Prompt-TSG node")
    if nodes[binding.control_node_id].semantic_id != binding.feature_id:
        raise MechanismRegistryError("control node does not bind the declared actionable feature")
    for path in binding.paths:
        if not set(path.node_ids) <= set(nodes) or not set(path.edge_ids) <= set(edges):
            raise MechanismRegistryError("control path references missing graph evidence")
        for source_id, target_id, edge_id in zip(
            path.node_ids[:-1],
            path.node_ids[1:],
            path.edge_ids,
            strict=True,
        ):
            edge = edges[edge_id]
            if edge.source_id != source_id or edge.target_id != target_id:
                raise MechanismRegistryError("control path edge order does not replay")


def load_mechanism_registry(path: Path) -> dict[str, dict[str, Any]]:
    """Load and validate a registry keyed by realization id."""

    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"schema_version", "mechanisms"} or value["schema_version"] not in {
        "1.0",
        "2.0",
    }:
        raise MechanismRegistryError("mechanism registry envelope is invalid")
    rows = value["mechanisms"]
    if not isinstance(rows, list) or not rows:
        raise MechanismRegistryError("mechanism registry is empty")
    result: dict[str, dict[str, Any]] = {}
    legacy_fields = {
        "realization_id",
        "cwe_id",
        "task_family",
        "prompt_markers",
        "oracle_profile_id",
        "specific_contract",
        "must_preserve",
    }
    context_fields = {
        "realization_id",
        "cwe_id",
        "task_family",
        "required_context",
        "excluded_context",
        "oracle_profile_id",
        "required_delta",
        "forbidden_delta",
        "must_preserve",
    }
    required = legacy_fields if value["schema_version"] == "1.0" else context_fields
    for row in rows:
        if not isinstance(row, dict) or set(row) != required:
            raise MechanismRegistryError("mechanism record fields are invalid")
        realization_id = row["realization_id"]
        scalar_fields = ("realization_id", "cwe_id", "task_family", "oracle_profile_id")
        list_fields = (
            ("prompt_markers", "must_preserve")
            if value["schema_version"] == "1.0"
            else (
                "required_context",
                "excluded_context",
                "required_delta",
                "forbidden_delta",
                "must_preserve",
            )
        )
        if (
            any(not isinstance(row[field], str) or not row[field] for field in scalar_fields)
            or any(
                not isinstance(row[field], list)
                or any(not isinstance(item, str) or not item for item in row[field])
                for field in list_fields
            )
            or (
                value["schema_version"] == "1.0"
                and (
                    not isinstance(row["specific_contract"], str)
                    or not row["specific_contract"].strip()
                )
            )
            or (
                value["schema_version"] == "2.0"
                and (
                    not row["required_delta"]
                    or set(row["required_context"]) & set(row["excluded_context"])
                )
            )
            or realization_id in result
        ):
            raise MechanismRegistryError("mechanism record values are invalid")
        result[realization_id] = row
    return result


def mechanism_binding_id(binding: Mapping[str, Any]) -> str:
    """Return the content identity of one task-side binding core."""

    core = {key: value for key, value in binding.items() if key != "binding_id"}
    return content_id("mechanism_binding_", core)


def tsg_mechanism_binding(
    task: Mapping[str, Any],
    graph: PromptTSG,
    catalog: Mapping[str, Any],
    registry: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Bind one task using only its frozen Prompt TSG and finite catalog queries."""

    relevant = [
        row
        for row in registry.values()
        if row["cwe_id"] == task.get("cwe") and row["task_family"] == task.get("task_family")
    ]
    results = []
    for row in sorted(relevant, key=lambda item: item["realization_id"]):
        query = query_for_realization(catalog, row["realization_id"])
        result = query_context(
            graph,
            query=query,
            cwe=task["cwe"],
            task_family=task["task_family"],
        )
        results.append((row, query, result))
    present = [item for item in results if item[2].state == QueryState.PRESENT]
    selected = present[0] if len(present) == 1 else None
    feature = selected[1]["actionable_feature_id"] if selected else None
    target_state = feature_state(graph, feature).value if feature else "not_applicable"
    controls = {
        semantic_id: feature_state(graph, semantic_id).value
        for semantic_id in ("control.generic_security", "control.code_style")
    }
    if len(present) > 1 or (not present and any(
        item[2].state == QueryState.UNRESOLVED for item in results
    )):
        decision = "unresolved"
    elif not present:
        decision = "not_applicable"
    elif target_state != QueryState.ABSENT.value:
        decision = "target_feature_present" if target_state == "present" else "unresolved"
    elif any(state != QueryState.ABSENT.value for state in controls.values()):
        decision = "control_feature_present"
    else:
        decision = "applicable"
    core = {
        "decision": decision,
        "realization_id": selected[0]["realization_id"] if selected else None,
        "prompt_tsg_id": graph.tsg_id,
        "context_query_id": selected[1]["query_id"] if selected else None,
        "context_state": selected[2].state.value if selected else "unresolved" if decision == "unresolved" else "absent",
        "actionable_feature_id": feature,
        "target_feature_state": target_state,
        "control_feature_states": controls,
        "evidence_node_ids": list(selected[2].evidence_node_ids) if selected else [],
        "evidence_edge_ids": list(selected[2].evidence_edge_ids) if selected else [],
        "query_states": [
            {"query_id": query["query_id"], "state": result.state.value}
            for _, query, result in results
        ],
        "outcomes_or_arms_used": False,
    }
    return {"binding_id": mechanism_binding_id(core), **core}


__all__ = [
    "ControlPath",
    "MechanismRegistryError",
    "PromptControlBinding",
    "load_mechanism_registry",
    "mechanism_binding_id",
    "tsg_mechanism_binding",
    "validate_prompt_control_binding",
]
