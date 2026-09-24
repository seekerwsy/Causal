"""Data-driven, context-conditioned mechanism specifications."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from prompt_mechanism_study.tsg.prompt_tsg import (
    PromptTSG,
    FeatureScope,
    requirement_owned_nodes,
    requirement_policy_relations,
    PromptTSGError,
    QueryState,
    feature_state,
    scoped_feature_assessment,
    validate_feature_scope,
    prompt_tsg_from_record,
    query_context,
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
    context = query_context(graph, query=query)
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
    target_requirements = requirement_owned_nodes(graph, target_requirements)
    nodes |= target_requirements
    nodes.update(endpoint for requirement in target_requirements
                 for source, _, target in requirement_policy_relations(graph, requirement)
                 for endpoint in (source, target))
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
    object_features = {feature for feature, selector in catalog.get("feature_scope_selectors", {}).items()
                       if selector["scope_kind"] == "objects"}
    scopes = []
    for feature, scope in zip(binding.factor_feature_ids, factor_scopes, strict=True):
        validate_feature_scope(graph, scope)
        if not {scope.operation_node_id, *scope.subject_node_ids, *scope.condition_node_ids} <= set(binding.target_subgraph_node_ids):
            raise MechanismRegistryError("factor scope binding changed before rendering")
        quote = lambda key: json.dumps(prompt[by_id[key].evidence_start:by_id[key].evidence_end], ensure_ascii=False)
        text = ""
        if scope.subject_node_ids:
            noun = "source object" if feature in object_features else "input"
            text += f"For the {noun if len(scope.subject_node_ids) == 1 else noun + 's'} described by "
            text += ", ".join(quote(key) for key in scope.subject_node_ids) + ": "
        if scope.condition_node_ids:
            text += "Under the unchanged source conditions " + ", ".join(quote(key) for key in scope.condition_node_ids) + ": "
        scopes.append(text)
    removals, instructions, expected = [], [], []
    for feature, edit, state, active, subject_scope, scope in zip(binding.factor_feature_ids, binding.factor_operations,
                                            binding.feature_states, enabled, scopes, factor_scopes, strict=True):
        operation = by_id[scope.operation_node_id]
        object_policy = feature in object_features
        required = "absent" if edit == "add" else "present"
        if state != required:
            raise MechanismRegistryError(f"{edit} requires explicit {required} at the exact target scope; got {state}")
        expected.append((feature, ("present" if edit == "add" else "absent") if active else state))
        if not active:
            if inactive_texts is not None and feature in inactive_texts:
                text = inactive_texts[feature]
                require_text(text, "frozen inactive factor text")
                instructions.append((operation.node_id, object_policy, subject_scope + text))
            continue
        if edit == "add":
            text = additions.get(feature)
            require_text(text, "frozen addition text")
            instructions.append((operation.node_id, object_policy, subject_scope + text))
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
            owned = requirement_owned_nodes(graph, {node.node_id})
            allowed_targets = {operation.node_id, *scope.subject_node_ids}
            if any(edge.source_id == node.node_id and edge.target_id not in allowed_targets for edge in graph.edges):
                raise MechanismRegistryError("removal would change a requirement on another object")
            if binding.factor_scopes and any(item.feature_id == feature and item.scope != scope
                    and node.node_id in item.requirement_node_ids for item in graph.scoped_feature_assessments):
                raise MechanismRegistryError("removal would change a requirement assessed at another scope; needs a reviewed neutral rewrite")
            if any(other.node_id not in owned and other.semantic_id != "task.root"
                   and max(node.evidence_start, other.evidence_start) < min(node.evidence_end, other.evidence_end)
                   for other in graph.nodes):
                raise MechanismRegistryError("removal overlaps non-target source evidence")
            start, end = node.evidence_start, node.evidence_end
            # Removing the final/initial policy also removes its now-unused
            # separator, so the resulting source remains a valid trimmed input.
            if end == len(prompt):
                while start and prompt[start - 1].isspace():
                    start -= 1
            if start == 0:
                while end < len(prompt) and prompt[end].isspace():
                    end += 1
            removals.append((start, end))
    variant = prompt
    for start, end in sorted(set(removals), reverse=True):
        variant = variant[:start] + variant[end:]
    if instructions:
        for operation_id, object_policy in dict.fromkeys((key, objects) for key, objects, _ in instructions):
            operation = by_id[operation_id]
            operation_text = prompt[operation.evidence_start:operation.evidence_end]
            variant += ("\n\nFor the named source objects:\n" if object_policy else
                        "\n\nFor the runtime task as a whole:\n" if operation.node_type == "task" else
                        "\n\nFor the operation described by " + json.dumps(operation_text, ensure_ascii=False) + ":\n")
            variant += "\n".join("- " + text for key, objects, text in instructions
                                 if (key, objects) == (operation_id, object_policy))
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


def _reviewed_edit_scope(binding, graph, target, *, prompt, target_prompt, catalog, review, enabled,
                         node_map, source_owned, target_owned):
    """Read candidate-local source judgments without inferring global ownership.

    Quotes identify the reviewed source, not proof that a fact is policy-only.
    Graph checks can reject contradictory sharing; independent qualification
    must still establish the semantic accuracy of the source review.
    """
    scope = review.get("edit_scope", {})
    fields = {"source_nodes", "variant_nodes", "source_edges", "variant_edges"}
    if not isinstance(scope, Mapping) or set(scope) - fields:
        raise MechanismRegistryError("candidate edit scope fields are invalid")
    declarations = {}
    for field in fields:
        rows = scope.get(field, {})
        current, text = (graph, prompt) if field.startswith("source_") else (target, target_prompt)
        known = {item.node_id for item in current.nodes} if field.endswith("nodes") else {
            item.edge_id for item in current.edges}
        if not isinstance(rows, Mapping) or set(rows) - known:
            raise MechanismRegistryError("candidate edit scope references an unknown " + field)
        if field.endswith("edges"):
            roots = {node.node_id for node in current.nodes
                     if node.node_type == "task" and node.semantic_id == "task.root"}
            if any(edge.edge_id in rows and edge.source_id in roots
                   and edge.edge_type in {"contains", "requires"} for edge in current.edges):
                raise MechanismRegistryError("candidate edit scope cannot review compiled root membership")
        for row in rows.values():
            if (not isinstance(row, Mapping)
                or set(row) != {"status", "source_evidence", "rationale"}
                or row["status"] not in {"policy_only", "shared", "unresolved"}
                or not isinstance(row["source_evidence"], list) or not row["source_evidence"]):
                raise MechanismRegistryError("candidate edit scope judgment is invalid")
            require_text(row["rationale"], "candidate edit scope rationale")
            for citation in row["source_evidence"]:
                if (not isinstance(citation, Mapping) or set(citation) != {"start", "end"}
                    or type(citation["start"]) is not int or type(citation["end"]) is not int
                    or not 0 <= citation["start"] < citation["end"] <= len(text)
                    or not text[citation["start"]:citation["end"]].strip()):
                    raise MechanismRegistryError("candidate edit scope source evidence is invalid")
        declarations[field] = rows

    query = next((q for q in catalog["queries"] if q["query_id"] == binding.context_query_id), None)
    if scope and query is None:
        raise MechanismRegistryError("candidate edit scope needs the frozen context query")
    anchors = {s.operation_node_id for s in binding.factor_scopes}
    context_nodes = {key for nodes, _ in query_bindings(graph, query=query)
                     if anchors & set(nodes) for key in nodes} if query else set()
    root_before = next(n.node_id for n in graph.nodes if n.semantic_id == "task.root")
    root_after = next(n.node_id for n in target.nodes if n.semantic_id == "task.root")
    translated = {**node_map, root_before: root_after}
    retained_context = {translated[key] for key in context_nodes if key in translated}
    released, introduced, removable_edges, added_edges = set(), set(), set(), set()
    for side, current, owned, context, changed_nodes, changed_edges in (
        ("source", graph, source_owned, context_nodes, released, removable_edges),
        ("variant", target, target_owned, retained_context, introduced, added_edges),
    ):
        nodes = {n.node_id: n for n in current.nodes}
        edges = {e.edge_id: e for e in current.edges}
        protected = set(context)
        for assessment in current.scoped_feature_assessments:
            protected.update((assessment.scope.operation_node_id, *assessment.scope.subject_node_ids,
                              *assessment.scope.condition_node_ids))
        for owner, _, boundaries, _ in current.requirement_scopes:
            if owner not in owned:
                protected.update(boundaries)
        for owner, source, _, dest in current.requirement_relations:
            if owner not in owned:
                protected.update((source, dest))
        for edge in current.edges:
            endpoints = {edge.source_id, edge.target_id}
            # Independent order and non-target obligations are never waived by
            # saying an operation is exclusive to the edited policy.
            if (edge.edge_type == "precedes" or any(
                key not in owned and nodes[key].node_type in {
                    "task_requirement", "safety_requirement", "constraint", "presentation_control", "condition"}
                for key in endpoints)):
                protected.update(endpoints)
        # Protection is global by default, but an unchanged unknown elsewhere
        # does not make the current candidate unresolved.
        relevant = set(context) | owned
        relevant.update(key for relation in current.requirement_relations if relation[0] in owned
                        for key in (relation[1], relation[3]))
        relevant.update(key for edge in current.edges
                        if edge.source_id in owned or edge.target_id in owned
                        for key in (edge.source_id, edge.target_id))
        allowed = bool(enabled[0]) and binding.factor_operations[0] == (
            "remove" if side == "source" else "add")
        for key, row in declarations[side + "_nodes"].items():
            if row["status"] == "unresolved" and key in relevant:
                raise MechanismRegistryError("candidate edit scope has unresolved relevant support")
            if row["status"] != "policy_only":
                continue
            if (not allowed or nodes[key].node_type not in {"task_operation", "data_object"}
                or key in protected or (side == "source" and key in node_map)
                or (side == "variant" and key in node_map.values())):
                raise MechanismRegistryError("candidate edit scope cannot release shared or context facts")
            changed_nodes.add(key)
        for key, row in declarations[side + "_edges"].items():
            edge = edges[key]
            endpoints = {edge.source_id, edge.target_id}
            if row["status"] == "unresolved" and endpoints & (relevant | changed_nodes):
                raise MechanismRegistryError("candidate edit scope has unresolved relevant support")
            if row["status"] != "policy_only":
                continue
            if (not allowed or not endpoints & changed_nodes or edge.edge_type not in {"used_by", "produces"}
                or any(endpoint not in owned and nodes[endpoint].node_type in {
                    "task_requirement", "safety_requirement", "constraint", "presentation_control", "condition"}
                    for endpoint in endpoints)):
                raise MechanismRegistryError("candidate edit scope cannot waive independent relations")
            changed_edges.add(key)
        supported = set(owned)
        supported.update(key for relation in current.requirement_relations if relation[0] in owned
                         for key in (relation[1], relation[3]))
        supported.update(key for edge in current.edges
                         if edge.source_id in owned or edge.target_id in owned
                         for key in (edge.source_id, edge.target_id))
        # A reviewed label is necessary but cannot release an unrelated graph
        # component. This connectivity test does not infer semantic ownership.
        pending = True
        while pending:
            before = set(supported)
            for key in changed_edges:
                edge = edges[key]
                if {edge.source_id, edge.target_id} & supported:
                    supported.update((edge.source_id, edge.target_id))
            pending = supported != before
        if changed_nodes - supported:
            raise MechanismRegistryError("candidate edit scope facts are unrelated to the edited requirement")
        checked_semantics = {nodes[key].semantic_id for key in relevant | changed_nodes}
        if scope and enabled[0] and (
            checked_semantics & set(current.unresolved_semantics)
            or any({source, dest} & checked_semantics for source, _, dest in current.unresolved_relations)
        ):
            raise MechanismRegistryError("candidate edit scope has unresolved relevant support")
        for edge in current.edges:
            endpoints = {edge.source_id, edge.target_id}
            if (edge.edge_type in {"contains", "requires"} and edge.target_id in changed_nodes
                and nodes[edge.source_id].node_type == "task"
                and nodes[edge.source_id].semantic_id == "task.root"):
                # Root membership is compiled bookkeeping, not an independent
                # source assertion needing another semantic judgment.
                changed_edges.add(edge.edge_id)
            if endpoints & changed_nodes and not endpoints & owned and edge.edge_id not in changed_edges:
                raise MechanismRegistryError("candidate edit scope leaves an incident relation unreviewed")
    return released, introduced, removable_edges, added_edges


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
    source_owned = requirement_owned_nodes(graph, targeted_requirements)
    source_root = next(node.node_id for node in graph.nodes if node.semantic_id == "task.root")
    target_root = next(node.node_id for node in target.nodes if node.semantic_id == "task.root")
    scope_map = {**node_map, source_root: target_root}
    assigned_scopes = {(feature, FeatureScope(scope_map.get(scope.operation_node_id),
        tuple(sorted(scope_map.get(key, "") for key in scope.subject_node_ids)),
        tuple(sorted(scope_map.get(key, "") for key in scope.condition_node_ids))))
        for feature, scope in zip(binding.factor_feature_ids, binding.factor_scopes, strict=True)}
    target_owned = requirement_owned_nodes(target, {
        key for item in target.scoped_feature_assessments
        if (item.feature_id, item.scope) in assigned_scopes for key in item.requirement_node_ids})
    released, introduced, removable_edges, added_edges = _reviewed_edit_scope(
        binding, graph, target, prompt=prompt, target_prompt=target_prompt, catalog=catalog,
        review=review, enabled=enabled, node_map=node_map, source_owned=source_owned, target_owned=target_owned)
    preserved = set(old) - source_owned - released
    if (
        not preserved <= set(node_map)
        or set(node_map) - set(old)
        or len(set(node_map.values())) != len(node_map)
        or set(node_map.values()) - set(new)
    ):
        raise MechanismRegistryError(
            "neutral rewrite needs a one-to-one map of all non-target source nodes"
        )
    unchanged_blocks = None
    for key in preserved:
        before, after = old[key], new[node_map[key]]
        same_evidence = (prompt[before.evidence_start : before.evidence_end]
                         == target_prompt[after.evidence_start : after.evidence_end])
        if not same_evidence:
            if unchanged_blocks is None:
                unchanged_blocks = SequenceMatcher(None, prompt, target_prompt, autojunk=False).get_matching_blocks()
            # Citation granularity may differ only within the same unchanged
            # occurrence. This does not replace the source's semantic review.
            same_evidence = any(
                start <= before.evidence_start < before.evidence_end <= start + size
                and dest <= after.evidence_start < after.evidence_end <= dest + size
                and max(before.evidence_start - start, after.evidence_start - dest)
                    < min(before.evidence_end - start, after.evidence_end - dest)
                for start, dest, size in unchanged_blocks
            )
        if (
            before.node_type != after.node_type
            or before.semantic_id != after.semantic_id
            or not same_evidence
        ):
            raise MechanismRegistryError("neutral rewrite changed non-target source evidence")
    old_root = next(node.node_id for node in graph.nodes if node.semantic_id == "task.root")
    new_root = next(node.node_id for node in target.nodes if node.semantic_id == "task.root")
    boundary_map = {**node_map, old_root: new_root}
    source_edges = {
        (boundary_map[edge.source_id], edge.edge_type, boundary_map[edge.target_id])
        for edge in graph.edges
        if not {edge.source_id, edge.target_id} & source_owned
        and edge.edge_id not in removable_edges
    }
    retained = {node_map[key] for key in preserved}
    target_edges = {
        (edge.source_id, edge.edge_type, edge.target_id)
        for edge in target.edges
        if not {edge.source_id, edge.target_id} & (target_owned | set(neutral_nodes.values()))
        and edge.edge_id not in added_edges
    }
    if source_edges != target_edges:
        raise MechanismRegistryError("neutral rewrite changed non-target relation structure")

    old_structures = {(node_map[key], kind, tuple(sorted(node_map[child] for child in members)))
                      for key, kind, members in graph.requirement_structures
                      if key in preserved and set(members) <= preserved}
    new_structures = {(key, kind, members) for key, kind, members in target.requirement_structures
                      if key in retained and set(members) <= retained}
    old_scopes = {(node_map[key], kind, tuple(sorted(boundary_map[b] for b in boundaries)), target_class)
                  for key, kind, boundaries, target_class in graph.requirement_scopes if key in preserved}
    new_scopes = {(key, kind, boundaries, target_class)
                  for key, kind, boundaries, target_class in target.requirement_scopes if key in retained}
    if old_structures != new_structures or old_scopes != new_scopes:
        raise MechanismRegistryError("neutral rewrite changed non-target composition or scope")
    # Ownership makes the edited policy's relation disappear with its owner,
    # while independently supported order and other owners remain invariant.
    old_owned_relations = {(node_map[owner], boundary_map[source], kind, boundary_map[target])
                          for owner, source, kind, target in graph.requirement_relations
                          if owner in preserved}
    new_owned_relations = {(owner, source, kind, target)
                          for owner, source, kind, target in target.requirement_relations
                          if owner in retained}
    if old_owned_relations != new_owned_relations:
        raise MechanismRegistryError("neutral rewrite changed another requirement's owned relation")

    def mapped_scope(scope):
        return FeatureScope(
            boundary_map[scope.operation_node_id],
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
        | introduced
        | set(neutral_nodes.values())
        | requirement_owned_nodes(target, {key for item in target.scoped_feature_assessments for key in item.requirement_node_ids})
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


def load_mechanism_registry(path: Path) -> dict[str, dict[str, Any]]:
    """Read source/Oracle coordinates; candidate policies come from TSG bindings.

    Additional registry descriptions are retained but do not define or qualify
    an intervention. Only fields used by source selection and Oracle scope need
    validation here.
    """
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or set(value) != {"schema_version", "mechanisms"}
            or value["schema_version"] not in {"1.0", "2.0"}):
        raise MechanismRegistryError("mechanism registry envelope is invalid")
    rows = value["mechanisms"]
    if not isinstance(rows, list) or not rows:
        raise MechanismRegistryError("mechanism registry is empty")
    fields = ("realization_id", "cwe_id", "task_family", "oracle_profile_id")
    result = {}
    for row in rows:
        if not isinstance(row, dict) or any(
            not isinstance(row.get(field), str) or not row[field].strip() for field in fields
        ):
            raise MechanismRegistryError("mechanism profile coordinates are invalid")
        if row["realization_id"] in result:
            raise MechanismRegistryError("mechanism profile coordinates are duplicated")
        result[row["realization_id"]] = row
    return result


__all__ = [
    "MechanismRegistryError",
    "TaskHypothesisBinding",
    "bind_task_hypothesis",
    "load_mechanism_registry",
    "render_task_hypothesis",
]
