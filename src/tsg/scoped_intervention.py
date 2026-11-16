"""Scope-bounded prompt intervention rendering driven by Prompt TSG bindings."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from prompt_mechanism_study.tsg.prompt_tsg import (
    REQUIREMENT_TYPES,
    PromptTSG,
    source_participation_paths,
)


VALID_INTERVENTION_MODES = ("baseline", "flat", "tsg_scoped")


def _snippet(prompt: str, start: int, end: int, *, limit: int = 120) -> str:
    text = " ".join(prompt[start:end].split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _node_label(
    node_id: str,
    nodes: Mapping[str, Any],
    reverse_local: Mapping[str, str],
    prompt: str,
) -> str:
    node = nodes[node_id]
    local = reverse_local.get(node_id, node.semantic_id)
    snippet = _snippet(prompt, node.evidence_start, node.evidence_end, limit=96)
    if snippet:
        return f"{local} (`{snippet}`)"
    return local


def render_prompt_intervention(
    task_prompt: str,
    *,
    mode: str,
    mechanisms: Sequence[Mapping[str, Any]],
    graph: PromptTSG | None = None,
    local_node_ids: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Render a matched baseline, unscoped flat, or TSG-scoped prompt intervention."""
    if mode not in VALID_INTERVENTION_MODES:
        raise ValueError(f"Unsupported intervention mode: {mode}")
    if not isinstance(task_prompt, str) or not task_prompt.strip():
        raise ValueError("task_prompt must be non-empty text")

    mech_list = [dict(item) for item in mechanisms]
    if mode == "baseline" or not mech_list:
        return {
            "mode": mode,
            "rendered_prompt": task_prompt,
            "applied_mechanisms": [],
            "target_operations": [],
            "protected_siblings": [],
            "scope_boundary": "none",
            "abstained": mode != "baseline" and not mech_list,
        }

    applied_ids = [str(item["mechanism_id"]) for item in mech_list]
    if mode == "flat":
        lines = [
            f"- Additional requirement: {str(item['instruction']).strip().rstrip('.')}. "
            "Apply uniformly across the entire module."
            for item in mech_list
        ]
        rendered = task_prompt.rstrip() + "\n\n" + "\n".join(lines)
        return {
            "mode": "flat",
            "rendered_prompt": rendered,
            "applied_mechanisms": applied_ids,
            "target_operations": [],
            "protected_siblings": [],
            "scope_boundary": "module_global",
            "abstained": False,
        }

    local_map = dict(local_node_ids or {})
    reverse_local = {node_id: local_id for local_id, node_id in local_map.items()}
    nodes = {node.node_id: node for node in graph.nodes} if graph is not None else {}
    links = {(edge.source_id, edge.edge_type, edge.target_id) for edge in graph.edges} if graph is not None else set()

    target_op_ids: set[str] = set()
    target_descriptions: list[str] = []
    target_operations: list[dict[str, Any]] = []

    for mech in mech_list:
        op_local = mech.get("operation_local_id")
        op_node_id = local_map.get(op_local) if isinstance(op_local, str) else None
        if op_node_id is not None and op_node_id not in nodes:
            op_node_id = None
        if op_node_id is not None:
            target_op_ids.add(op_node_id)
            op_text = _node_label(op_node_id, nodes, reverse_local, task_prompt)
        elif isinstance(op_local, str) and op_local.strip():
            op_text = op_local
        else:
            op_text = "declared sink operation"

        subj_locals = [str(s) for s in mech.get("subject_local_ids", ()) if isinstance(s, str)]
        subj_node_ids = [local_map[s] for s in subj_locals if s in local_map and local_map[s] in nodes]
        subject_labels: list[str] = []
        ownership_chains: list[list[str]] = []

        if graph is not None and op_node_id is not None and subj_node_ids:
            paths = source_participation_paths(graph, [op_node_id], subj_node_ids)
            if paths:
                for path in paths:
                    chain = [reverse_local.get(nid, nodes[nid].semantic_id) for nid in path["ownership_path_node_ids"]]
                    ownership_chains.append(chain)
                    chain_desc = " ->(part_of)-> ".join(chain)
                    subj_node = nodes[path["subject_node_id"]]
                    snippet = _snippet(task_prompt, subj_node.evidence_start, subj_node.evidence_end, limit=80)
                    subject_labels.append(f"{chain_desc} (`{snippet}`)" if snippet else chain_desc)

        if not subject_labels:
            for s in subj_locals:
                nid = local_map.get(s)
                if nid is not None and nid in nodes:
                    subject_labels.append(_node_label(nid, nodes, reverse_local, task_prompt))
                else:
                    subject_labels.append(s)

        cond_locals = [str(c) for c in mech.get("condition_local_ids", ()) if isinstance(c, str)]
        cond_labels = [
            _node_label(local_map[c], nodes, reverse_local, task_prompt)
            if c in local_map and local_map[c] in nodes
            else c
            for c in cond_locals
        ]

        subj_phrase = ", ".join(subject_labels) if subject_labels else "its bound untrusted input"
        cond_phrase = f" under condition [{'; '.join(cond_labels)}]" if cond_labels else ""
        instruction = str(mech["instruction"]).strip().rstrip(".")
        target_descriptions.append(
            f"- Target operation {op_text} on object(s) {subj_phrase}{cond_phrase}: {instruction}."
        )
        target_operations.append(
            {
                "mechanism_id": str(mech["mechanism_id"]),
                "operation_local_id": op_local,
                "operation_node_id": op_node_id,
                "subject_local_ids": subj_locals,
                "ownership_paths": ownership_chains,
            }
        )

    protected_siblings: list[dict[str, Any]] = []
    sibling_descriptions: list[str] = []
    if graph is not None:
        all_ops = sorted(
            (node for node in graph.nodes if node.node_type == "task_operation"),
            key=lambda item: (item.evidence_start, item.node_id),
        )
        for op in all_ops:
            if op.node_id in target_op_ids:
                continue
            contracts = sorted(
                (
                    nodes[src]
                    for src, kind, tgt in links
                    if tgt == op.node_id
                    and kind in {"about_operation", "constrains"}
                    and src in nodes
                    and nodes[src].node_type in REQUIREMENT_TYPES
                ),
                key=lambda item: (item.evidence_start, item.node_id),
            )
            contract_snippets = [_snippet(task_prompt, c.evidence_start, c.evidence_end, limit=96) for c in contracts]
            op_local_id = reverse_local.get(op.node_id, op.semantic_id)
            op_desc = _node_label(op.node_id, nodes, reverse_local, task_prompt)
            contract_text = "; ".join(contract_snippets) if contract_snippets else "exact input/output formatting and behavior"
            sibling_descriptions.append(f"- Sibling operation {op_desc}: preserve unchanged ({contract_text}).")
            protected_siblings.append(
                {
                    "operation_local_id": op_local_id,
                    "operation_node_id": op.node_id,
                    "preserved_contracts": contract_snippets,
                }
            )

    sections = [
        task_prompt.rstrip(),
        "",
        "[Task-Grounded Scope Directive (Prompt TSG)]",
        "Apply the following security requirement strictly to the bound target operation(s) and data object(s):",
        *target_descriptions,
    ]
    if sibling_descriptions:
        sections.extend(
            [
                "Preserve all sibling operation(s) strictly unchanged (do NOT alter, escape, sanitize, block, or reformat their inputs or outputs):",
                *sibling_descriptions,
            ]
        )
    else:
        sections.append(
            "Do not extend, generalize, or alter unrelated helper interfaces, return types, or formatting contracts outside the bound target operation."
        )

    return {
        "mode": "tsg_scoped",
        "rendered_prompt": "\n".join(sections),
        "applied_mechanisms": applied_ids,
        "target_operations": target_operations,
        "protected_siblings": protected_siblings,
        "scope_boundary": "operation_and_part_of",
        "abstained": False,
    }
