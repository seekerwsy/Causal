"""Offline interface diagnostic on already exposed sources; no provider or outcome access."""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import platform

from prompt_mechanism_study.artifact_io import write_bundle
from prompt_mechanism_study.candidate_construction import (
    candidate_request, compile_candidate_proposal, _occurrence_span,
)
from prompt_mechanism_study.mechanisms import bind_task_hypothesis, render_task_hypothesis
from prompt_mechanism_study.prompt_contract import (
    compile_task_context_contract, task_context_contract_from_record,
)
from prompt_mechanism_study.prompt_tsg import (
    FeatureScope, ScopedFeatureAssessment, prompt_tsg_record, requirement_covers_scope,
    validate_prompt_tsg,
)
from prompt_mechanism_study.records import content_hash


def local_nodes(contract, graph, prompt):
    result = {}
    for fact in contract.facts:
        span = _occurrence_span(prompt, fact["evidence_text"], fact["occurrence"])
        matches = [n for n in graph.nodes if n.semantic_id == fact["semantic_id"]
                   and (n.evidence_start, n.evidence_end) == span]
        if len(matches) != 1:
            raise ValueError("Diagnostic source fact must have one exact compiled node")
        result[fact["local_id"]] = matches[0]
    return result


def candidate_probe(request, node, scope, definition):
    """Submit a fixed source-bound probe; ordinary functionality is never approved."""
    source = request["sources"][0]
    response = dict(factors=[dict(label="Fixed diagnostic requirement", definition=definition,
        atomicity_rationale="Source-audit probe, not an approved editable security factor.",
        occurrences=[dict(task_id=source["task_id"], requirement_node_ids=[node.node_id],
                          scope=asdict(scope))])],
        dispositions=[dict(task_id=source["task_id"], requirement_node_id=n["node_id"],
            status="included" if n["node_id"] == node.node_id else "not_actionable",
            rationale="Focal interface probe only; remaining source requirements are held fixed.")
            for n in source["nodes"] if n["node_type"] in
            {"task_requirement", "safety_requirement", "constraint", "presentation_control"}])
    design = dict(outcome_id="oracle_evaluable_secure_code_yield", language_scope=["python"],
        api_scope=["source_audit"], task_archetype_scope=["source_audit"],
        operations=["add", "remove"], model_id="offline_interface_diagnostic", covariate_names=[],
        support_rule=dict(minimum_state_task_units=2, minimum_shared_lineages=1,
                          maximum_unresolved_fraction=0.2, minimum_feature_reliability=0.8))
    try:
        draft = compile_candidate_proposal(request, response, design)
    except ValueError as error:
        return dict(status="STRUCTURAL_REJECTION", error=str(error), approved_policies=0)
    return dict(status=draft["status"], proposed_factors=len(draft["factors"]),
                approved_policies=len(draft["policies"]), draft=draft)


def edit_probe(task, contract, graph, node, scope):
    """Exercise existing ADD/REMOVE gates with explicitly authored positive evidence."""
    nodes = {n.node_id: n for n in graph.nodes}
    links = {(e.source_id, e.edge_type, e.target_id) for e in graph.edges}
    evidence = tuple(sorted(n.node_id for n in graph.nodes if n.semantic_id == node.semantic_id
        and requirement_covers_scope(n.node_id, scope.operation_node_id, scope.subject_node_ids,
                                    scope.condition_node_ids, links=links,
                                    node_types={k: n.node_type for k, n in nodes.items()})))
    assessment = ScopedFeatureAssessment(scope, node.semantic_id, "present", evidence)
    assessed = replace(graph, scoped_feature_assessments=(assessment,))
    validate_prompt_tsg(assessed, prompt=task["prompt"], catalog=contract.catalog)
    op = nodes[scope.operation_node_id]
    # Native source concepts for this renderer probe. No relabeling into the new
    # candidate catalog and no claim that its fresh-extraction requirement ran.
    query = dict(query_id="offline_existing_scope", required_semantics=[op.semantic_id],
        forbidden_semantics=[], required_relations=[])
    outputs = {}
    for edit in ("add", "remove"):
        try:
            binding = bind_task_hypothesis(assessed, query=query, policy_id="diagnostic_"+edit,
                factor_feature_ids=(node.semantic_id,), factor_operations=(edit,),
                factor_scopes=(scope,))
            rendered = render_task_hypothesis(binding, assessed, prompt=task["prompt"],
                catalog=contract.catalog, enabled=(True,), additions={node.semantic_id:
                "Require the requested download file to remain within download_dir."})
            outputs[edit] = dict(status="MECHANICALLY_RENDERED_NOT_SEMANTICALLY_APPROVED",
                **rendered,
                permission_error_clause_retained='raise a "PermissionError" if the file is outside the download directory' in rendered["prompt"])
        except ValueError as error:
            outputs[edit] = dict(status="REJECTED", error=str(error))
    return dict(assessment_origin="Developer source audit, not LLM output or independent qualification",
                positive_evidence_node_ids=evidence, edits=outputs)


def run(inputs):
    results, graphs = [], {}
    for case in inputs["cases"]:
        task = case["task"]
        for variant in ("automatic", "source_reviewed"):
            contract = task_context_contract_from_record(case[variant+"_contract"])
            catalog = case["variant_catalogs"][variant]
            graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
            request = candidate_request([task], [contract], input_catalog=catalog)
            local = local_nodes(contract, graph, task["prompt"])
            by_id = {n.node_id: n for n in graph.nodes}
            inverse = {n.node_id: key for key, n in local.items()}
            links = {(e.source_id, e.edge_type, e.target_id) for e in graph.edges}
            graphs[case["case_id"]+":"+variant] = prompt_tsg_record(graph)
            for probe in case["probes"]:
                node = local[probe[variant]]
                targets = sorted(b for a, rel, b in links if a == node.node_id
                                 and rel == "constrains" and by_id[b].node_type == "task_operation")
                subjects = tuple(sorted(b for a, rel, b in links if a == node.node_id
                                 and rel == "constrains" and by_id[b].node_type == "data_object"))
                for target in targets:
                    conditions = tuple(sorted(a for a, rel, b in links if rel == "conditions"
                                              and b in {node.node_id, target}))
                    scope = FeatureScope(target, subjects, conditions)
                    result = dict(case_id=case["case_id"], task_unit_id=task.get("task_unit_id",task["task_id"]),
                        variant=variant, probe_id=probe["id"], role=probe["role"],
                        source_requirement=probe[variant], target=inverse[target],
                        subject_ids=[inverse[k] for k in subjects],
                        conditions=[contract.catalog["semantic_guidance"][by_id[k].semantic_id]
                                    for k in conditions],
                        definition=contract.catalog["semantic_guidance"][node.semantic_id],
                        final_security_intervention_admission=False)
                    result["candidate_probe"] = candidate_probe(request, node, scope, result["definition"])
                    if probe["role"] == "security_requirement":
                        result["edit_probe"] = edit_probe(task, contract, graph, node, scope)
                    results.append(result)
    source_root = Path(__file__).resolve().parents[3] / "src/prompt_mechanism_study"
    code = {name:hashlib.sha256((source_root/name).read_bytes()).hexdigest() for name in
            ("candidate_construction.py","mechanisms.py","prompt_tsg.py","prompt_contract.py")}
    return {
        "report.json": dict(status="EXECUTED_NON_CLAIM_OFFLINE_DIAGNOSTIC", task_units=len(inputs["cases"]),
            provider_calls=0, scientific_claim_allowed=False, automatic_candidate_discovery_executed=False,
            independently_qualified_references=False, approved_interventions=0,
            limitation="Known exposed cases and authored probes; no population accuracy, model comparison or graph-value claim.",
            input_sha256=content_hash(inputs), implementation_sha256=code,
            python=platform.python_version()),
        "results.json": results, "graphs.json": graphs,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Fresh output directory")
    args = parser.parse_args()
    inputs = json.loads(Path(__file__).with_name("inputs.json").read_text(encoding="utf-8"))
    outputs = run(inputs)
    write_bundle(args.output, outputs)
    print(json.dumps(outputs["report.json"], ensure_ascii=False, indent=2))
