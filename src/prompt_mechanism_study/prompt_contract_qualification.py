"""Source-reference coverage, independent assertion review and extraction replay."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
    file_sha256,
    loads_exact_json,
)
from prompt_mechanism_study.mechanisms import load_mechanism_registry, tsg_mechanism_binding
from prompt_mechanism_study.prompt_contract import (
    compile_task_context_contract,
    task_context_contract_from_record,
)
from prompt_mechanism_study.prompt_contract_extract import (
    contract_decision_request,
    contract_from_response,
    contract_response_format,
)
from prompt_mechanism_study.prompt_tsg import PromptTSGError, load_catalog, prompt_tsg_record
from prompt_mechanism_study.records import canonical_json, content_hash


class PromptContractQualificationError(RuntimeError):
    """The Gate C inputs or deterministic replay closure are invalid."""


def evaluate_open_graph_expectations(graph: dict | None, *, prompt: str, expected: dict) -> dict:
    """Check prospectively written source anchors, roles and relations on exposed cases.

    This is a bounded development coverage check, not representation qualification.
    The source review must also assess unsupported assertions: exact quotations do
    not by themselves prove that a relation's meaning is correct. Matching uses
    source spans and generic roles, never a generator outcome or concept-name score.
    A prospectively declared semantic_overlap policy permits citation boundaries
    inside the reference phrase, requiring the same semantic identity and a shared
    word/number span. It aligns instances only; full-meaning support still requires
    assertion review. Omitted policy preserves frozen containment checks.
    """
    from prompt_mechanism_study.prompt_tsg import _occurrence_span

    if (expected.get("source_prompt_sha256") != content_hash(prompt) or not expected.get("nodes")
        or len({item["key"] for item in expected["nodes"]}) != len(expected["nodes"])
        or graph is not None and graph.get("prompt_sha256") != content_hash(prompt)):
        raise PromptContractQualificationError("development source expectations do not bind this exact input")
    nodes = [] if graph is None else graph["nodes"]
    alignment = expected.get("evidence_alignment", "contains")
    if alignment not in {"contains", "semantic_overlap"} or (
        alignment == "semantic_overlap" and any(not item.get("semantic_ids") for item in expected["nodes"])
    ):
        raise PromptContractQualificationError("source alignment needs a declared policy and semantic identities")
    edges = set() if graph is None else {
        (edge["source_id"], edge["edge_type"], edge["target_id"]) for edge in graph["edges"]
    }
    matches, checks, collective_matches = {}, [], set()
    def add(kind, key, status, **details):
        checks.append({"kind": kind, "key": key, "status": status,
                       "passed": True if status == "PASS" else False if status in {
                           "MISSING", "COLLAPSED_ROLES", "FORBIDDEN_RELATION", "WRONG_STATE"
                       } else None, **details})

    def endpoints(keys, *, allow_collectives=False):
        return [key for key in keys if len(matches[key]) != 1
                and not (allow_collectives and key in collective_matches and matches[key])]
    for item in expected["nodes"]:
        anchors = [item, *item.get("evidence_alternatives", [])]
        spans = [_occurrence_span(prompt, anchor["evidence_text"], anchor.get("occurrence", 1))
                 for anchor in anchors]
        allowed_types = item["node_types"]
        found = []
        def at_span(start, end):
            return sorted({node["node_id"] for node in nodes if node["node_type"] in allowed_types
                           and ("semantic_ids" not in item or node["semantic_id"] in item["semantic_ids"])
                           and ((node["evidence_start"] <= start and node["evidence_end"] >= end)
                                if alignment == "contains" else bool(re.search(r"[^\W_]", prompt[
                                    max(start, node["evidence_start"]):min(end, node["evidence_end"])])))})
        members = item.get("member_evidence")
        if members is not None and (not isinstance(members, list) or len(members) < 2
                                    or not item.get("semantic_ids")):
            raise PromptContractQualificationError("collective alignment needs distinct member anchors and semantics")
        # Alternatives are ordered fallback mentions of the same role. Do not
        # turn a later mention inside another object's description into a second
        # match when the primary source anchor already resolves the role.
        for start, end in spans:
            found = at_span(start, end)
            if found:
                break
        # A prospectively declared collective may instead be represented by ALL
        # its distinct members. One member or one broad node is insufficient.
        if not found and members:
            member_matches = [at_span(*_occurrence_span(prompt, anchor["evidence_text"],
                                                       anchor.get("occurrence", 1))) for anchor in members]
            if (all(len(group) == 1 for group in member_matches)
                    and len({group[0] for group in member_matches}) == len(members)):
                found = sorted(group[0] for group in member_matches)
                collective_matches.add(item["key"])
        matches[item["key"]] = found
        status = ("PASS" if len(found) == 1 or item["key"] in collective_matches
                  else "AMBIGUOUS_SOURCE_BINDING" if found else "MISSING")
        add("node", item["key"], status if graph is not None else "GRAPH_UNAVAILABLE",
            matched_node_ids=found)
    if alignment == "semantic_overlap":
        # Reference rows name distinct source instances. One broad citation must
        # not substitute a single model instance for two required instances.
        uses = Counter(node for key, found in matches.items()
                       if len(found) == 1 or key in collective_matches for node in found)
        for check in checks:
            found = matches[check["key"]]
            if (len(found) == 1 or check["key"] in collective_matches) and any(uses[node] > 1 for node in found):
                check.update(status="COLLAPSED_ROLES", passed=False)
                matches[check["key"]] = []
    for source, kind, target in expected.get("edges", []):
        blocked = endpoints([source, target], allow_collectives=True)
        status = ("BLOCKED_ENDPOINT_BINDING" if blocked else "PASS"
                  if all((s, kind, t) in edges for s in matches[source] for t in matches[target]) else "MISSING")
        add("edge", f"{source}/{kind}/{target}", status, blocked_by=blocked,
            matched_node_ids=sorted(set(matches[source]+matches[target])))
    for group in expected.get("distinct", []):
        blocked = endpoints(group)
        status = ("BLOCKED_ENDPOINT_BINDING" if blocked else "PASS"
                  if len({matches[key][0] for key in group}) == len(group) else "COLLAPSED_ROLES")
        add("distinct", "/".join(group), status, blocked_by=blocked,
            matched_node_ids=sorted({node for key in group for node in matches[key]}))
    for source, kind, target in expected.get("forbidden_edges", []):
        blocked = endpoints([source, target], allow_collectives=True)
        status = ("BLOCKED_ENDPOINT_BINDING" if blocked else "PASS"
                  if all((s, kind, t) not in edges for s in matches[source] for t in matches[target]) else "FORBIDDEN_RELATION")
        add("forbidden_edge_absent", f"{source}/{kind}/{target}", status, blocked_by=blocked,
            matched_node_ids=sorted(set(matches[source]+matches[target])))
    states = {} if graph is None else {(target, feature): state
                                       for target, feature, state in graph["feature_assessments"]}
    for item in expected.get("feature_checks", []):
        target = matches[item["target"]]
        scoped = "subjects" in item or "conditions" in item
        coordinates = [item["target"], *item.get("subjects", []), *item.get("conditions", [])]
        blocked = endpoints(coordinates)
        if scoped and not blocked:
            exact_scope = dict(operation_node_id=target[0],
                subject_node_ids=sorted(matches[key][0] for key in item.get("subjects", [])),
                condition_node_ids=sorted(matches[key][0] for key in item.get("conditions", [])))
            candidates = [] if graph is None else [row["state"] for row in graph.get("scoped_feature_assessments", [])
                if row["scope"] == exact_scope and row["feature_id"] == item["feature_id"]]
            state = candidates[0] if len(candidates) == 1 else None
        else:
            state = states.get((target[0], item["feature_id"])) if not blocked and not scoped else None
        status = ("BLOCKED_ENDPOINT_BINDING" if blocked else "PASS"
                  if state == item["state"] else "UNASSESSED_FEATURE" if state in {None, "unresolved"}
                  else "WRONG_STATE")
        key = item["target"] + "/" + item["feature_id"]
        if scoped:
            key += "/subjects=" + ",".join(sorted(item.get("subjects", [])))
            key += "/conditions=" + ",".join(sorted(item.get("conditions", [])))
        add("feature_state", key, status,
            actual_state=state, expected_state=item["state"],
            scope=exact_scope if scoped and not blocked else None, feature_id=item['feature_id'])
    check_by_key = {(row["kind"], row["key"]): row for row in checks}
    critical = [tuple(key) for key in expected.get("critical_checks", [])]
    if len(set(critical)) != len(critical) or any(key not in check_by_key for key in critical):
        raise PromptContractQualificationError("critical source checks must reference unique declared checks")
    critical_status = ("NOT_SPECIFIED" if not critical else "MET_PENDING_SEMANTIC_SOURCE_REVIEW"
                       if all(check_by_key[key]["passed"] is True for key in critical) else "REVIEW_REQUIRED")
    return {"status": "DEVELOPMENT_EXPECTATIONS_MET" if all(row["passed"] is True for row in checks)
            else "DEVELOPMENT_EXPECTATIONS_NOT_MET", "scientific_claim_allowed": False,
            "checks": checks, "passed": sum(row["passed"] is True for row in checks), "total": len(checks),
            "check_status_counts": dict(Counter(row["status"] for row in checks)),
            "sections": {kind: dict(Counter(row["status"] for row in checks if row["kind"] == kind))
                         for kind in sorted({row["kind"] for row in checks})},
            "critical_checks": [check_by_key[key] for key in critical],
            "critical_scope_status": critical_status,
            "format_status": "COMPILED_GRAPH" if graph is not None else "GRAPH_UNAVAILABLE",
            "semantic_coverage_status": "NOT_ESTIMATED_BY_SOURCE_ALIGNMENT_CHECK",
            "semantic_precision_status": "REQUIRES_SOURCE_REVIEW",
            "nodes": sum(node["node_type"] != "task" for node in nodes),
            "semantic_edges": sum(source != target and not any(
                node["node_id"] in {source, target} and node["node_type"] == "task" for node in nodes)
                for source, _, target in edges)}

def qualify_prompt_contract_extractor(
    repository_root: Path,
    tasks_path: Path,
    extraction_bundle: Path,
    catalog_path: Path,
    registry_path: Path | None,
    gold_path: Path,
    evaluator_path: Path,
    annotator_prompt_path: Path,
    output: Path,
    *,
    assertion_review_path: Path | None = None,
) -> dict[str, Any]:
    """Score active open graphs; closed-vocabulary records retain archival replay only."""

    if load_catalog(catalog_path).get("schema_version") == "2.0":
        return _qualify_open_contract(tasks_path, extraction_bundle, catalog_path, gold_path,
            evaluator_path, annotator_prompt_path, output, assertion_review_path)
    if registry_path is None:
        raise PromptContractQualificationError("closed-vocabulary replay requires its original archival registry")
    return _qualify_archival_contract(repository_root, tasks_path, extraction_bundle, catalog_path,
        registry_path, gold_path, evaluator_path, annotator_prompt_path, output)


def _qualify_archival_contract(
    repository_root: Path, tasks_path: Path, extraction_bundle: Path, catalog_path: Path,
    registry_path: Path, gold_path: Path, evaluator_path: Path, annotator_prompt_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Replay frozen closed-vocabulary evidence under its original interpretation."""

    root = repository_root.resolve()
    verify_bundle(extraction_bundle)
    bundle_report = read_json(extraction_bundle / "report.json")
    contracts = _rows(read_json(extraction_bundle / "contracts.json"))
    graph_rows = _rows(read_json(extraction_bundle / "graphs.json"))
    requests = _rows(read_json(extraction_bundle / "requests.json"))
    responses = _rows(read_json(extraction_bundle / "responses.json"))
    tasks = _rows(read_json(tasks_path))
    task_by_id = {row.get("task_id"): row for row in tasks}
    if len(task_by_id) != len(tasks) or None in task_by_id:
        raise PromptContractQualificationError("Prompt contract qualification task identities are invalid")

    gold = read_json(gold_path)
    required_gold = {
        "schema_version",
        "contract_protocol_id",
        "extractor_candidate_id",
        "selection_path",
        "review_completed_before_extraction",
        "arms_or_outcomes_used",
        "qualification_rule",
        "cases",
    }
    allowed_gold = {frozenset(required_gold), frozenset(required_gold | {"execution"})}
    if (
        not isinstance(gold, dict)
        or frozenset(gold) not in allowed_gold
        or gold["schema_version"] != "2.0"
        or gold["contract_protocol_id"]
        != "task_context_contract_v5_evidence_bound_single_annotation"
        or gold["review_completed_before_extraction"] is not True
        or gold["arms_or_outcomes_used"] is not False
    ):
        raise PromptContractQualificationError("Prompt contract qualification gold record is invalid")
    execution = gold.get("execution", {"task_workers": 1})
    if (
        not isinstance(execution, dict)
        or set(execution) != {"task_workers"}
        or type(execution["task_workers"]) is not int
        or not 1 <= execution["task_workers"] <= 8
    ):
        raise PromptContractQualificationError("Prompt contract execution policy is invalid")
    rule = gold["qualification_rule"]
    if (
        not isinstance(rule, dict)
        or set(rule)
        != {
            "minimum_exact_context_accuracy",
            "minimum_present_recall",
            "maximum_false_positive_present",
            "maximum_wrong_realization",
        }
        or type(rule["minimum_exact_context_accuracy"]) is not float
        or not 0 < rule["minimum_exact_context_accuracy"] <= 1
        or type(rule["minimum_present_recall"]) is not float
        or not 0 < rule["minimum_present_recall"] <= 1
        or type(rule["maximum_false_positive_present"]) is not int
        or rule["maximum_false_positive_present"] < 0
        or type(rule["maximum_wrong_realization"]) is not int
        or rule["maximum_wrong_realization"] < 0
    ):
        raise PromptContractQualificationError("Prompt contract qualification rule is invalid")

    selection_path = (root / gold["selection_path"]).resolve()
    try:
        selection_path.relative_to(root)
    except ValueError:
        raise PromptContractQualificationError("Prompt contract qualification selection escapes repository") from None
    selection = read_json(selection_path)
    cases = _rows(gold["cases"])
    case_ids = [case.get("task_id") for case in cases]
    evaluator = read_json(evaluator_path)
    if not isinstance(evaluator, dict):
        raise PromptContractQualificationError("Prompt contract evaluator record is invalid")
    candidate_id = f"single-evidence:{evaluator.get('candidate_id')}"
    expected_report = {
        "status": "PROMPT_CONTRACT_EXTRACTION_COMPLETE",
        "protocol_id": gold["contract_protocol_id"],
        "tasks": len(cases),
        "contracts": len(cases),
        "graphs": len(cases),
        "provider_calls": len(cases),
        "task_workers": execution["task_workers"],
        "effective_task_workers": min(execution["task_workers"], len(cases)),
        "candidate_id": candidate_id,
        "task_file_sha256": _sha256(tasks_path),
        "task_selection_sha256": _sha256(selection_path),
        "evaluator_sha256": _sha256(evaluator_path),
        "annotator_prompt_sha256": _sha256(annotator_prompt_path),
        "response_protocol_id": "task_keyed_prompt_contract_catalog_attributes_v2",
        "annotation_policy_id": "single_annotation_valid_evidence_v1",
        "model_visible_routing_labels": False,
        "failed_task_unit_count": 0,
        "failed_task_units": [],
        "review_status": "prospective_frozen",
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    if (
        gold["extractor_candidate_id"] != candidate_id
        or case_ids != selection.get("task_ids")
        or selection.get("source_tasks_sha256") != _sha256(tasks_path)
        or any(bundle_report.get(key) != value for key, value in expected_report.items())
        or not all(
            len(rows) == len(cases)
            for rows in (contracts, graph_rows, requests, responses)
        )
    ):
        raise PromptContractQualificationError("Prompt contract qualification inputs do not close")

    catalog = load_catalog(catalog_path)
    registry = load_mechanism_registry(registry_path)
    if bundle_report.get("catalog_sha256") != hashlib.sha256(
        canonical_json(catalog).encode("utf-8")
    ).hexdigest():
        raise PromptContractQualificationError("Prompt contract catalog identity drifted")
    contract_by_task = {
        row.get("task_id"): row for row in contracts if isinstance(row.get("task_id"), str)
    }
    graph_by_task = {
        row.get("task_id"): row for row in graph_rows if isinstance(row.get("task_id"), str)
    }
    request_by_task = {
        row.get("task_id"): row for row in requests if isinstance(row.get("task_id"), str)
    }
    response_by_task = {
        row.get("task_id"): row for row in responses if isinstance(row.get("task_id"), str)
    }
    populations = (contract_by_task, graph_by_task, request_by_task, response_by_task)
    if any(set(rows) != set(case_ids) for rows in populations):
        raise PromptContractQualificationError("Prompt contract bundle population differs from gold")

    results = []
    for case in cases:
        if set(case) != {
            "task_id",
            "expected_context",
            "expected_realization_id",
            "rationale",
        } or case["expected_context"] not in {
            "present",
            "absent",
            "unresolved",
            "absent_or_unresolved",
        }:
            raise PromptContractQualificationError("Prompt contract qualification case is invalid")
        task = task_by_id.get(case["task_id"])
        if task is None:
            raise PromptContractQualificationError("Prompt contract qualification task is missing")
        response = response_by_task[case["task_id"]]
        response_fields = {
            "task_id",
            "response_format_sha256",
            "provider_calls",
            "status",
            "response_sha256",
            "response_text",
            "error_type",
            "error_message",
        }
        if (
            set(response) != response_fields
            or response["provider_calls"] != 1
            or response["status"] != "complete"
            or response["error_type"] is not None
            or response["error_message"] is not None
            or not isinstance(response["response_text"], str)
        ):
            raise PromptContractQualificationError("Prompt contract response closure fields are invalid")
        expected_request = contract_decision_request(task, catalog)
        if response["response_format_sha256"] != content_hash(
            contract_response_format(expected_request)
        ):
            raise PromptContractQualificationError("Prompt contract response format identity is invalid")
        raw = response["response_text"].encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != response["response_sha256"]:
            raise PromptContractQualificationError("Prompt contract response identity is invalid")
        try:
            replayed = contract_from_response(
                raw, task=task, catalog=catalog, annotator_id=candidate_id,
                review_status="prospective_frozen",
            )
            contract = task_context_contract_from_record(contract_by_task[case["task_id"]])
            if replayed != contract:
                raise PromptContractQualificationError("single annotation replay differs")
            graph = compile_task_context_contract(
                contract, prompt=task["prompt"], catalog=catalog
            )
        except PromptTSGError as error:
            raise PromptContractQualificationError(str(error)) from None
        if (
            request_by_task[case["task_id"]] != {"task_id": case["task_id"], "request": expected_request}
            or prompt_tsg_record(graph) != graph_by_task[case["task_id"]]
            or contract.annotator_id != candidate_id
            or contract.review_status != "prospective_frozen"
        ):
            raise PromptContractQualificationError("Prompt contract deterministic replay differs")
        binding = tsg_mechanism_binding(task, graph, catalog, registry)
        actual_context = (
            "present"
            if binding["realization_id"] is not None
            else "unresolved"
            if binding["decision"] == "unresolved"
            else "absent"
        )
        context_matched = actual_context == case["expected_context"] or (
            case["expected_context"] == "absent_or_unresolved"
            and actual_context in {"absent", "unresolved"}
        )
        matched = context_matched and (
            binding["realization_id"] == case["expected_realization_id"]
        )
        results.append(
            {
                "task_id": case["task_id"],
                "expected_context": case["expected_context"],
                "actual_context": actual_context,
                "expected_realization_id": case["expected_realization_id"],
                "actual_realization_id": binding["realization_id"],
                "binding_decision": binding["decision"],
                "matched": matched,
            }
        )

    mismatches = [row for row in results if not row["matched"]]
    expected_present = [row for row in results if row["expected_context"] == "present"]
    if not expected_present:
        raise PromptContractQualificationError("Prompt contract qualification lacks positive gold")
    present_recovered = [
        row
        for row in expected_present
        if row["actual_context"] == "present"
        and row["actual_realization_id"] == row["expected_realization_id"]
    ]
    false_positive_present = [
        row
        for row in results
        if row["expected_context"] != "present" and row["actual_context"] == "present"
    ]
    wrong_realization = [
        row
        for row in results
        if row["actual_realization_id"] is not None
        and row["actual_realization_id"] != row["expected_realization_id"]
    ]
    exact_accuracy = (len(results) - len(mismatches)) / len(results)
    present_recall = len(present_recovered) / len(expected_present)
    qualified = (
        exact_accuracy >= rule["minimum_exact_context_accuracy"]
        and present_recall >= rule["minimum_present_recall"]
        and len(false_positive_present) <= rule["maximum_false_positive_present"]
        and len(wrong_realization) <= rule["maximum_wrong_realization"]
    )
    positive_gold_realization_ids = sorted(
        {
            row["expected_realization_id"]
            for row in cases
            if row["expected_context"] == "present"
        }
    )
    catalog_realization_ids = sorted(
        {query["realization_id"] for query in catalog["queries"]}
    )
    report = {
        "schema_version": "2.0",
        "status": "QUALIFIED_FOR_FORMAL_EXTRACTION" if qualified else "QUALIFICATION_FAILED",
        "contract_protocol_id": gold["contract_protocol_id"],
        "extractor_candidate_id": candidate_id,
        "holdout_task_units": len(cases),
        "matched_task_units": len(cases) - len(mismatches),
        "mismatched_task_units": len(mismatches),
        "exact_context_accuracy": round(exact_accuracy, 6),
        "present_recall": round(present_recall, 6),
        "false_positive_present": len(false_positive_present),
        "wrong_realization": len(wrong_realization),
        "qualification_rule": rule,
        "positive_gold_realization_ids": positive_gold_realization_ids,
        "catalog_realization_ids_without_positive_gold": sorted(
            set(catalog_realization_ids) - set(positive_gold_realization_ids)
        ),
        "context_counts": dict(
            sorted(Counter(row["expected_context"] for row in cases).items())
        ),
        "extractor_bundle_sha256": bundle_digest(extraction_bundle),
        "extractor_implementation_sha256": bundle_report[
            "extractor_implementation_sha256"
        ],
        "catalog_sha256": _sha256(catalog_path),
        "registry_sha256": _sha256(registry_path),
        "gold_sha256": _sha256(gold_path),
        "selection_sha256": _sha256(selection_path),
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
        "claim_boundary": (
            "Gate C qualifies task-context selection only for expected-present realizations "
            "represented in this frozen source-only holdout; it is not effect evidence."
        ),
    }
    write_bundle(output, {"case-results.json": results, "qualification.json": report})
    return report


_OPEN_REFERENCE = "open_tsg_source_semantics"


def representation_implementation_identity() -> str:
    """Bind the small scientific producer, including scope compilation and input preparation."""
    folder = Path(__file__).parent
    return content_hash({name: file_sha256(folder / name) for name in (
        "prompt_contract_extract.py", "source_records.py", "prompt_contract.py", "prompt_tsg.py", "task_input.py",
        "functional_judge.py", "prompt_contract_qualification.py",
    )})


def validate_open_source_reference(reference: dict, *, bindings: dict, tasks: list[dict]) -> None:
    """Validate the prospective reference before any output is obtained; never show it to the model.

    Independence and exposure are attestations requiring external review, not facts
    that a hash or this validator can establish. Synthetic fixtures cannot qualify.
    """
    if (reference.get("protocol_id") != _OPEN_REFERENCE
        or reference.get("reference_kind") not in {"INDEPENDENT_SOURCE_REFERENCE", "SYNTHETIC_TEST"}
        or reference.get("bindings") != bindings
        or reference.get("review_completed_before_extraction") is not True
        or reference.get("extractor_outputs_used") is not False
        or reference.get("arms_or_outcomes_used") is not False
        or reference.get("independence_attested") is not True
        or not isinstance(reference.get("reference_author_id"), str)
        or not reference["reference_author_id"].strip()
        or reference["reference_author_id"] == bindings["candidate_id"]):
        raise PromptContractQualificationError("open source reference identity or independence is invalid")
    rule = reference.get("qualification_rule")
    rates = {"minimum_complete_task_fraction", "maximum_unsupported_task_fraction",
             "maximum_wrong_decisive_state_task_fraction", "confidence_level",
             "maximum_incomplete_error_upper_bound", "maximum_unsupported_error_upper_bound",
             "maximum_wrong_decisive_error_upper_bound", "minimum_profile_reliability_lower_bound"}
    if (not isinstance(rule, dict) or set(rule) != rates | {"minimum_task_units", "minimum_profile_task_units"}
        or type(rule["minimum_task_units"]) is not int or rule["minimum_task_units"] <= 0
        or type(rule["minimum_profile_task_units"]) is not int or rule["minimum_profile_task_units"] <= 0
        or any(type(rule[k]) not in {int, float} or not math.isfinite(rule[k]) or not 0 <= rule[k] <= 1
               for k in rates) or rule["minimum_complete_task_fraction"] <= 0
        or not 0 < rule["confidence_level"] < 1):
        raise PromptContractQualificationError("open qualification requires explicit prospective thresholds")
    profiles = reference.get("required_profiles")
    profile_fields = {"language", "operation_semantic_id", "feature_id", "expected_state"}
    if (not isinstance(profiles, list) or not profiles
        or any(not isinstance(p, dict) or set(p) != profile_fields
               or any(not isinstance(v, str) or not v.strip() for v in p.values())
               or p["expected_state"] not in {"present", "absent", "unresolved", "not_applicable"} for p in profiles)
        or len({content_hash(p) for p in profiles}) != len(profiles)):
        raise PromptContractQualificationError("qualification requires unique prospective language/operation/feature/state profiles")
    cases = _rows(reference.get("cases"))
    if not cases or [case.get("task_id") for case in cases] != [task["task_id"] for task in tasks]:
        raise PromptContractQualificationError("source reference must retain the full selected task denominator")
    units = [task.get("task_unit_id", task.get("semantic_cluster_id", task["task_id"])) for task in tasks]
    duplicate_groups = [task.get("near_duplicate_group_id", unit) for task, unit in zip(tasks, units, strict=True)]
    if len(set(units)) != len(units) or len(set(duplicate_groups)) != len(duplicate_groups):
        raise PromptContractQualificationError("qualification must use distinct task units")
    for case, task in zip(cases, tasks, strict=True):
        if (not case.get("critical_checks") or not case.get("non_target_checks")
            or not case.get("feature_checks")
            or not any(key[0] == "feature_state" for key in case["critical_checks"])
            or any(not node.get("semantic_ids") for node in case.get("nodes", []))
            or any("subjects" not in row or "conditions" not in row
                   or row.get("state") not in {"present", "absent", "unresolved", "not_applicable"}
                   for row in case.get("feature_checks", []))):
            raise PromptContractQualificationError("source reference lacks concepts, exact scopes or non-target checks")
        checked = evaluate_open_graph_expectations(None, prompt=task["prompt"], expected=case)
        keys = {(row["kind"], row["key"]) for row in checked["checks"]}
        if any(tuple(key) not in keys for key in case["non_target_checks"]):
            raise PromptContractQualificationError("non-target checks must refer to declared source checks")


def binomial_error_upper_bound(errors: int, n: int, alpha: float) -> float | None:
    """Exact one-sided binomial bound by CDF inversion (Clopper-Pearson).

    NIST EXACBINO: P(X <= errors; n, upper) = alpha. The log-sum avoids
    underflow. Empty profiles remain unknown; zero observed errors never imply
    a zero population error probability. Assumes independent Bernoulli units.
    """
    if type(n) is not int or type(errors) is not int or not 0 <= errors <= n or not 0 < alpha < 1:
        raise ValueError("invalid binomial counts or tail probability")
    if not n:
        return None
    if errors == n:
        return 1.0
    if errors == 0:
        return -math.expm1(math.log(alpha) / n)
    coefficients = [math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
                    for k in range(errors + 1)]
    low, high = 0.0, 1.0
    for _ in range(64):
        p = (low + high) / 2
        if p in {low, high}:
            break
        terms = [c + k * math.log(p) + (n - k) * math.log1p(-p) for k, c in enumerate(coefficients)]
        maximum = max(terms)
        log_cdf = maximum + math.log(math.fsum(math.exp(v - maximum) for v in terms))
        if log_cdf > math.log(alpha):
            low = p
        else:
            high = p
    return high


def open_qualification_statistics(reference: dict, tasks: list[dict], results: list[dict]) -> dict:
    """Task-unit errors and simultaneous, prospectively enumerated profile bounds.

    A profile error conservatively includes any incomplete task or failed declared
    source check. Multiple matching operations/checks never replicate the task.
    No profile is selected using predicted states or extraction outcomes.
    """
    if ([r["task_id"] for r in results] != [t["task_id"] for t in tasks]
        or [c["task_id"] for c in reference["cases"]] != [t["task_id"] for t in tasks]):
        raise PromptContractQualificationError("qualification statistics task denominator differs")
    n, rule = len(results), reference["qualification_rule"]
    counts = dict(complete_task_units=sum(row["complete_task"] for row in results),
        unsupported_task_units=sum(bool(row["unsupported_assertions"]) for row in results),
        wrong_decisive_state_task_units=sum(bool(row["wrong_decisive_states"]) for row in results),
        incomplete_review_task_units=sum(not row["review_complete"] for row in results),
        failed_extraction_task_units=sum(row["extraction_failed"] for row in results))
    family_size = 3 + len(reference["required_profiles"])
    alpha = (1 - rule["confidence_level"]) / family_size
    errors = dict(incomplete=n - counts["complete_task_units"], unsupported=counts["unsupported_task_units"],
                  wrong_decisive=counts["wrong_decisive_state_task_units"])
    aggregate = {key: dict(error_task_units=k, task_units=n,
                          error_upper_bound=binomial_error_upper_bound(k, n, alpha)) for key, k in errors.items()}
    profiles = []
    for profile in sorted(reference["required_profiles"], key=canonical_json):
        selected = []
        for task, case, result in zip(tasks, reference["cases"], results, strict=True):
            nodes = {node["key"]: node for node in case["nodes"]}
            if task["language"] == profile["language"] and any(
                check["feature_id"] == profile["feature_id"] and check["state"] == profile["expected_state"]
                and profile["operation_semantic_id"] in nodes[check["target"]]["semantic_ids"]
                for check in case["feature_checks"]):
                selected.append(result)
        failures = sum(not row["complete_task"] or any(c["passed"] is not True for c in row["coverage"]["checks"])
                       for row in selected)
        upper = binomial_error_upper_bound(failures, len(selected), alpha)
        lower = 1 - upper if upper is not None else None
        profiles.append(dict(**profile, task_units=len(selected), error_task_units=failures,
            error_upper_bound=upper, reliability_lower_bound=lower,
            passed=len(selected) >= rule["minimum_profile_task_units"] and lower is not None
                   and lower >= rule["minimum_profile_reliability_lower_bound"]))
    passed = bool(n and n >= rule["minimum_task_units"]
        and counts["complete_task_units"] / n >= rule["minimum_complete_task_fraction"]
        and counts["unsupported_task_units"] / n <= rule["maximum_unsupported_task_fraction"]
        and counts["wrong_decisive_state_task_units"] / n <= rule["maximum_wrong_decisive_state_task_fraction"]
        and all(v["error_upper_bound"] <= rule[f"maximum_{key}_error_upper_bound"] for key, v in aggregate.items())
        and all(p["passed"] for p in profiles))
    return dict(**counts, acceptance_rule_passed=passed,
        uncertainty=dict(method="one_sided_clopper_pearson_bonferroni", confidence_level=rule["confidence_level"],
            family_size=family_size, per_bound_alpha=alpha, aggregate=aggregate, profiles=profiles,
            assumption="Independent task units within each prospectively defined source population; "
                       "bounds do not establish reviewer independence or coverage of unrepresented cases."))


def load_open_qualification_profiles(bundle: Path) -> dict:
    """Read an accepted current-producer result and replay all error/profile arithmetic."""
    verify_bundle(bundle)
    report = read_json(bundle / "qualification.json")
    reference = read_json(bundle / "source-reference.json")
    tasks, results = read_json(bundle / "source-tasks.json"), read_json(bundle / "case-results.json")
    validate_open_source_reference(reference, bindings=report["bindings"], tasks=tasks)
    calculated = open_qualification_statistics(reference, tasks, results)
    if (any(report.get(k) != v for k, v in calculated.items())
        or report["bindings"]["representation_implementation_sha256"] != representation_implementation_identity()
        or report.get("reference_kind") != reference["reference_kind"]
        or report.get("source_reference_record_sha256") != content_hash(reference)
        or report.get("status") not in {"QUALIFIED_FOR_FORMAL_EXTRACTION", "SYNTHETIC_REFERENCE_CHECK_PASSED"}
        or (report["status"] == "SYNTHETIC_REFERENCE_CHECK_PASSED") != (reference["reference_kind"] == "SYNTHETIC_TEST")
        or report.get("blockers") or not calculated["acceptance_rule_passed"]):
        raise PromptContractQualificationError("source qualification is unaccepted, stale or has inconsistent uncertainty")
    return dict(report=report, profiles=calculated["uncertainty"]["profiles"],
                task_unit_ids=[t.get("task_unit_id", t.get("semantic_cluster_id", t["task_id"])) for t in tasks])


def open_graph_assertions(graph: dict | None, *, contract: dict | None = None) -> dict[str, dict]:
    """Inventory every source assertion, excluding the mechanically added task root.

    Keys bind exact statements rather than unstable ordinal numbering. Extra valid
    facts are permitted, but absence from a reference is never automatic support.
    """
    if graph is None:
        return {}
    roots = {node["node_id"] for node in graph["nodes"] if node["node_type"] == "task"}
    statements = [("node", row) for row in graph["nodes"] if row["node_id"] not in roots]
    statements += [("edge", row) for row in graph["edges"]
                   if row["source_id"] not in roots and row["target_id"] not in roots]
    statements += [("scoped_state", row) for row in graph.get("scoped_feature_assessments", [])]
    statements += [("feature_state", row) for row in graph.get("feature_assessments", [])]
    statements += [("concept_absence", row) for row in graph.get("absent_semantics", [])]
    statements += [("requirement_structure", dict(requirement=key, kind=kind, members=members))
                   for key,kind,members in graph.get('requirement_structures', [])]
    if contract is not None:
        if (contract.get("task_id") != graph["task_id"]
            or contract.get("prompt_sha256") != graph["prompt_sha256"]):
            raise PromptContractQualificationError("source inventory belongs to a different graph/source")
        inventory = contract.get("source_inventory")
        if inventory is not None:
            # Distinct typed roles can collapse to one used_by edge. Review
            # their actual claims, not merely the deduplicated graph picture.
            statements += [("operation_role", row) for row in inventory["operation_roles"]]
            statements += [("statement_kind", dict(fact_id=key, modality=kind)) for key, kind in inventory.get("statement_kinds", {}).items()]
            statements += [("source_layer", dict(fact_id=key, layer=layer))
                           for key, layer in inventory["layers"].items()]
            for field, kind in (("coverage", "source_coverage"), ("unit_impacts", "source_impact")):
                statements += [(kind, dict(unit_id=key, source_unit=inventory["source_units"][key], decision=row))
                               for key, row in inventory.get(field, {}).items()]
        statements += [("source_note", note) for note in contract.get("unresolved_notes", [])]
    return {content_hash({"kind": kind, "statement": row}): {"kind": kind, "statement": row}
            for kind, row in statements}


def evaluate_open_semantic_case(graph: dict | None, *, prompt: str, expected: dict,
                               assertion_review: dict | None, extraction_failed: bool,
                               contract: dict | None = None,
                               allow_nonsemantic_notes: bool = False) -> dict:
    """Two directions: source-to-graph critical coverage and graph-to-source review."""
    from prompt_mechanism_study.prompt_tsg import _occurrence_span

    coverage = evaluate_open_graph_expectations(graph, prompt=prompt, expected=expected)
    assertions = open_graph_assertions(graph, contract=contract)
    reviewed = {} if assertion_review is None else assertion_review.get("assertions", {})
    if assertion_review is not None and (
        assertion_review.get("graph_sha256") != content_hash(graph)
        or assertion_review.get("source_prompt_sha256") != content_hash(prompt)
        or contract is not None and assertion_review.get("contract_sha256") != content_hash(contract)
        or not isinstance(reviewed, dict) or not set(reviewed) <= set(assertions)):
        raise PromptContractQualificationError("assertion review is stale or refers to a different graph/source")
    diagnostic_notes = set()
    reference_scopes = {row['key'] for row in coverage['checks'] if row['kind']=='feature_state'}
    for key, row in reviewed.items():
        if (row.get("status") not in {"SUPPORTED", "UNSUPPORTED", "UNCERTAIN"}
            or not isinstance(row.get("rationale"), str) or not row["rationale"].strip()
            or not isinstance(row.get("source_evidence"), list) or not row["source_evidence"]):
            raise PromptContractQualificationError("every reviewed assertion needs a source-based judgment")
        for anchor in row["source_evidence"]:
            _occurrence_span(prompt, anchor["evidence_text"], anchor.get("occurrence", 1))
        impact = row.get('impact')
        if impact is not None:
            if (not isinstance(impact, dict) or set(impact)!={'effect','scopes','rationale','source_evidence'}
                or impact['effect'] not in {'local','global','unresolved','irrelevant'}
                or not isinstance(impact['scopes'], list) or not set(impact['scopes']) <= reference_scopes
                or len(set(impact['scopes']))!=len(impact['scopes'])
                or (impact['effect']=='local') != bool(impact['scopes'])
                or not isinstance(impact['rationale'], str) or not impact['rationale'].strip()
                or not isinstance(impact['source_evidence'],list) or not impact['source_evidence']):
                raise PromptContractQualificationError('assertion impact needs explicit scope coverage and source evidence')
            for anchor in impact['source_evidence']:
                _occurrence_span(prompt, anchor['evidence_text'], anchor.get('occurrence',1))
        if "nonsemantic_issue" in row:
            if (not allow_nonsemantic_notes or assertions[key]["kind"] != "source_note"
                or row["nonsemantic_issue"] not in {"duplicate_note", "wording_only"}):
                raise PromptContractQualificationError("nonsemantic tolerance applies only to prospectively allowed note diagnostics")
            # The source reviewer must justify why this note defect changes no
            # semantic claim. Nodes, roles, coverage and states cannot be waived.
            diagnostic_notes.add(key)
    unsupported = sorted(key for key, row in reviewed.items() if row["status"] == "UNSUPPORTED")
    unresolved_review = sorted(set(assertions) - set(reviewed)
                              | {key for key, row in reviewed.items() if row["status"] == "UNCERTAIN"})
    blocking_unsupported = set(unsupported) - diagnostic_notes
    blocking_unresolved = set(unresolved_review) - diagnostic_notes
    lookup = {(row["kind"], row["key"]): row for row in coverage["checks"]}
    required = set(map(tuple, expected["critical_checks"] + expected["non_target_checks"]))
    complete = all(lookup[key]["passed"] is True for key in required)
    wrong_states = [row for row in coverage["checks"] if row["kind"] == "feature_state"
                    and row["status"] == "WRONG_STATE" and row["actual_state"] != "unresolved"]
    scope_quality = []
    feature_rows = {row["key"]: row for row in coverage["checks"] if row["kind"] == "feature_state"}
    dependencies = expected.get("scope_dependencies")
    if dependencies is not None and (not isinstance(dependencies, dict) or set(dependencies) != set(feature_rows)):
        raise PromptContractQualificationError("scope dependencies must cover every reference scope")
    # Existing coordinates establish a lower bound on dependencies. Source review
    # must account for additional/global influence; absent edges prove nothing.
    local_nodes = {}
    if graph and contract:
        for fact in contract.get('facts', []):
            left,right = _occurrence_span(prompt,fact['evidence_text'],fact.get('occurrence',1))
            local_nodes[fact['local_id']] = {n['node_id'] for n in graph['nodes']
                if n['semantic_id']==fact['semantic_id'] and (n['evidence_start'],n['evidence_end'])==(left,right)}
    node_ids = {n['node_id'] for n in (graph or {}).get('nodes', [])}
    def mentioned_nodes(value):
        if isinstance(value, str):
            return ({value} if value in node_ids else set()) | local_nodes.get(value,set())
        if isinstance(value, dict):
            return set().union(*(mentioned_nodes(v) for v in value.values())) if value else set()
        if isinstance(value,(list,tuple)):
            return set().union(*(mentioned_nodes(v) for v in value)) if value else set()
        return set()
    assertion_nodes = {key:mentioned_nodes(value['statement']) for key,value in assertions.items()}
    for key, row in feature_rows.items():
        needed = required if dependencies is None else set(map(tuple, dependencies[key]))
        if not needed or not needed <= set(lookup) or ("feature_state", key) not in needed:
            raise PromptContractQualificationError("scope dependencies lack their state or reference checks")
        needed_nodes = set().union(*(set(lookup[item].get('matched_node_ids',[])) for item in needed))
        needed_nodes |= mentioned_nodes(row.get('scope'))
        # A scope owns its declared participants, guards and requirements even
        # when an extra assertion has no dedicated source-reference node row.
        operations = {n['node_id'] for n in (graph or {}).get('nodes', [])
                      if n['node_type']=='task_operation' and n['node_id'] in needed_nodes}
        links = (graph or {}).get('edges', [])
        needed_nodes |= {endpoint for e in links if e['edge_type']!='contains'
            and {e['source_id'],e['target_id']} & operations for endpoint in (e['source_id'],e['target_id'])}
        changed = True
        while changed:
            before = set(needed_nodes)
            for parent, _, members in (graph or {}).get('requirement_structures', []):
                if {parent,*members} & needed_nodes:
                    needed_nodes.update((parent,*members))
            needed_nodes.update(e['source_id'] for e in links
                if e['edge_type']=='conditions' and e['target_id'] in needed_nodes)
            changed = before != needed_nodes
        def relevant(assertion):
            impact = reviewed.get(assertion,{}).get('impact')
            if dependencies is None or impact is None or impact['effect'] in {'global','unresolved'}:
                return True
            # A reviewer cannot waive a statement that names required coordinates.
            return bool(assertion_nodes[assertion] & needed_nodes) or key in impact['scopes']
        bad = sorted(a for a in blocking_unsupported if relevant(a))
        uncertain = sorted(a for a in blocking_unresolved if relevant(a))
        correct = (not extraction_failed and assertion_review is not None and not uncertain and not bad
                   and all(lookup[item]["passed"] is True for item in needed))
        actual = row.get("actual_state")
        decisive = actual in {"present", "absent", "not_applicable"}
        scope_quality.append(dict(key=key, correct=correct, usable=correct and actual in {"present", "absent"},
            decisive=decisive, wrong_decisive=decisive and actual != row.get("expected_state"),
            actual_state=actual, expected_state=row.get("expected_state"),
            blocking_unsupported_assertions=bad, blocking_uncertain_assertions=uncertain,
            dependencies=sorted(needed), blocked_checks=[list(item) for item in sorted(needed) if lookup[item]["passed"] is not True]))
    result = dict(task_id=expected["task_id"], coverage=coverage, assertion_count=len(assertions),
        unsupported_assertions=unsupported, unresolved_review_assertions=unresolved_review,
        review_complete=assertion_review is not None and not blocking_unresolved,
        extraction_failed=extraction_failed, wrong_decisive_states=wrong_states,
        scope_quality=scope_quality,
        layered_metrics=dict(reference_scopes=len(scope_quality), correct_scopes=sum(s["correct"] for s in scope_quality),
            usable_scopes=sum(s["usable"] for s in scope_quality), decisive_scopes=sum(s["decisive"] for s in scope_quality),
            wrong_decisive_scopes=sum(s["wrong_decisive"] for s in scope_quality),
            unresolved_scopes=sum(s["actual_state"] == "unresolved" for s in scope_quality),
            unassessed_scopes=sum(s["actual_state"] is None for s in scope_quality),
            supported_assertions=sum(r["status"] == "SUPPORTED" for r in reviewed.values()),
            unsupported_assertions=len(unsupported), unreviewed_or_uncertain_assertions=len(unresolved_review)),
        complete_task=complete and graph is not None and not extraction_failed and not blocking_unsupported
                      and assertion_review is not None and not blocking_unresolved)
    fixed = {(canonical_json(row.get('scope')),row['feature_id']) for row in feature_rows.values()}
    extras = [row for row in (graph or {}).get('scoped_feature_assessments', [])
              if (canonical_json(row['scope']),row['feature_id']) not in fixed]
    accepted = [row for row in scope_quality if row['actual_state'] in {'present','absent'}]
    extra_accepted = [row for row in extras if row['state'] in {'present','absent'}]
    certified = sum(row['usable'] for row in accepted)
    uncertain_accepted = sum(bool(row['blocking_uncertain_assertions']) or extraction_failed
        or any(lookup[tuple(item)]['passed'] is None for item in row['blocked_checks']) for row in accepted)
    n_accepted = len(accepted)+len(extra_accepted)
    expected_applicable = sum(row['expected_state'] in {'present','absent'} for row in scope_quality)
    result['extra_scope_assessments'] = extras
    result['candidate_metrics'] = dict(reference_queries=len(scope_quality), accepted=n_accepted,
        certified_correct=certified, extra_accepted=len(extra_accepted),
        uncertified_accepted=uncertain_accepted+len(extra_accepted),
        acceptance_precision=(certified/n_accepted if n_accepted and not uncertain_accepted and not extra_accepted else None),
        certified_correct_fraction_lower=(certified/n_accepted if n_accepted else None),
        applicable_reference_queries=expected_applicable,
        applicable_recall=(sum(row['usable'] and row['expected_state'] in {'present','absent'} for row in scope_quality)/expected_applicable
                           if expected_applicable else None),
        decisive_coverage=(sum(row['decisive'] for row in scope_quality)/len(scope_quality) if scope_quality else None))
    if allow_nonsemantic_notes:
        result["nonsemantic_note_diagnostics"] = sorted(diagnostic_notes)
    if contract is not None:
        result["contract_sha256"] = content_hash(contract)
        result["source_inventory_assertion_count"] = sum(a["kind"] in {
            "operation_role", "source_layer", "source_coverage", "source_impact", "source_note"
        } for a in assertions.values())
    return result


def summarize_review_changes(reference_ids, before, after):
    """Compare source-reviewed stable meanings, never model approval or moving node IDs."""
    keys = set(reference_ids)
    labels = {'correct','incorrect','unknown','unassessed'}
    if len(keys)!=len(reference_ids) or set(before)!=keys or set(after)!=keys or not (set(before.values()) | set(after.values())) <= labels:
        raise PromptContractQualificationError('review comparison must preserve every frozen reference unit and judgment')
    transitions = Counter(before[key]+'->'+after[key] for key in keys)
    gain = transitions['incorrect->correct']-transitions['correct->incorrect']
    return dict(reference_units=len(keys), transitions=dict(sorted(transitions.items())),
        net_corrections=gain, net_correction_rate=gain/len(keys) if keys else None,
        interpretation='Source-reviewed development transitions, not independent trials or a causal review effect.')


def _qualify_open_contract(tasks_path, extraction_bundle, catalog_path, gold_path,
                          evaluator_path, annotator_prompt_path, output, assertion_review_path):
    """Replay facts, bindings and scopes, then score the complete reference selection."""
    from dataclasses import replace
    from prompt_mechanism_study.prompt_contract_extract import (
        apply_fixed_scope_response, fixed_scope_request, fixed_scope_response_format,
        apply_fixed_binding_response, fixed_binding_request, fixed_binding_response_format,
        PromptContractExtractionError,
    )
    from prompt_mechanism_study.prompt_tsg import catalog_sha256
    from prompt_mechanism_study.task_input import prepare_task_input

    verify_bundle(extraction_bundle)
    report = read_json(extraction_bundle / "report.json")
    reference = loads_exact_json(gold_path.read_bytes())
    blocked = []
    # Earlier exposed runs lack this prospective capture; do not retrofit it.
    if report.get("qualification_reference_sha256") != file_sha256(gold_path):
        blocked.append("SOURCE_REFERENCE_NOT_CAPTURED_BEFORE_EXTRACTION")
    if reference.get("protocol_id") != _OPEN_REFERENCE:
        blocked.append("ACTIVE_SOURCE_SEMANTICS_REFERENCE_REQUIRED")
    if assertion_review_path is None:
        blocked.append("INDEPENDENT_ASSERTION_REVIEW_REQUIRED")
    if blocked:
        result = dict(status="QUALIFICATION_BLOCKED", blockers=blocked, scientific_claim_allowed=False,
                      extractor_bundle_sha256=bundle_digest(extraction_bundle),
                      gold_sha256=file_sha256(gold_path), task_units=report["tasks"])
        write_bundle(output, {"qualification.json": result})
        return result

    catalog, evaluator = load_catalog(catalog_path), read_json(evaluator_path)
    candidate_id = f"single-evidence:{evaluator['candidate_id']}"
    bindings = dict(task_file_sha256=file_sha256(tasks_path),
        task_selection_sha256=report["task_selection_sha256"], catalog_sha256=catalog_sha256(catalog),
        task_selection_record_sha256=report["task_selection_record_sha256"],
        evaluator_sha256=file_sha256(evaluator_path), annotator_prompt_sha256=file_sha256(annotator_prompt_path),
        representation_implementation_sha256=representation_implementation_identity(), candidate_id=candidate_id)
    if (catalog.get("concept_policy") != "FROZEN"
        or any(report.get(k) != v for k, v in bindings.items())
        or report.get("annotation_policy_id") != "atomic_records_review_patch_compile_scopes"
        or report.get("response_protocol_id") != "source_covered_layered_bindings_expression_v1"
        or report.get("model_visible_routing_labels") is not False
        or report.get("arms_or_outcomes_used") is not False):
        raise PromptContractQualificationError("active extraction implementation or frozen input identity differs")
    selected = read_json(extraction_bundle / "selection.json")
    if (content_hash(selected) != report["task_selection_record_sha256"]
        or reference != read_json(extraction_bundle / "qualification-reference.json")):
        raise PromptContractQualificationError("captured selection identity differs")
    original_tasks = {task["task_id"]: task for task in _rows(read_json(tasks_path))}
    tasks = [prepare_task_input(original_tasks[key]) for key in selected["task_ids"]]
    if (selected["source_tasks_sha256"] != bindings["task_file_sha256"]
        or tasks != read_json(extraction_bundle / "tasks.json") or report["tasks"] != len(tasks)):
        raise PromptContractQualificationError("source task population differs")
    validate_open_source_reference(reference, bindings=bindings, tasks=tasks)
    audit = loads_exact_json(assertion_review_path.read_bytes())
    if (audit.get("extraction_bundle_sha256") != bundle_digest(extraction_bundle)
        or audit.get("source_reference_sha256") != file_sha256(gold_path)
        or audit.get("independence_attested") is not True
        or audit.get("arms_or_outcomes_used") is not False
        or not isinstance(audit.get("reviewer_id"), str) or not audit["reviewer_id"].strip()
        or audit["reviewer_id"] == candidate_id):
        raise PromptContractQualificationError("independent assertion review provenance does not close")

    ids = {task["task_id"] for task in tasks}
    def indexed(name, value, required=False):
        rows = _rows(value)
        result = {row["task_id"]: row for row in rows}
        if len(rows) != len(result) or not set(result) <= ids or required and set(result) != ids:
            raise PromptContractQualificationError(f"{name} task denominator differs")
        return result
    requests = indexed("requests", read_json(extraction_bundle / "requests.json"), True)
    responses = indexed("responses", read_json(extraction_bundle / "responses.json"), True)
    contracts = indexed("contracts", read_json(extraction_bundle / "contracts.json"))
    graphs = indexed("graphs", read_json(extraction_bundle / "graphs.json"))
    reviews = indexed("reviews", audit.get("cases", []))
    failed = {row["task_id"] for row in report["failed_task_units"]}
    if (failed != {key for key, row in responses.items() if row["status"] == "failed"}
        or report["failed_task_unit_count"] != len(failed)
        or report["provider_calls"] != sum(row["provider_calls"] for row in responses.values())
        or report.get("initial_record_calls") != len(responses)
        or report.get("record_review_and_repair_calls") != sum(row.get("binding_annotation", {}).get("provider_calls", 0) for row in responses.values())
        or report.get("fixed_scope_assessment_calls") != sum(row.get("scope_assessment", {}).get("provider_calls", 0) for row in responses.values())
        or report.get("graph_annotation_calls") != report.get("initial_record_calls", 0) + report.get("record_review_and_repair_calls", 0)
        or report["graphs"] != len(graphs) or report["contracts"] != len(contracts)):
        raise PromptContractQualificationError("extraction failure/call accounting differs")
    results = []
    for task, case in zip(tasks, reference["cases"], strict=True):
        key, prompt = task["task_id"], task["prompt"]
        response = responses[key]
        from .source_records import record_request
        request = record_request(contract_decision_request(task, catalog))
        if (requests[key] != dict(task_id=key, request=request)
            or response["response_format_sha256"] != content_hash(contract_response_format(request))):
            raise PromptContractQualificationError("source graph request replay differs")
        scope = response.get("scope_assessment")
        binding = response.get("binding_annotation")
        if response["provider_calls"] != 1 + (binding["provider_calls"] if binding else 0) + (scope["provider_calls"] if scope else 0):
            raise PromptContractQualificationError("three-step provider accounting differs")
        for raw_row in [response, *([binding] if binding else []), *([scope] if scope else [])]:
            raw = raw_row["response_text"]
            digest = hashlib.sha256(raw.encode()).hexdigest() if raw is not None else None
            if raw_row["response_sha256"] != digest:
                raise PromptContractQualificationError("raw response identity differs")
        from .prompt_contract_extract import _attempt_source_graph
        if binding is None or len(binding.get("calls", [])) != 1 + binding["provider_calls"]:
            raise PromptContractQualificationError("source record trace is incomplete")
        retained = iter(binding["calls"])
        mismatches = []
        def provider(payload, config, _prompt):
            saved = next(retained)
            if (saved["request"] != payload or saved["response_format_sha256"] != content_hash(config["response_format"])):
                mismatches.append("record request/schema replay differs")
                raise ValueError(mismatches[-1])
            raw = saved["response_text"]
            if saved["response_sha256"] != (hashlib.sha256(raw.encode()).hexdigest() if raw is not None else None):
                mismatches.append("record response digest differs")
                raise ValueError(mismatches[-1])
            if saved["error"] is not None:
                raise RuntimeError(saved["error"]["message"])
            return raw.encode()
        replay = _attempt_source_graph(task, catalog=catalog, evaluator={"candidate_id": candidate_id.removeprefix("single-evidence:")},
            annotator_prompt="Retained-response verification.", review_status=report["review_status"], provider=provider)
        if mismatches or next(retained, None) is not None or replay.provider_calls != 1 + binding["provider_calls"]:
            raise PromptContractQualificationError("atomic record execution replay differs")
        if replay.raw != (response["response_text"].encode() if response["response_text"] is not None else None):
            raise PromptContractQualificationError("retained record response differs from extraction trace")
        replayed, graph, replay_failed = replay.contract, replay.graph, not replay.succeeded
        if graph is not None and not replay_failed:
            expected_scope = fixed_scope_request(replayed, prompt=prompt, catalog=catalog)
            if (scope is None or scope["request"] != expected_scope
                or scope["response_format_sha256"] != content_hash(fixed_scope_response_format(expected_scope))
                or scope["provider_calls"] != int(bool(expected_scope["scopes"]))):
                raise PromptContractQualificationError("fixed scope request replay differs")
            if (not expected_scope["scopes"] and scope["status"] != (
                    "SOURCE_INVENTORY_INCOMPLETE" if expected_scope["source_inventory_status"]["status"] == "INCOMPLETE"
                    else "NO_SOURCE_BOUND_SCOPES")):
                raise PromptContractQualificationError("withheld scope status differs")
            if expected_scope["scopes"]:
                try:
                    if scope["response_text"] is None:
                        raise ValueError("scope response unavailable")
                    replayed = apply_fixed_scope_response(scope["response_text"].encode(), request=expected_scope,
                        contract=replayed, prompt=prompt, catalog=catalog)
                    graph = compile_task_context_contract(replayed, prompt=prompt, catalog=catalog)
                except (ValueError, PromptContractExtractionError):
                    replay_failed = True
        elif scope is not None:
            raise PromptContractQualificationError("scope assessment exists without completed source bindings")
        actual = prompt_tsg_record(graph) if graph is not None else None
        from prompt_mechanism_study.prompt_contract import task_context_contract_record
        if (replay_failed != (key in failed) or actual != graphs.get(key)
            or (task_context_contract_record(replayed) if actual is not None else None) != contracts.get(key)):
            raise PromptContractQualificationError("raw annotation replay differs from saved partial/full output")
        scored = evaluate_open_semantic_case(actual, prompt=prompt, expected=case,
            assertion_review=reviews.get(key), extraction_failed=key in failed, contract=contracts.get(key))
        scored["raw_graph_response_sha256"] = response["response_sha256"]
        scored["raw_binding_response_sha256"] = binding["response_sha256"] if binding else None
        scored["raw_scope_response_sha256"] = scope["response_sha256"] if scope else None
        scored["compiler_unresolved_notes"] = list(replayed.unresolved_notes) if replayed else []
        scored["source_inventory_status"] = scope["request"]["source_inventory_status"] if scope else None
        scored["withheld_scope_count"] = len(scope["request"]["withheld_scopes"]) if scope else 0
        if scope and scope["request"]["source_inventory_status"]["status"] == "INCOMPLETE":
            scored["complete_task"] = False
        results.append(scored)

    n = len(results)
    statistics = open_qualification_statistics(reference, tasks, results)
    rule = reference["qualification_rule"]
    passed = statistics["acceptance_rule_passed"]
    if statistics["incomplete_review_task_units"]:
        blocked.append("INCOMPLETE_OR_UNCERTAIN_SOURCE_ASSERTION_REVIEW")
    if reference["reference_kind"] != "SYNTHETIC_TEST" and report["review_status"] != "prospective_frozen":
        blocked.append("EXPOSED_DEVELOPMENT_CANNOT_QUALIFY")
    if (reference["reference_kind"] != "SYNTHETIC_TEST"
        and report.get("provider_adapter_sha256") != file_sha256(Path(__file__).with_name("functional_judge.py"))):
        blocked.append("ACTIVE_PROVIDER_ADAPTER_IDENTITY_REQUIRED")
    status = ("QUALIFICATION_BLOCKED" if blocked else "QUALIFICATION_FAILED" if not passed else
              "SYNTHETIC_REFERENCE_CHECK_PASSED" if reference["reference_kind"] == "SYNTHETIC_TEST"
              else "QUALIFIED_FOR_FORMAL_EXTRACTION")
    result = dict(status=status, blockers=blocked, task_units=n, **statistics, qualification_rule=rule,
        reference_kind=reference["reference_kind"], source_reference_record_sha256=content_hash(reference),
        extractor_bundle_sha256=bundle_digest(extraction_bundle), gold_sha256=file_sha256(gold_path),
        assertion_review_sha256=file_sha256(assertion_review_path), bindings=bindings,
        source_check_counts={kind: dict(Counter(check["status"] for row in results
            for check in row["coverage"]["checks"] if check["kind"] == kind))
            for kind in sorted({check["kind"] for row in results for check in row["coverage"]["checks"]})},
        reference_state_coverage=[dict(language=language, operation_semantic_ids=list(operations),
            feature_id=feature, expected_state=state) for language, operations, feature, state in sorted({
                (task["language"], tuple(sorted(next(node["semantic_ids"] for node in case["nodes"]
                    if node["key"] == check["target"]))), check["feature_id"], check["state"])
                for task, case in zip(tasks, reference["cases"], strict=True) for check in case["feature_checks"]})],
        scientific_claim_allowed=False,
        claim_boundary="Final compiled-pipeline source-reference sample acceptance only; raw replies and "
                       "compiler corrections are retained separately. Unrepresented features/languages/states "
                       "are outside scope. Independence/exposure require external review. "
                       "No population-accuracy guarantee, intervention qualification or protocol activation.")
    write_bundle(output, {"qualification.json": result, "case-results.json": results,
                          "source-reference.json": reference, "source-tasks.json": tasks})
    return result


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise PromptContractQualificationError("qualification input must contain object rows")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = [
    "PromptContractQualificationError",
    "qualify_prompt_contract_extractor",
]
