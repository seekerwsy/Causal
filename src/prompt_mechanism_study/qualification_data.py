"""Outcome-blind preparation of source-only qualification review packets."""

from __future__ import annotations

import hashlib
import json
import platform
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    file_sha256,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.contract_cleaning import verify_contract_content_data
from prompt_mechanism_study.datasets import audit_source_material
from prompt_mechanism_study.functional_judge import functional_source_scope, syntax_parser_identity
from prompt_mechanism_study.mechanisms import load_mechanism_registry
from prompt_mechanism_study.prompt_contract_extract import contract_decision_request
from prompt_mechanism_study.prompt_tsg import load_catalog
from prompt_mechanism_study.records import canonical_json, content_hash, content_id, require_text
from prompt_mechanism_study.representation import (
    AnalysisScope, AtomicPolicyKey, Operation, PairPolicyKey, PolicyFactor,
)


_QUALIFICATION_RULE = {
    "minimum_exact_context_accuracy": 0.9,
    "minimum_present_recall": 0.8,
    "maximum_false_positive_present": 0,
    "maximum_wrong_realization": 0,
}
_FORBIDDEN_REVIEW_INPUTS = [
    "preexisting mechanism binding or readiness label",
    "proposer or reviewer response",
    "Prompt TSG or extractor output",
    "generated code",
    "arm or assignment",
    "Security Oracle or Functional Judge result",
    "discovery, confirmation, or experimental outcome",
]

# Frozen five-axis rule used by research-source-use-v1/v2 and their replay only.
# Protocol Section 19 now separates source screening from intervention design;
# revised development reviews must not be relabeled or passed through this rule.
# Source quality is retained; these are source permissions, not formal roles.
SOURCE_USE_RULE = {
    "source_population": "all_frozen_task_units_all_declared_languages_and_quality_dispositions",
    "source_quality": "retain_the_original_independent_review_and_all_quality_labels",
    "candidate_sufficiency": {
        "required_axes": ["context", "target_operation", "security_boundary",
                          "non_target_invariants", "arm_compatibility"],
        "axis_states": ["supported", "unresolved", "contradicted"],
        "missing_axis": "unresolved",
        "evidence": "exact_prompt_bound_source_spans_and_a_candidate_bound_blind_review",
        "partial_source": "permitted_only_if_all_five_candidate_axes_are_supported",
        "source_defect": "requires_source_correction_and_independent_re_review",
        "atomic_and_pair": "same_rule_without_atomic_selection_or_rank_requirements",
        "formal_admission": "requires_separate_representation_intervention_oracle_and_design_qualification",
    },
    "functionality": "partial_or_unresolved_source_cannot_receive_complete_functional_success",
    "source_recovery": "restore_original_upstream_input_fields_and_assets_with_new_input_hashes_under_the_same_parent_task",
    "native_security_requirements": "preserve_original_upstream_default_prompt_security_requirements_without_selector_or_outcome_feedback",
    "restored_inputs": "require_fresh_source_contract_review_and_candidate_qualification_never_reuse_the_old_input_qualification",
    "protected_inputs": "record_restoration_candidates_but_do_not_override_frozen_role_or_reservation_inputs",
    "source_tests": "inert_assets_pending_separate_functional_and_security_coverage_review",
    "independence": "one_task_per_near_duplicate_group_across_the_union_of_formal_roles",
    "role_firewall": "preserve_all_prior_exposures_and_exact_qualification_reservations",
    "post_assignment": "all_assigned_arms_remain_in_ITT_regardless_of_measurement_or_diagnostics",
    "forbidden_inputs": _FORBIDDEN_REVIEW_INPUTS,
    "scientific_claim_allowed": False,
}


def screen_prepared_source_pool(
    source_bundle: Path, output: Path, *, qualification_manifest: Path,
) -> dict[str, Any]:
    """Include usable sources; reuse three source axes without relabeling design.

    Pool membership is not candidate eligibility. Missing policy definitions or
    Oracle support do not delete a natural task. Frozen reviews stay unchanged.
    """
    if output.exists():
        raise FileExistsError(output)
    verify_bundle(source_bundle)
    task_rows = read_json(source_bundle / "prepared-tasks.json")
    use_rows = read_json(source_bundle / "task-uses.json")
    tasks = {r["task_unit_id"]: r for r in task_rows}
    uses = {r["task_unit_id"]: r for r in use_rows}
    if len(tasks) != len(task_rows) or len(uses) != len(use_rows):
        raise ValueError("prepared pool repeats task identities")
    if set(tasks) != set(uses):
        raise ValueError("prepared pool task identities differ")
    qualification = read_json(qualification_manifest)
    if qualification.get("prospective_source_population", {}).get("prepared_data_manifest_sha256") != file_sha256(source_bundle / "manifest.json"):
        raise ValueError("qualification manifest refers to a different prepared population")
    exposures = qualification.get("additional_method_development_exposures", [])
    if not isinstance(exposures, list):
        raise ValueError("additional method exposures must be a list")
    exposed_ids, exposed_groups = set(), set()
    for exposure in exposures:
        key = exposure["task_unit_id"]
        if key in exposed_ids or key not in tasks:
            raise ValueError("additional method exposure repeats or leaves the prepared population")
        task = tasks[key]
        if (exposure["near_duplicate_group_id"] != task["near_duplicate_group_id"]
                or exposure["source_prompt_sha256"] != task["prompt_sha256"]):
            raise ValueError("additional method exposure source identity differs")
        exposed_ids.add(key)
        exposed_groups.add(task["near_duplicate_group_id"])
    protected_groups = {r["near_duplicate_group_id"] for r in uses.values()
                        if not r["available_for_source_review"]} | exposed_groups
    rows, selected = [], {}
    for key, task in sorted(tasks.items()):
        use, contract = uses[key], task["functional_contract"]
        quality = use.get("prepared_source_quality", use["source_quality_unchanged"])
        group = task["near_duplicate_group_id"]
        if (task["prompt_sha256"] != content_hash(task["prompt"])
                or use["prepared_natural_prompt_sha256"] != task["prompt_sha256"]
                or use["near_duplicate_group_id"] != group):
            raise ValueError("prepared pool prompt or independent-unit identity differs")
        if not use["available_for_source_review"] or group in protected_groups:
            decision = "PRESERVE_PROTECTED_INPUT"
        elif quality == "QUALITY_EXCLUDED_SOURCE_DEFECT":
            decision = "SOURCE_DEFECT_PENDING_CORRECTION"
        elif (quality not in {"QUALITY_INCLUDED", "QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION"}
              or not task["prompt"].strip()
              or not contract.get("parent_contract_applies_to_current_input")
              or contract.get("source_prompt_sha256") != task["prompt_sha256"]
              or contract.get("review", {}).get("contract_status") != "faithful"
              or contract.get("review", {}).get("evidence_status") != "supported"):
            decision = "CURRENT_SOURCE_REVIEW_PENDING"
        elif group in selected:
            decision = "RETAIN_AS_DEPENDENT_SOURCE_VARIANT"
        else:
            decision = "INCLUDED_RESEARCH_POOL"
            selected[group] = key
        limits = []
        if contract["measurement_scope"] != "complete":
            limits.append("functional_verdict_pending_task_relative_review")
        if not contract["requirements"]:
            limits.append("structured_functional_requirements_unresolved")
        rows.append({"task_unit_id": key, "near_duplicate_group_id": group,
                     "language": task["language"], "source_quality_retained": quality,
                     "decision": decision, "functional_measurement_scope": contract["measurement_scope"],
                     "limitations": limits, "formal_admission": False})
    included = {r["task_unit_id"] for r in rows if r["decision"] == "INCLUDED_RESEARCH_POOL"}
    for row in rows:
        row["pool_representative_task_unit_id"] = selected.get(row["near_duplicate_group_id"])
    axes = ("context", "security_boundary", "non_target_invariants")
    screens, seen = [], set()
    for review in read_json(source_bundle / "candidate-source-reviews.json"):
        key = review["task_unit_id"]
        coordinate = (key, review["candidate_id"])
        if coordinate in seen:
            raise ValueError("prepared pool repeats a task-candidate review")
        seen.add(coordinate)
        task = tasks[key]
        old = review_candidate_source_sufficiency(
            {"task_unit_id": key, "model_visible_input": {"natural_prompt": task["prompt"]},
             "pre_treatment_source_metadata": {"language": task["language"]}},
            {"task_unit_id": key, "quality_disposition": uses[key]["prepared_source_quality"]}, review,
        )
        states = {axis: old["axis_states"][axis] for axis in axes}
        status = ("TASK_NOT_IN_RESEARCH_POOL" if key not in included
                  else "SOURCE_SUPPORTED_PENDING_INTERVENTION" if all(v == "supported" for v in states.values())
                  else "SOURCE_CONTRADICTED" if "contradicted" in states.values()
                  else "SOURCE_UNRESOLVED")
        screens.append({"task_unit_id": key, "candidate_id": review["candidate_id"],
                        "candidate_family": review["candidate_family"], "candidate_policy": review["candidate_policy"],
                        "source_prompt_sha256": review["source_prompt_sha256"],
                        "source_review_sha256": content_hash(review), "source_axis_states": states,
                        "status": status, "frozen_five_axis_status": old["status"],
                        "original_design_axis_states": {a: old["axis_states"][a]
                                                        for a in ("target_operation", "arm_compatibility")},
                        "intervention_qualified": False, "formal_admission": False})
    supported = [r for r in screens if r["status"] == "SOURCE_SUPPORTED_PENDING_INTERVENTION"]
    report = {
        "status": "RESEARCH_POOL_PREPARED_FORMAL_QUALIFICATION_PENDING",
        "source_bundle": source_bundle.as_posix(),
        "source_manifest_sha256": file_sha256(source_bundle / "manifest.json"),
        "qualification_manifest_sha256": file_sha256(qualification_manifest),
        "additional_method_exposure_task_count": len(exposed_ids),
        "additional_method_exposure_group_count": len(exposed_groups),
        "source_task_count": len(tasks), "included_task_units": len(included),
        "decision_counts": dict(sorted(Counter(r["decision"] for r in rows).items())),
        "included_by_language": dict(sorted(Counter(tasks[k]["language"] for k in included).items())),
        "included_by_functional_scope": dict(sorted(Counter(tasks[k]["functional_contract"]["measurement_scope"] for k in included).items())),
        "candidate_screen_counts": dict(sorted(Counter(r["status"] for r in screens).items())),
        "source_supported_task_candidate_count": len(supported),
        "source_supported_task_units": len({r["task_unit_id"] for r in supported}),
        "source_supported_by_family": dict(sorted(Counter(r["candidate_family"] for r in supported).items())),
        "screening_rule": {"pool": "include_unprotected_nondefective_current_reviewed_sources_in_all_languages",
                           "partial_or_unresolved_functional_scope": "retain_with_limits",
                           "method_exposures": "protect_all_recorded_method_exposure_groups_before_selecting_representatives",
                           "deduplication": "lexicographically_first_usable_task_id_per_near_duplicate_group",
                           "candidate_source_axes": list(axes),
                           "design_axes": "retain_original_judgments_for_intervention_review_not_source_exclusion",
                           "missing_policy_or_oracle": "pending_candidate_work_not_global_source_exclusion"},
        "review_boundary": "mechanical_reuse_of_existing_source_reviews_not_new_manual_or_model_review",
        "provider_calls": 0, "arms_or_outcomes_used": False, "formal_admission_count": 0,
        "scientific_claim_allowed": False, "implementation_sha256": file_sha256(Path(__file__)),
        "python": platform.python_version(),
    }
    write_bundle(output, {"tasks.json": [tasks[k] for k in sorted(included)],
                          "screening.json": rows, "candidate-screens.json": screens, "report.json": report,
                          "qualification-input.json": qualification})
    return report


def _source_role_inputs(source_bundle: Path, reservation_bundle: Path):
    verify_contract_content_data(source_bundle)
    verify_bundle(reservation_bundle)
    tasks, quality, contracts, roles = (
        _rows_by_id(source_bundle / name, "task_unit_id")
        for name in ("task-units.jsonl", "task-quality.jsonl", "functional-contracts.jsonl", "task-roles.jsonl")
    )
    if any(set(rows) != set(tasks) for rows in (quality, contracts, roles)):
        raise ValueError("source use requires exactly aligned task identities")
    reserved = {}
    reserved_groups = set()
    for role in ("qual-dev", "qual-accept"):
        selection = read_json(reservation_bundle / f"{role}-selection.json")
        if selection["source_manifest_sha256"] != file_sha256(source_bundle / "manifest.json"):
            raise ValueError("source reservation refers to a different population")
        ids = selection["task_ids_in_review_order"]
        if (len(set(ids)) != len(ids) or not set(ids) <= set(tasks)
                or set(ids) & set(reserved)):
            raise ValueError("source reservations overlap or leave the frozen population")
        for task_id in ids:
            row = roles[task_id]
            group = row["near_duplicate_group_id"]
            if (row["exposure_status"] != "SOURCE_CURATED_ONLY"
                    or row["data_role"] != "UNASSIGNED"
                    or row["prospective_formal_role_assigned"]
                    or group in reserved_groups):
                raise ValueError("source reservations violate the exposure or near-duplicate firewall")
            reserved[task_id] = role.replace("-", "_").upper()
            reserved_groups.add(group)
    protected = {
        task_id for task_id, row in roles.items()
        if row["exposure_status"] != "SOURCE_CURATED_ONLY"
        or row["data_role"] != "UNASSIGNED" or row["prospective_formal_role_assigned"]
    } | set(reserved)
    protected_groups = {roles[task_id]["near_duplicate_group_id"] for task_id in protected}
    if any(roles[task_id]["near_duplicate_group_id"] in reserved_groups
           for task_id in protected - set(reserved)):
        raise ValueError("qualification reservation is near-duplicate of an exposed task")
    available = {task_id for task_id in tasks
                 if roles[task_id]["near_duplicate_group_id"] not in protected_groups}
    return tasks, quality, contracts, roles, reserved, available


def review_candidate_source_sufficiency(
    task: Mapping[str, Any], quality: Mapping[str, Any], review: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one source-only Atomic or Pair review; unknown never becomes absent.

    This determines source sufficiency only. It cannot grant formal admission,
    certify an Oracle, select an Atomic ancestor for a Pair, or revise a source.
    """
    required = {"task_unit_id", "candidate_id", "candidate_family", "candidate_policy", "source_prompt_sha256",
                "source_use_rule_sha256", "reviewer_id", "axes", "arms_or_outcomes_used"}
    if (quality.get("task_unit_id") != task["task_unit_id"] or quality.get("quality_disposition") not in {
        "QUALITY_INCLUDED", "QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION", "QUALITY_EXCLUDED_SOURCE_DEFECT",
    }):
        raise ValueError("candidate source review quality identity or disposition differs")
    if set(review) != required or review["arms_or_outcomes_used"] is not False:
        raise ValueError("candidate source review is not a blind source-only record")
    prompt = task["model_visible_input"]["natural_prompt"]
    if (review["task_unit_id"] != task["task_unit_id"]
            or review["source_prompt_sha256"] != content_hash(prompt)
            or review["source_use_rule_sha256"] != content_hash(SOURCE_USE_RULE)
            or review["candidate_family"] not in {"Atomic", "Pair"}):
        raise ValueError("candidate source review identity or prospective rule differs")
    require_text(review["candidate_id"], "candidate_id")
    require_text(review["reviewer_id"], "reviewer_id")
    value = review["candidate_policy"]
    factor_field = "factor" if review["candidate_family"] == "Atomic" else "factors"
    if not isinstance(value, Mapping) or set(value) != {"analysis_scope", factor_field, "outcome_id"}:
        raise ValueError("candidate source review lacks its exact policy definition")
    scope_value = value["analysis_scope"]
    if not isinstance(scope_value, Mapping) or set(scope_value) != {
        "security_pattern_id", "context_query_id", "language_scope", "api_scope", "task_archetype_scope",
    }:
        raise ValueError("candidate source review analysis scope is invalid")
    if any(not isinstance(scope_value[key], list)
           for key in ("language_scope", "api_scope", "task_archetype_scope")):
        raise ValueError("candidate source review scopes must be canonical lists")
    scope = AnalysisScope(**{key: tuple(item) if key.endswith("_scope") else item
                             for key, item in scope_value.items()})
    factors = [value["factor"]] if factor_field == "factor" else value["factors"]
    if not isinstance(factors, list) or any(not isinstance(factor, Mapping) or set(factor) != {
        "actionable_feature_id", "operation",
    } for factor in factors):
        raise ValueError("candidate source review factors are invalid")
    parsed = tuple(PolicyFactor(factor["actionable_feature_id"], Operation(factor["operation"]))
                   for factor in factors)
    candidate = (AtomicPolicyKey(scope, parsed[0], value["outcome_id"]) if factor_field == "factor"
                 else PairPolicyKey(scope, parsed, value["outcome_id"]))
    if review["candidate_id"] != candidate.policy_key:
        raise ValueError("candidate source review policy identity differs from its definition")
    if task["pre_treatment_source_metadata"]["language"] not in scope.language_scope:
        raise ValueError("candidate source review is outside its declared language scope")
    axes = SOURCE_USE_RULE["candidate_sufficiency"]["required_axes"]
    if not isinstance(review["axes"], Mapping) or not set(review["axes"]) <= set(axes):
        raise ValueError("candidate source review has unknown sufficiency axes")
    states = {}
    for axis in axes:
        value = review["axes"].get(axis)
        if value is None:
            states[axis] = "unresolved"
            continue
        if (not isinstance(value, Mapping) or set(value) != {"state", "evidence", "reason"}
                or value["state"] not in {"supported", "unresolved", "contradicted"}
                or not isinstance(value["evidence"], list)):
            raise ValueError("candidate source sufficiency judgment is invalid")
        require_text(value["reason"], "candidate source review reason")
        if value["state"] != "unresolved" and not value["evidence"]:
            raise ValueError("resolved source judgment requires exact source evidence")
        for span in value["evidence"]:
            if (not isinstance(span, Mapping) or set(span) != {"start", "end", "text"}
                    or type(span["start"]) is not int or type(span["end"]) is not int
                    or not 0 <= span["start"] < span["end"] <= len(prompt)
                    or prompt[span["start"]:span["end"]] != span["text"]):
                raise ValueError("candidate source evidence is not bound to the original prompt")
        states[axis] = value["state"]
    blockers = [axis + "_" + states[axis] for axis in axes if states[axis] != "supported"]
    if quality["quality_disposition"] == "QUALITY_EXCLUDED_SOURCE_DEFECT":
        blockers.append("original_source_defect_requires_independent_correction")
    return {
        "task_unit_id": task["task_unit_id"], "candidate_id": review["candidate_id"],
        "candidate_family": review["candidate_family"], "axis_states": states,
        "status": "SOURCE_SUFFICIENT_PENDING_QUALIFICATION" if not blockers else "SOURCE_BLOCKED",
        "blockers": blockers, "review_sha256": content_hash(review),
        "source_quality_unchanged": quality["quality_disposition"], "formal_admission": False,
    }


def _reviewed_source_contracts(rounds, tasks, material_by_task, available, source_manifest_sha256):
    """Accept only independently replayed judgments bound to these exact source inputs."""
    from prompt_mechanism_study.contract_cleaning import (
        _validate_contract_values, _validate_frozen_evidence, _validate_proposal_identity,
    )
    from prompt_mechanism_study.curation import _is_response_format_requirement
    from prompt_mechanism_study.verification.qualification import verify_contract_review_evidence

    updates = {}
    for evidence in rounds:
        verify_contract_review_evidence(evidence)
        proposal_report = json.loads(evidence["proposals"]["report.json"])
        if (proposal_report.get("base_bundle_sha256") != source_manifest_sha256
                or not proposal_report.get("source_use_bundle_sha256")
                or proposal_report.get("arms_or_outcomes_used") is not False):
            raise ValueError("source contract review does not bind to the frozen preparation population")
        proposals = {row["task_unit_id"]: row for row in json.loads(evidence["proposals"]["proposed-contracts.json"])}
        reviewed = json.loads(evidence["reviews"]["contract-content-reviews.json"])
        reviewed_ids = {row["task_unit_id"] for row in reviewed}
        for key, proposal in proposals.items():
            if key not in available:
                raise ValueError("source contract review cannot update a protected task")
            if key in updates and key not in reviewed_ids and proposal != updates[key]["proposal"]:
                raise ValueError("a changed source contract lacks its fresh independent review")
        for review in reviewed:
            key = review["task_unit_id"]
            proposal, task = proposals[key], tasks[key]
            restoration = material_by_task[key]["input_restoration"]
            visible = restoration["model_visible_input"] if restoration else task["model_visible_input"]
            record_id = restoration["normalized_record_id"] if restoration else task["representative_record_id"]
            if proposal["record_id"] != record_id:
                raise ValueError("reviewed source contract record identity differs")
            _validate_proposal_identity(proposal)
            _validate_contract_values(proposal)
            _validate_frozen_evidence({**task, "model_visible_input": visible}, proposal)
            updates[key] = {"proposal": proposal, "review": review,
                            "round_sha256": content_hash(evidence)}
    for update in updates.values():
        proposal, review = update["proposal"], update["review"]
        if (review["terminal_quality_decision"] is None
                or proposal["resolution_status"] not in {"resolved", "ambiguous", "unsupported"}
                or review["terminal_quality_decision"] == "QUALITY_INCLUDED" and proposal["resolution_status"] != "resolved"
                or any(_is_response_format_requirement(value) for value in proposal["requirements"])):
            raise ValueError("source contract review still requires contract repair")
    return updates


def review_candidate_context_coverage(task, policy_book_text, review):
    """Account for a finite source-only proposal set without inferring feature absence."""
    book_hash = hashlib.sha256(policy_book_text.encode("utf-8")).hexdigest()
    protocol_hash = "7e454d5755e2cf3f5bf118202b6be65fd23558d7a1c2dd198e83fc63ee48f5a1"
    if book_hash != "651feaf80ebb6daf5cb82625d4d232b84ba84cc49ef68f496f53509c3c371abd":
        raise ValueError("candidate context review policy meanings are not the frozen source proposals")
    book = json.loads(policy_book_text)
    prompt = task["model_visible_input"]["natural_prompt"]
    if (not isinstance(review, Mapping) or set(review) != {
        "task_unit_id", "source_prompt_sha256", "policy_book_sha256", "protocol_prompt_sha256",
        "reviewer_id", "groups", "arms_or_outcomes_used",
    } or review["task_unit_id"] != task["task_unit_id"]
            or review["source_prompt_sha256"] != content_hash(prompt)
            or review["policy_book_sha256"] != book_hash
            or review["protocol_prompt_sha256"] != protocol_hash
            or review["arms_or_outcomes_used"] is not False or not isinstance(review["groups"], list)):
        raise ValueError("candidate context coverage is not bound to the source and frozen meanings")
    require_text(review["reviewer_id"], "candidate context reviewer")
    defined = task["pre_treatment_source_metadata"]["language"] in book["supported_definition_languages"]
    groups = {row["group_id"]: row for row in book["groups"]}
    seen, selected, counts = set(), [], Counter()
    for row in review["groups"]:
        if (not isinstance(row, Mapping) or set(row) != {"group_ids", "state", "evidence", "reason"}
                or not isinstance(row["group_ids"], list) or not row["group_ids"]
                or len(set(row["group_ids"])) != len(row["group_ids"])
                or not set(row["group_ids"]) <= set(groups) or set(row["group_ids"]) & seen
                or row["state"] not in {"REVIEW", "NO_SOURCE_CONTEXT", "LANGUAGE_DEFINITION_MISSING"}
                or not isinstance(row["evidence"], list)
                or row["state"] != "LANGUAGE_DEFINITION_MISSING" and not row["evidence"]
                or (row["state"] == "LANGUAGE_DEFINITION_MISSING") == defined
                or row["state"] == "REVIEW" and len(row["group_ids"]) != 1):
            raise ValueError("candidate context coverage omits, repeats or misstates a proposal scope")
        require_text(row["reason"], "candidate context source reason")
        for span in row["evidence"]:
            if (not isinstance(span, Mapping) or set(span) != {"start", "end", "text"}
                    or type(span["start"]) is not int or type(span["end"]) is not int
                    or not 0 <= span["start"] < span["end"] <= len(prompt)
                    or prompt[span["start"]:span["end"]] != span["text"]):
                raise ValueError("candidate context evidence is not an exact source span")
        seen.update(row["group_ids"])
        counts[row["state"]] += len(row["group_ids"])
        if row["state"] == "REVIEW":
            selected.extend(groups[row["group_ids"][0]]["candidates"])
    if seen != set(groups):
        raise ValueError("candidate context review did not account for every frozen group")
    return {"task_unit_id": task["task_unit_id"], "review_sha256": content_hash(review),
            "policy_book_sha256": book_hash, "protocol_prompt_sha256": protocol_hash,
            "group_state_counts": dict(sorted(counts.items())),
            "candidate_ids_requiring_review": sorted(row["candidate_id"] for row in selected),
            "status": "SOURCE_CONTEXT_REVIEWED_NO_QUALIFICATION_GRANTED", "formal_admission": False}


def review_native_source_assets(task, contract, material, review):
    """Bind an inert source-asset audit; it cannot authorize a measurement.

    Functional checks refer to the current source contract. Security checks
    separately describe the property actually asserted. Neither a test name
    nor its upstream role declaration establishes coverage.
    """
    import base64

    fields = {"task_unit_id", "source_prompt_sha256", "contract_id", "protocol_prompt_sha256", "reviewer_id",
              "assets", "arms_or_outcomes_used"}
    prompt = task["model_visible_input"]["natural_prompt"]
    task_id = task["task_unit_id"]
    if (not isinstance(review, Mapping) or set(review) != fields
            or review["task_unit_id"] != task_id or review["arms_or_outcomes_used"] is not False
            or review["source_prompt_sha256"] != content_hash(prompt)
            or review["contract_id"] != contract["contract_id"]
            or review["protocol_prompt_sha256"] != "7b16d9c91ddd7d722642477c09bbadf8f8adaaf34dea051ede5f728de6c809ca"
            or not isinstance(review["assets"], list)):
        raise ValueError("native asset review does not bind to the current source contract")
    require_text(review["reviewer_id"], "native asset reviewer")
    bindings = {content_hash(row): row for row in material["asset_bindings"]
                if row["task_unit_id"] == task_id}
    assets = {row["sha256"]: row for row in material["assets"]}
    if not bindings or {row.get("binding_sha256") for row in review["assets"]} != set(bindings):
        raise ValueError("native asset review must account for every source binding")
    seen, functional_count, security_count, alignments = set(), 0, 0, Counter()
    for row in review["assets"]:
        if (not isinstance(row, Mapping) or set(row) != {
            "binding_sha256", "asset_sha256", "alignment", "observed_role",
            "functional_checks", "security_checks", "limitations", "reason",
        } or row["binding_sha256"] in seen
                or row["alignment"] not in {"supported", "partial", "contradicted", "unresolved"}
                or row["observed_role"] not in {"SETUP", "DEPENDENCIES", "EVALUATION_ENTRY_POINT",
                    "FUNCTIONAL_TESTS", "SECURITY_TESTS", "MIXED_TESTS", "NO_ASSERTIONS", "UNRESOLVED"}
                or any(not isinstance(row[field], list) for field in ("functional_checks", "security_checks", "limitations"))):
            raise ValueError("native asset review fields or duplicate binding are invalid")
        seen.add(row["binding_sha256"])
        binding = bindings[row["binding_sha256"]]
        if row["asset_sha256"] != binding["asset_sha256"]:
            raise ValueError("native asset review substituted a different source asset")
        raw = base64.b64decode(assets[row["asset_sha256"]]["content_base64"], validate=True)
        if hashlib.sha256(raw).hexdigest() != row["asset_sha256"]:
            raise ValueError("native source asset byte identity differs")
        require_text(row["reason"], "native asset review reason")
        for limitation in row["limitations"]:
            require_text(limitation, "native asset coverage limitation")
        if ((row["functional_checks"] or row["security_checks"] or row["alignment"] != "supported") and not row["limitations"]
                or row["alignment"] in {"contradicted", "unresolved"} and (row["functional_checks"] or row["security_checks"])):
            raise ValueError("native asset checks require matched source evidence and explicit coverage limits")
        if (row["functional_checks"] and row["observed_role"] not in {"FUNCTIONAL_TESTS", "MIXED_TESTS"}
                or row["security_checks"] and row["observed_role"] not in {"SECURITY_TESTS", "MIXED_TESTS"}):
            raise ValueError("native assertion mappings contradict their independently reviewed role")
        for kind in ("functional_checks", "security_checks"):
            for check in row[kind]:
                identity = "requirement_index" if kind == "functional_checks" else "criterion"
                if (not isinstance(check, Mapping) or set(check) != {identity, "source_evidence", "asset_evidence"}
                        or not isinstance(check["source_evidence"], list) or not check["source_evidence"]
                        or not isinstance(check["asset_evidence"], list) or not check["asset_evidence"]):
                    raise ValueError("native test coverage lacks separate source and assertion evidence")
                if identity == "requirement_index":
                    if type(check[identity]) is not int or not 1 <= check[identity] <= len(contract["requirements"]):
                        raise ValueError("native functional assertion has no current source requirement")
                else:
                    require_text(check[identity], "native security assertion")
                for span in check["source_evidence"]:
                    if (not isinstance(span, Mapping) or set(span) != {"start", "end", "text"}
                            or type(span["start"]) is not int or type(span["end"]) is not int
                            or not 0 <= span["start"] < span["end"] <= len(prompt)
                            or prompt[span["start"]:span["end"]] != span["text"]):
                        raise ValueError("native assertion context is not an exact source span")
                for span in check["asset_evidence"]:
                    if (not isinstance(span, Mapping) or set(span) != {"start_byte", "end_byte", "quoted_text"}
                            or type(span["start_byte"]) is not int or type(span["end_byte"]) is not int
                            or not 0 <= span["start_byte"] < span["end_byte"] <= len(raw)
                            or raw[span["start_byte"]:span["end_byte"]].decode("utf-8") != span["quoted_text"]):
                        raise ValueError("native assertion evidence is not an exact asset byte span")
        functional_count += len(row["functional_checks"])
        security_count += len(row["security_checks"])
        alignments[row["alignment"]] += 1
    return {"task_unit_id": task_id, "review_sha256": content_hash(review),
            "asset_binding_count": len(seen), "alignment_counts": dict(sorted(alignments.items())),
            "functional_assertion_mappings": functional_count, "security_assertion_mappings": security_count,
            "status": "SOURCE_ASSET_REVIEWED_MEASUREMENT_QUALIFICATION_PENDING",
            "tests_executed": False, "measurement_qualified": False, "formal_admission": False}


def prepare_source_use(
    source_bundle: Path, reservation_bundle: Path, catalog_path: Path,
    registry_path: Path, output: Path, *, source_roots: Mapping[str, Path],
    source_archives: Mapping[str, Path] | None = None,
    candidate_reviews: Path | None = None,
    candidate_context_reviews: Path | None = None,
    contract_review_rounds: Iterable[Iterable[Path]] | None = None,
    native_asset_reviews: Path | None = None,
) -> dict[str, Any]:
    """Prepare every frozen task for source-specific use along the existing path."""
    if output.exists():
        raise FileExistsError(output)
    tasks, quality, contracts, roles, reserved, available = _source_role_inputs(
        source_bundle, reservation_bundle,
    )
    catalog, registry = load_catalog(catalog_path), load_mechanism_registry(registry_path)
    query_by_cwe = defaultdict(list)
    for query in catalog["queries"]:
        realization = registry.get(query["realization_id"])
        if realization is None or realization["cwe_id"] != query["cwe_id"]:
            raise ValueError("source routing catalog and realization registry differ")
        query_by_cwe[query["cwe_id"]].append({
            "query_id": query["query_id"], "realization_id": query["realization_id"],
            "profile_language": realization["oracle_profile_id"].split(".")[0],
        })
    # Parser setup and the rule are checked before any source-specific review.
    languages = sorted({task["pre_treatment_source_metadata"]["language"] for task in tasks.values()})
    parser_identities = {language: syntax_parser_identity(language) for language in languages}
    source_material = audit_source_material(tasks.values(), source_roots, source_archives=source_archives)
    material_by_task = {row["task_unit_id"]: row for row in source_material["tasks"]}
    review_round_paths = [tuple(paths) for paths in (contract_review_rounds or ())]
    if any(len(paths) != 6 for paths in review_round_paths):
        raise ValueError("source contract review requires all six frozen round inputs")
    from prompt_mechanism_study.verification.qualification import read_contract_review_evidence

    review_rounds = [read_contract_review_evidence(*paths) for paths in review_round_paths]
    updates = _reviewed_source_contracts(review_rounds, tasks, material_by_task, available,
                                        file_sha256(source_bundle / "manifest.json"))
    current_tasks, current_quality, current_contracts = dict(tasks), dict(quality), dict(contracts)
    for key, update in updates.items():
        proposal, review = update["proposal"], update["review"]
        restoration = material_by_task[key]["input_restoration"]
        if restoration:
            current_tasks[key] = {**tasks[key], "model_visible_input": restoration["model_visible_input"],
                                  "representative_record_id": restoration["normalized_record_id"]}
        current_quality[key] = {"task_unit_id": key, "quality_disposition": review["terminal_quality_decision"]}
        current_contracts[key] = {**proposal, "review": review,
                                  "functional_contract_record_sha256": content_hash({"proposal": proposal, "review": review})}
    native_reviews = [] if native_asset_reviews is None else read_json(native_asset_reviews)
    if not isinstance(native_reviews, list):
        raise ValueError("native source asset reviews must be a list")
    asset_decisions = {}
    for review in native_reviews:
        task_id = review.get("task_unit_id")
        if (task_id not in available or task_id in asset_decisions
                or material_by_task[task_id]["input_restoration"] is not None and task_id not in updates):
            raise ValueError("native asset review uses a protected, repeated or unreviewed restored input")
        asset_decisions[task_id] = review_native_source_assets(
            current_tasks[task_id], current_contracts[task_id], source_material, review,
        )
    reviews = [] if candidate_reviews is None else read_json(candidate_reviews)
    if not isinstance(reviews, list):
        raise ValueError("candidate source reviews must be a list")
    decisions, seen = [], set()
    for review in reviews:
        if not isinstance(review, Mapping) or review.get("task_unit_id") not in tasks:
            raise ValueError("candidate source review leaves the frozen population")
        task_id = review["task_unit_id"]
        if task_id not in available:
            raise ValueError("candidate source review cannot consume a protected task")
        if material_by_task[task_id]["input_restoration"] is not None and task_id not in updates:
            raise ValueError("restored task input requires fresh source-contract review before candidate review")
        key = (task_id, review.get("candidate_id"))
        if key in seen:
            raise ValueError("candidate source review repeats a task-candidate coordinate")
        seen.add(key)
        decisions.append(review_candidate_source_sufficiency(current_tasks[task_id], current_quality[task_id], review))
    decisions_by_task = defaultdict(list)
    for decision in decisions:
        decisions_by_task[decision["task_unit_id"]].append(decision)
    context_evidence = None if candidate_context_reviews is None else read_json(candidate_context_reviews)
    context_by_task = {}
    if context_evidence is not None:
        if (not isinstance(context_evidence, Mapping) or set(context_evidence) != {"policy_book_text", "reviews"}
                or not isinstance(context_evidence["policy_book_text"], str)
                or not isinstance(context_evidence["reviews"], list) or not context_evidence["reviews"]):
            raise ValueError("candidate context evidence requires its exact policy book and source reviews")
        book_candidates = {row["candidate_id"]: row for group in json.loads(context_evidence["policy_book_text"])["groups"]
                           for row in group["candidates"]}
        reviewers = {}
        for review in context_evidence["reviews"]:
            key = review.get("task_unit_id")
            if (key not in available or key in context_by_task
                    or material_by_task[key]["input_restoration"] is not None and key not in updates):
                raise ValueError("candidate context review uses a protected, duplicate or unreviewed restored input")
            context_by_task[key] = review_candidate_context_coverage(current_tasks[key], context_evidence["policy_book_text"], review)
            reviewers[key] = review["reviewer_id"]
        expected = {(key, candidate) for key, row in context_by_task.items()
                    for candidate in row["candidate_ids_requiring_review"]}
        if seen != expected:
            raise ValueError("candidate decisions do not exactly cover the independently screened proposal set")
        for review in reviews:
            candidate = book_candidates[review["candidate_id"]]
            if (any(review[field] != candidate[field] for field in ("candidate_family", "candidate_policy"))
                    or review["reviewer_id"] != reviewers[review["task_unit_id"]]):
                raise ValueError("candidate decision changed a frozen meaning or its source reviewer")
    rows = []
    prepared_tasks = []
    for task_id, task in sorted(tasks.items()):
        role = roles[task_id]
        disposition = quality[task_id]["quality_disposition"]
        current_disposition = current_quality[task_id]["quality_disposition"]
        metadata = task["pre_treatment_source_metadata"]
        language = metadata["language"]
        routing = [query for cwe in metadata["source_declared_cwe_ids"] for query in query_by_cwe[cwe]]
        if role["data_role"] != "UNASSIGNED":
            use = "PRESERVE_" + role["data_role"]
        elif task_id in reserved:
            use = "PRESERVE_" + reserved[task_id] + "_RESERVATION"
        elif task_id not in available:
            use = "PROTECTED_EXPOSURE_OR_NEAR_DUPLICATE"
        elif current_disposition == "QUALITY_EXCLUDED_SOURCE_DEFECT":
            use = "SOURCE_CORRECTION_OR_DEFINED_DIAGNOSTICS_ONLY"
        else:
            use = "CANDIDATE_SOURCE_REVIEW"
        pending = []
        restoration = material_by_task[task_id]["input_restoration"]
        apply_restoration = restoration is not None and task_id in available
        input_review_pending = apply_restoration and task_id not in updates
        prepared_input = restoration["model_visible_input"] if apply_restoration else task["model_visible_input"]
        functional_scope = "unresolved" if input_review_pending else functional_source_scope(current_contracts[task_id])
        source_contract = current_contracts[task_id]
        # The released source contracts use literal requirement strings. Bind
        # each to its source evidence in the measurement adapter's existing shape.
        requirements = [] if input_review_pending else [
            {"requirement_id": f"{source_contract['contract_id']}:requirement:{index + 1}",
             "criterion": criterion,
             "source_evidence": source_contract["content_evidence"]["requirements"][index]}
            for index, criterion in enumerate(source_contract["requirements"])
        ]
        measurement_contract = {
            "language": language, "measurement_scope": functional_scope,
            "source_prompt_sha256": prepared_input["natural_prompt_content_sha256"],
            "parent_source_contract_sha256": source_contract["functional_contract_record_sha256"],
            "parent_contract_applies_to_current_input": not input_review_pending,
            "requirements": requirements,
            "environment_dependencies": [] if input_review_pending else source_contract["environment_dependencies"],
        }
        if not input_review_pending:
            measurement_contract["review"] = source_contract["review"]
        if task_id in updates:
            measurement_contract["source_contract_review_sha256"] = updates[task_id]["review"]["contract_content_review_record_sha256"]
            measurement_contract["original_parent_source_contract_sha256"] = contracts[task_id]["functional_contract_record_sha256"]
        prepared_tasks.append({
            "task_id": task_id, "task_unit_id": task_id,
            "prompt": prepared_input["natural_prompt"],
            "prompt_sha256": prepared_input["natural_prompt_content_sha256"],
            "model_visible_input_sha256": prepared_input["model_visible_input_identity_sha256"],
            "language": language, "source_declared_cwe_ids": metadata["source_declared_cwe_ids"],
            "source_lineage_id": task["source_lineage_id"],
            "near_duplicate_group_id": role["near_duplicate_group_id"],
            "source_task_record_sha256": task["task_unit_record_sha256"],
            "source_use": use, "functional_contract": measurement_contract,
            "formal_use_authorized": False,
        })
        if task_id in available:
            if input_review_pending:
                pending.append("source_contract_review_for_restored_input_required")
            context_review = context_by_task.get(task_id)
            if context_review is not None:
                if context_review["group_state_counts"].get("LANGUAGE_DEFINITION_MISSING"):
                    pending.append("language_specific_candidate_policy_definition_missing")
                elif not context_review["candidate_ids_requiring_review"]:
                    pending.append("no_source_context_in_reviewed_policy_book")
            elif not routing:
                pending.append("candidate_catalog_scope_missing")
            elif not any(q["profile_language"] == language for q in routing):
                pending.append("language_specific_intervention_and_oracle_scope_missing")
            if not decisions_by_task[task_id] and context_review is None:
                pending.append("candidate_specific_source_sufficiency_unreviewed")
            pending.extend(["representation_and_measurement_qualification_incomplete",
                            "formal_roles_and_candidate_support_not_frozen"])
        rows.append({
            "task_unit_id": task_id, "source_lineage_id": task["source_lineage_id"],
            "near_duplicate_group_id": role["near_duplicate_group_id"],
            "language": language, "source_cwe_ids": metadata["source_declared_cwe_ids"],
            "source_task_sha256": task["task_unit_record_sha256"],
            "source_quality_sha256": quality[task_id]["task_quality_record_sha256"],
            "source_contract_sha256": contracts[task_id]["functional_contract_record_sha256"],
            "source_role_sha256": role["task_role_record_sha256"],
            "model_visible_input_sha256": task["model_visible_input"]["model_visible_input_identity_sha256"],
            "prepared_model_visible_input_sha256": prepared_input["model_visible_input_identity_sha256"],
            "prepared_natural_prompt_sha256": prepared_input["natural_prompt_content_sha256"],
            "input_restoration_status": ("APPLIED_SOURCE_CONTRACT_REVIEWED" if apply_restoration and task_id in updates
                                         else "APPLIED_PENDING_SOURCE_CONTRACT_REVIEW" if apply_restoration
                                         else "WITHHELD_PRESERVE_FROZEN_ROLE_INPUT" if restoration
                                         else "ORIGINAL_INPUT_RETAINED"),
            "source_quality_unchanged": disposition, "existing_role": role["data_role"],
            "existing_exposure": role["exposure_status"], "qualification_reservation": reserved.get(task_id),
            "available_for_source_review": task_id in available, "source_use": use,
            "functional_measurement_scope": functional_scope,
            "syntax_parser": parser_identities[language],
            "catalog_routing_not_eligibility": routing,
            "candidate_source_decisions": sorted(decisions_by_task[task_id], key=lambda item: item["candidate_id"]),
            "source_material": material_by_task[task_id], "pending_requirements": pending,
            "formal_admission": False,
            **({"native_asset_review": asset_decisions.get(task_id)} if native_asset_reviews is not None else {}),
            **({"candidate_context_review": context_by_task.get(task_id)} if context_evidence is not None else {}),
            **({"prepared_source_quality": None if input_review_pending else current_disposition,
                "source_contract_review": ({"contract_id": updates[task_id]["proposal"]["contract_id"],
                                             "review_record_sha256": updates[task_id]["review"]["contract_content_review_record_sha256"],
                                             "round_sha256": updates[task_id]["round_sha256"]} if task_id in updates else None)}
               if review_rounds else {}),
        })
    available_rows = [row for row in rows if row["available_for_source_review"]]
    quality_passed = [row for row in available_rows if row["source_quality_unchanged"] == "QUALITY_INCLUDED"]
    report = {
        "status": "SOURCE_USE_PREPARED_QUALIFICATION_PENDING",
        "source_manifest_sha256": file_sha256(source_bundle / "manifest.json"),
        "reservation_manifest_sha256": file_sha256(reservation_bundle / "manifest.json"),
        "catalog_sha256": file_sha256(catalog_path), "registry_sha256": file_sha256(registry_path),
        "source_use_rule_sha256": content_hash(SOURCE_USE_RULE),
        "task_unit_count": len(rows), "near_duplicate_groups": len({row["near_duplicate_group_id"] for row in rows}),
        "task_unit_id_set_sha256": content_hash(tuple(sorted(tasks))),
        "available_source_review_tasks": len(available_rows),
        "available_source_review_independent_groups": len({row["near_duplicate_group_id"] for row in available_rows}),
        "quality_passed_unexposed_unreserved": len(quality_passed),
        "quality_passed_with_unchanged_input": sum(row["input_restoration_status"] == "ORIGINAL_INPUT_RETAINED"
                                                  for row in quality_passed),
        "quality_passed_restored_input_pending_review": sum(row["input_restoration_status"] == "APPLIED_PENDING_SOURCE_CONTRACT_REVIEW"
                                                            for row in quality_passed),
        "quality_passed_unexposed_unreserved_by_language": dict(sorted(Counter(row["language"] for row in quality_passed).items())),
        "source_use_counts": dict(sorted(Counter(row["source_use"] for row in rows).items())),
        "source_quality_counts": dict(sorted(Counter(row["source_quality_unchanged"] for row in rows).items())),
        "language_counts": dict(sorted(Counter(row["language"] for row in rows).items())),
        "functional_scope_counts": dict(sorted(Counter(row["functional_measurement_scope"] for row in rows).items())),
        "pending_requirement_counts": dict(sorted(Counter(item for row in rows for item in row["pending_requirements"]).items())),
        "candidate_source_review_count": len(decisions),
        "source_sufficient_candidate_count": sum(row["status"] == "SOURCE_SUFFICIENT_PENDING_QUALIFICATION" for row in decisions),
        "source_native_asset_bindings": len(source_material["asset_bindings"]),
        "source_native_asset_contents": len(source_material["assets"]),
        "source_asset_origin_pending": sum(row["origin_status"] == "SOURCE_VERSION_VERIFICATION_PENDING"
                                            for row in source_material["asset_bindings"]),
        "tasks_with_native_assets": sum(row["source_material"]["referenced_asset_count"] > 0 for row in rows),
        "source_input_restoration_candidates": source_material["prompt_repairs"],
        "prompt_repairs": sum(row["input_restoration_status"] in {"APPLIED_PENDING_SOURCE_CONTRACT_REVIEW", "APPLIED_SOURCE_CONTRACT_REVIEWED"} for row in rows),
        "withheld_protected_input_restorations": sum(row["input_restoration_status"] == "WITHHELD_PRESERVE_FROZEN_ROLE_INPUT" for row in rows),
        "recovered_source_asset_bindings": sum(row["binding_kind"] == "RECOVERED_ORIGINAL_SOURCE_FIELD"
                                               for row in source_material["asset_bindings"]),
        "new_independent_units": 0, "formal_admission_count": 0,
        "formal_use_authorized": False, "scientific_claim_allowed": False,
        "provider_calls_made": 0, "arms_or_outcomes_used": False,
        "reproduction": {
            "python": platform.python_version(), "platform": platform.platform(),
            "required_project_extra": "languages",
            "command": ["python", "-m", "prompt_mechanism_study", "curate", "prepare", "source-use",
                        *[path.as_posix() for path in (source_bundle, reservation_bundle, catalog_path, registry_path, output)],
                        *[part for name, path in sorted(source_roots.items()) for part in ("--source-root", name + "=" + path.as_posix())],
                        *[part for name, path in sorted((source_archives or {}).items()) for part in ("--source-archive", name + "=" + path.as_posix())],
                        *([] if candidate_reviews is None else ["--candidate-reviews", candidate_reviews.as_posix()])],
            "implementation_sha256": {name: file_sha256(Path(__file__).parent / name) for name in (
                "artifact_io.py", "datasets.py", "qualification_data.py", "functional_judge.py", "verification/qualification.py",
            )},
        },
    }
    artifacts = {"source-use-rule.json": SOURCE_USE_RULE, "task-uses.json": rows,
                          "prepared-tasks.json": prepared_tasks,
                          "source-material.json": source_material,
                          "candidate-source-reviews.json": reviews, "report.json": report}
    if review_rounds:
        current_good = [row for row in available_rows if row["prepared_source_quality"] == "QUALITY_INCLUDED"]
        report.update({
            "source_contract_review_round_count": len(review_rounds),
            "source_contracts_independently_reviewed": len(updates),
            "reviewed_source_contract_ids": sorted(updates),
            "current_quality_passed_unexposed_unreserved": len(current_good),
            "current_quality_passed_unexposed_unreserved_by_language": dict(sorted(Counter(row["language"] for row in current_good).items())),
            "prepared_source_quality_counts": dict(sorted(Counter(row["prepared_source_quality"] or "PENDING_SOURCE_CONTRACT_REVIEW" for row in rows).items())),
            "source_contract_quality_transition_counts": dict(sorted(Counter(
                quality[key]["quality_disposition"] + " -> " + update["review"]["terminal_quality_decision"]
                for key, update in updates.items()).items())),
        })
        report["reproduction"]["command"].extend(part for paths in review_round_paths
                                                for part in ("--contract-review-round", *(path.as_posix() for path in paths)))
        artifacts["source-contract-reviews.json"] = review_rounds
    if native_asset_reviews is not None:
        report.update({"native_asset_review_task_count": len(asset_decisions),
                       "native_asset_review_binding_count": sum(row["asset_binding_count"] for row in asset_decisions.values()),
                       "native_functional_assertion_mappings": sum(row["functional_assertion_mappings"] for row in asset_decisions.values()),
                       "native_security_assertion_mappings": sum(row["security_assertion_mappings"] for row in asset_decisions.values()),
                       "native_measurement_qualifications_granted": 0})
        report["reproduction"]["command"].extend(["--native-asset-reviews", native_asset_reviews.as_posix()])
        artifacts["native-source-reviews.json"] = native_reviews
    if context_evidence is not None:
        group_counts = Counter()
        for row in context_by_task.values():
            group_counts.update(row["group_state_counts"])
        report.update({"candidate_context_review_task_count": len(context_by_task),
                       "candidate_context_group_state_counts": dict(sorted(group_counts.items())),
                       "candidate_policy_book_sha256": hashlib.sha256(context_evidence["policy_book_text"].encode("utf-8")).hexdigest()})
        report["reproduction"]["command"].extend(["--candidate-context-reviews", candidate_context_reviews.as_posix()])
        artifacts["candidate-context-reviews.json"] = context_evidence
    write_bundle(output, artifacts)
    return report


def summarize_source_role_capacity(
    source_bundle: Path, eligibility_policy: Path, reservation_bundle: Path,
) -> dict[str, Any]:
    """Read-only source census; no support score, outcome, acquisition or role assignment.

    CWE routing and quality come from the frozen source/curation records. Counts
    are upper bounds before context, operation and measurement qualification.
    """
    tasks, quality, _, roles, reservations, available = _source_role_inputs(source_bundle, reservation_bundle)
    metadata = _rows_by_id(source_bundle / "readiness-worklist.jsonl", "task_unit_id")
    if any(set(rows) != set(tasks) for rows in (quality, roles, metadata)):
        raise ValueError("source capacity census requires exactly aligned task identities")
    family_by_cwe = {cwe: row["family_id"] for row in read_json(eligibility_policy)["python_families"]
                     for cwe in row["cwes"]}
    reserved = set(reservations)
    included = {key for key, row in tasks.items()
                if row["pre_treatment_source_metadata"]["language"] == "python"
                and quality[key]["quality_disposition"] == "QUALITY_INCLUDED"}
    current = {key for key in included if metadata[key]["primary_cwe"] in family_by_cwe}
    unexposed = {key for key in current if roles[key]["exposure_status"] == "SOURCE_CURATED_ONLY"
                 and not roles[key]["prospective_formal_role_assigned"]}
    remaining = current & available
    groups = {roles[key]["near_duplicate_group_id"] for key in remaining}
    return {
        "status": "SOURCE_CAPACITY_CENSUS_NOT_FORMAL_ELIGIBILITY",
        "source_manifest_sha256": file_sha256(source_bundle / "manifest.json"),
        "eligibility_policy_sha256": file_sha256(eligibility_policy),
        "reservation_manifest_sha256": file_sha256(reservation_bundle / "manifest.json"),
        "scope": "prior_21_cwe_python_capacity_diagnostic_not_the_full_source_population",
        "full_source_task_units": len(tasks),
        "full_source_available_tasks": len(available),
        "full_source_available_independent_groups": len({roles[key]["near_duplicate_group_id"] for key in available}),
        "quality_included_python": len(included), "current_scope": len(current),
        "unexposed_before_reservations": len(unexposed),
        "reserved_current_scope": len(reserved & unexposed), "remaining_task_units": len(remaining),
        "remaining_near_duplicate_groups": len(groups),
        "remaining_by_family": dict(sorted(Counter(family_by_cwe[metadata[key]["primary_cwe"]] for key in remaining).items())),
        "remaining_by_cwe": dict(sorted(Counter(metadata[key]["primary_cwe"] for key in remaining).items())),
        "remaining_task_unit_ids": sorted(remaining),
        "formal_eligible_counts_available": False, "formal_use_authorized": False,
        "provider_calls_made": 0, "arms_or_outcomes_used": False,
        "blockers": ["representation_and_measurement_qualification_incomplete",
                     "candidate_specific_context_and_operation_support_not_frozen",
                     "task_level_power_design_not_qualified", "formal_roles_not_frozen"],
    }


def prepare_qualification_source_review(
    source_bundle: Path,
    catalog_path: Path,
    registry_path: Path,
    output: Path,
    *,
    producer_commit: str,
    ranking_salt: str,
    qual_dev_count: int = 28,
    qual_accept_count: int = 28,
) -> dict[str, Any]:
    """Prepare disjoint candidate reservations and blind review packets.

    This does not assign a formal data role. It freezes exact candidate
    memberships so an independent reviewer can create source-only gold before
    the one-shot acceptance set is ever sent to the candidate extractor.
    """

    require_text(ranking_salt, "ranking_salt")
    if (
        not isinstance(producer_commit, str)
        or len(producer_commit) != 40
        or any(character not in "0123456789abcdef" for character in producer_commit)
    ):
        raise ValueError("producer_commit must be a full lowercase Git commit")
    if (
        type(qual_dev_count) is not int
        or type(qual_accept_count) is not int
        or qual_dev_count < 1
        or qual_accept_count < 1
    ):
        raise ValueError("qualification candidate counts must be positive integers")

    source = source_bundle.resolve()
    verified = verify_contract_content_data(source)
    catalog = load_catalog(catalog_path)
    registry = load_mechanism_registry(registry_path)
    catalog_sha256 = file_sha256(catalog_path)
    registry_sha256 = file_sha256(registry_path)
    source_manifest_sha256 = file_sha256(source / "manifest.json")

    tasks = _rows_by_id(source / "task-units.jsonl", "task_unit_id")
    quality = _rows_by_id(source / "task-quality.jsonl", "task_unit_id")
    roles = _rows_by_id(source / "task-roles.jsonl", "task_unit_id")
    readiness = _rows_by_id(source / "readiness-worklist.jsonl", "task_unit_id")
    if any(set(rows) != set(tasks) for rows in (quality, roles, readiness)):
        raise ValueError("qualification source populations differ")

    query_by_realization: dict[str, dict[str, str]] = {}
    families_by_cwe: dict[str, set[str]] = defaultdict(set)
    queries_by_scope: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for query in catalog["queries"]:
        realization_id = query["realization_id"]
        coordinate = {
            "cwe": query["cwe_id"],
            "task_family": query["task_family"],
        }
        previous = query_by_realization.setdefault(realization_id, coordinate)
        if previous != coordinate or realization_id not in registry:
            raise ValueError("catalog and mechanism registry realization coordinates differ")
        families_by_cwe[query["cwe_id"]].add(query["task_family"])
        queries_by_scope[(query["cwe_id"], query["task_family"])].append(query)

    eligible = []
    for task_id, task in tasks.items():
        quality_row = quality[task_id]
        role = roles[task_id]
        ready = readiness[task_id]
        if (
            task["pre_treatment_source_metadata"]["language"] != "python"
            or quality_row["quality_disposition"] != "QUALITY_INCLUDED"
            or role["data_role"] != "UNASSIGNED"
            or role["exposure_status"] != "SOURCE_CURATED_ONLY"
            or role["exposure_data_ids"] != []
            or role["exposure_evidence"] != []
            or role["prospective_formal_role_assigned"] is not False
            or role["role_assignment_status"] != "PENDING_PROSPECTIVE_ALLOCATION"
            or not isinstance(role["future_evaluation_reservation_id"], str)
        ):
            continue
        cwes = task["pre_treatment_source_metadata"]["source_declared_cwe_ids"]
        if not isinstance(cwes, list) or len(cwes) != 1:
            continue
        cwe = cwes[0]
        realization_id = ready["mechanism_realization_id"]
        if realization_id is not None:
            coordinate = query_by_realization.get(realization_id)
            if coordinate is None or coordinate["cwe"] != cwe:
                continue
            task_family = coordinate["task_family"]
        else:
            families = families_by_cwe.get(cwe, set())
            if len(families) != 1:
                continue
            task_family = next(iter(families))
        eligible.append(
            {
                "task_id": task_id,
                "task": task,
                "role": role,
                "cwe": cwe,
                "task_family": task_family,
                "realization_id": realization_id,
            }
        )

    by_realization: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unbound = []
    for row in eligible:
        if row["realization_id"] is None:
            unbound.append(row)
        else:
            by_realization[row["realization_id"]].append(row)
    if len(by_realization) > qual_accept_count:
        raise ValueError("QUAL_ACCEPT candidate count cannot cover every bound realization stratum")

    used_groups: set[str] = set()
    selected: dict[str, list[dict[str, Any]]] = {
        "QUAL_ACCEPT": [],
        "QUAL_DEV": [],
    }
    counts = {
        role: {"cwe": Counter(), "lineage": Counter()}
        for role in selected
    }

    for realization_id in sorted(by_realization):
        _select_one(
            by_realization[realization_id],
            selected["QUAL_ACCEPT"],
            used_groups,
            counts["QUAL_ACCEPT"],
            ranking_salt,
            "QUAL_ACCEPT",
            realization_id,
        )
    for realization_id in sorted(by_realization):
        remaining = [
            row
            for row in by_realization[realization_id]
            if row["role"]["near_duplicate_group_id"] not in used_groups
        ]
        if remaining:
            _select_one(
                remaining,
                selected["QUAL_DEV"],
                used_groups,
                counts["QUAL_DEV"],
                ranking_salt,
                "QUAL_DEV",
                realization_id,
            )

    _fill_selection(
        unbound,
        selected["QUAL_ACCEPT"],
        qual_accept_count,
        used_groups,
        counts["QUAL_ACCEPT"],
        ranking_salt,
        "QUAL_ACCEPT",
    )
    _fill_selection(
        unbound,
        selected["QUAL_DEV"],
        qual_dev_count,
        used_groups,
        counts["QUAL_DEV"],
        ranking_salt,
        "QUAL_DEV",
    )
    if (
        len(selected["QUAL_ACCEPT"]) != qual_accept_count
        or len(selected["QUAL_DEV"]) != qual_dev_count
    ):
        raise ValueError("qualification source population cannot fill both candidate reservations")

    artifacts: dict[str, Any] = {}
    summaries: dict[str, Any] = {}
    all_task_ids: set[str] = set()
    all_group_ids: set[str] = set()
    for role_name, prefix in (("QUAL_DEV", "qual-dev"), ("QUAL_ACCEPT", "qual-accept")):
        rows = selected[role_name]
        task_rows = [_extractor_task(row) for row in rows]
        task_payload_sha256 = _artifact_sha256(task_rows)
        membership = sorted(
            (
                {
                    "task_unit_id": row["task_id"],
                    "near_duplicate_group_id": row["role"]["near_duplicate_group_id"],
                    "source_lineage_id": row["role"]["source_lineage_id"],
                    "exposure_history": [],
                    "future_evaluation_reservation_id": row["role"][
                        "future_evaluation_reservation_id"
                    ],
                }
                for row in rows
            ),
            key=lambda item: item["task_unit_id"],
        )
        data_id = content_id(
            "qualification_dataset_candidate_",
            {
                "protocol_id": "phase-context-policy-v3",
                "proposed_role": role_name,
                "source_manifest_sha256": source_manifest_sha256,
                "task_manifest_sha256": task_payload_sha256,
                "task_units": membership,
            },
        )
        selection_record = {
            "schema_version": "1.0",
            "artifact_kind": "qualification_role_candidate_selection",
            "status": "CANDIDATE_RESERVATION_FROZEN_NOT_FORMAL_DATA_ROLE_MANIFEST",
            "protocol_id": "phase-context-policy-v3",
            "producer_commit": producer_commit,
            "data_id": data_id,
            "proposed_data_role": role_name,
            "formal_role_assigned": False,
            "qualification_accept_authorized": False,
            "source_manifest_sha256": source_manifest_sha256,
            "catalog_sha256": catalog_sha256,
            "registry_sha256": registry_sha256,
            "ranking_salt": ranking_salt,
            "selection_rule": (
                "one unexposed source-only candidate per existing catalog-bound realization "
                "for QUAL_ACCEPT; a second candidate where available for QUAL_DEV; fill each "
                "fixed count from unbound tasks whose CWE has one unambiguous catalog family, "
                "greedily balancing CWE and source lineage with salted SHA-256 tie-breaks"
            ),
            "existing_binding_metadata_used_only_for_stratified_selection": True,
            "task_manifest_sha256": task_payload_sha256,
            "task_ids_in_review_order": [row["task_id"] for row in rows],
            "task_units": membership,
            "arms_or_outcomes_used": False,
            "scientific_claim_allowed": False,
        }
        review_cases = []
        for task_row in task_rows:
            request = contract_decision_request(task_row, catalog)
            scope_queries = queries_by_scope[(task_row["cwe"], task_row["task_family"])]
            review_cases.append(
                {
                    "task_id": task_row["task_id"],
                    "source_reference": task_row["source"],
                    "annotation_request": request,
                    "candidate_realizations": [
                        {
                            "query_id": query["query_id"],
                            "realization_id": query["realization_id"],
                        }
                        for query in sorted(scope_queries, key=lambda item: item["query_id"])
                    ],
                }
            )
        review_packet = {
            "schema_version": "1.0",
            "artifact_kind": "source_only_prompt_contract_gold_review_packet",
            "status": "AWAITING_EXTERNAL_INDEPENDENT_REVIEW",
            "candidate_data_id": data_id,
            "proposed_data_role": role_name,
            "reviewer_independence_required": True,
            "allowed_inputs": [
                "exact natural source prompt in this packet",
                "source reference in this packet",
                "finite catalog queries, semantics, relations, and guidance in this packet",
            ],
            "prohibited_inputs": _FORBIDDEN_REVIEW_INPUTS,
            "annotation_fields": {
                "expected_context": [
                    "present",
                    "absent",
                    "unresolved",
                    "absent_or_unresolved",
                ],
                "expected_realization_id": (
                    "one candidate realization ID when expected_context is present; otherwise null"
                ),
                "rationale": "non-empty source-grounded explanation",
            },
            "cases": review_cases,
            "arms_or_outcomes_used": False,
        }
        gold_template = {
            "schema_version": "2.0-template",
            "status": "INCOMPLETE_EXTERNAL_INDEPENDENT_REVIEW_REQUIRED",
            "candidate_data_id": data_id,
            "contract_protocol_id": "task_context_contract_v2_dual_blind_consensus",
            "review_completed_before_extraction": False,
            "reviewer_independence_attested": False,
            "arms_or_outcomes_used": False,
            "execution": {"task_workers": 4},
            "qualification_rule": _QUALIFICATION_RULE,
            "cases": [
                {
                    "task_id": task["task_id"],
                    "expected_context": "REVIEW_REQUIRED",
                    "expected_realization_id": "REVIEW_REQUIRED_OR_NULL",
                    "rationale": "REVIEW_REQUIRED",
                }
                for task in task_rows
            ],
        }
        artifacts[f"{prefix}-selection.json"] = selection_record
        artifacts[f"{prefix}-tasks.json"] = task_rows
        artifacts[f"{prefix}-review-packet.json"] = review_packet
        artifacts[f"{prefix}-gold-template.json"] = gold_template
        task_ids = {row["task_id"] for row in rows}
        group_ids = {row["role"]["near_duplicate_group_id"] for row in rows}
        if all_task_ids.intersection(task_ids) or all_group_ids.intersection(group_ids):
            raise ValueError(
                "qualification candidate reservations cross task or near-duplicate roles"
            )
        all_task_ids.update(task_ids)
        all_group_ids.update(group_ids)
        summaries[role_name] = {
            "data_id": data_id,
            "task_units": len(rows),
            "bound_realization_strata": len(
                {row["realization_id"] for row in rows if row["realization_id"] is not None}
            ),
            "unbound_catalog_cwe_challenges": sum(
                row["realization_id"] is None for row in rows
            ),
            "source_lineages": dict(
                sorted(
                    Counter(
                        row["role"]["source_lineage_id"] for row in rows
                    ).items()
                )
            ),
            "cwes": dict(sorted(Counter(row["cwe"] for row in rows).items())),
            "task_manifest_sha256": task_payload_sha256,
        }

    report = {
        "schema_version": "1.0",
        "status": "SOURCE_ONLY_REVIEW_PACKETS_READY_FORMAL_ROLE_MANIFEST_AND_GOLD_PENDING",
        "protocol_id": "phase-context-policy-v3",
        "producer_commit": producer_commit,
        "source_bundle_sha256": verified["bundle_sha256"],
        "source_manifest_sha256": source_manifest_sha256,
        "catalog_sha256": catalog_sha256,
        "registry_sha256": registry_sha256,
        "eligible_unexposed_python_task_units": len(eligible),
        "candidate_reservations": summaries,
        "task_unit_disjoint": True,
        "near_duplicate_group_disjoint": True,
        "qual_accept_method_exposure_history_empty": True,
        "formal_role_assignment_frozen": False,
        "qualification_accept_attempts_authorized": 0,
        "provider_calls_authorized": 0,
        "independent_gold_complete": False,
        "next_gate": (
            "Obtain independent source-only labels without opening extractor outputs; approve "
            "and power-qualify all role counts; then freeze one complete five-role "
            "DataRoleManifest and "
            "the integrated acceptance plan before any QUAL_ACCEPT provider call."
        ),
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    artifacts["report.json"] = report
    write_bundle(output, artifacts)
    return {**report, "bundle_sha256": bundle_digest(output)}


def _rows_by_id(path: Path, key: str) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if not isinstance(value, dict) or not isinstance(value.get(key), str):
            raise ValueError(f"invalid qualification source row: {path.name}")
        identity = value[key]
        if identity in rows:
            raise ValueError(f"duplicate qualification source identity: {identity}")
        rows[identity] = value
    return rows


def _rank(salt: str, role: str, stratum: str, task_id: str) -> str:
    return hashlib.sha256(f"{salt}\0{role}\0{stratum}\0{task_id}".encode("utf-8")).hexdigest()


def _select_one(
    candidates: Iterable[dict[str, Any]],
    destination: list[dict[str, Any]],
    used_groups: set[str],
    counts: Mapping[str, Counter[str]],
    salt: str,
    role: str,
    stratum: str,
) -> None:
    available = [
        row
        for row in candidates
        if row["role"]["near_duplicate_group_id"] not in used_groups
    ]
    if not available:
        raise ValueError(f"qualification stratum is unavailable: {role}/{stratum}")
    chosen = min(
        available,
        key=lambda row: (
            counts["lineage"][row["role"]["source_lineage_id"]],
            _rank(salt, role, stratum, row["task_id"]),
            row["task_id"],
        ),
    )
    destination.append(chosen)
    used_groups.add(chosen["role"]["near_duplicate_group_id"])
    counts["cwe"][chosen["cwe"]] += 1
    counts["lineage"][chosen["role"]["source_lineage_id"]] += 1


def _fill_selection(
    candidates: Iterable[dict[str, Any]],
    destination: list[dict[str, Any]],
    target: int,
    used_groups: set[str],
    counts: Mapping[str, Counter[str]],
    salt: str,
    role: str,
) -> None:
    pool = list(candidates)
    while len(destination) < target:
        available = [
            row
            for row in pool
            if row["role"]["near_duplicate_group_id"] not in used_groups
        ]
        if not available:
            raise ValueError(f"insufficient unbound source-only candidates for {role}")
        chosen = min(
            available,
            key=lambda row: (
                counts["cwe"][row["cwe"]],
                counts["lineage"][row["role"]["source_lineage_id"]],
                _rank(salt, role, "unbound", row["task_id"]),
                row["task_id"],
            ),
        )
        destination.append(chosen)
        used_groups.add(chosen["role"]["near_duplicate_group_id"])
        counts["cwe"][chosen["cwe"]] += 1
        counts["lineage"][chosen["role"]["source_lineage_id"]] += 1


def _extractor_task(row: Mapping[str, Any]) -> dict[str, Any]:
    task = row["task"]
    model_input = task["model_visible_input"]
    prompt = model_input["natural_prompt"]
    if model_input["natural_prompt_content_sha256"] != content_hash(prompt):
        raise ValueError("qualification source prompt identity drifted")
    representative = task["representative_record_id"]
    source_members = [
        member for member in task["source_members"] if member["record_id"] == representative
    ]
    if len(source_members) != 1:
        raise ValueError("qualification source representative provenance is missing")
    member = source_members[0]
    return {
        "task_id": row["task_id"],
        "task_unit_id": row["task_id"],
        "prompt": prompt,
        "prompt_sha256": content_hash(prompt),
        "language": "python",
        "cwe": row["cwe"],
        "task_family": row["task_family"],
        "source": {
            "dataset": member["dataset_id"],
            "source_lineage_id": task["source_lineage_id"],
            "repository": member["citation_url"],
            "version": member["source_version"],
            "upstream_id": member["source_item_id"],
            "source_locator": member["source_locator"],
            "source_record_sha256": member["source_record_sha256"],
        },
    }


def _artifact_sha256(value: Any) -> str:
    payload = (canonical_json(value) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


__all__ = ["SOURCE_USE_RULE", "prepare_source_use", "review_candidate_source_sufficiency",
           "prepare_qualification_source_review", "summarize_source_role_capacity", "screen_prepared_source_pool"]
