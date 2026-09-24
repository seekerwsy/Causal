"""Outcome-blind source-pool screening using supplied review and exposure evidence."""

from __future__ import annotations

import platform
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.tsg.representation import (
    AnalysisScope,
    AtomicPolicyKey,
    Operation,
    PolicyFactor,
)


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
    frozen_source_rule_sha256 = content_hash(read_json(source_bundle / "source-use-rule.json"))
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
    ignored_pair_reviews = 0
    for review in read_json(source_bundle / "candidate-source-reviews.json"):
        key = review["task_unit_id"]
        coordinate = (key, review["candidate_id"])
        if coordinate in seen:
            raise ValueError("prepared pool repeats a task-candidate review")
        seen.add(coordinate)
        if review["candidate_family"] == "Pair":
            ignored_pair_reviews += 1
            continue
        task = tasks[key]
        states = _frozen_source_axis_states(
            review, task, frozen_source_rule_sha256, axes
        )
        design_states = {
            axis: review["axes"].get(axis, {}).get("state", "unresolved")
            for axis in ("target_operation", "arm_compatibility")
        }
        status = ("TASK_NOT_IN_RESEARCH_POOL" if key not in included
                  else "SOURCE_SUPPORTED_PENDING_INTERVENTION" if all(v == "supported" for v in states.values())
                  else "SOURCE_CONTRADICTED" if "contradicted" in states.values()
                  else "SOURCE_UNRESOLVED")
        screens.append({"task_unit_id": key, "candidate_id": review["candidate_id"],
                        "candidate_family": review["candidate_family"], "candidate_policy": review["candidate_policy"],
                        "source_prompt_sha256": review["source_prompt_sha256"],
                        "source_review_sha256": content_hash(review), "source_axis_states": states,
                        "status": status,
                        "original_design_axis_states": design_states,
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
        "ignored_pair_review_count": ignored_pair_reviews,
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


def _frozen_source_axis_states(
    review: Mapping[str, Any], task: Mapping[str, Any], rule_sha256: str,
    axes: tuple[str, ...],
) -> dict[str, str]:
    """Read only the source evidence needed by the current candidate screen."""
    prompt = task["prompt"]
    if (review.get("task_unit_id") != task["task_unit_id"]
            or review.get("source_prompt_sha256") != content_hash(prompt)
            or review.get("source_use_rule_sha256") != rule_sha256
            or review.get("candidate_family") != "Atomic"
            or review.get("arms_or_outcomes_used") is not False):
        raise ValueError("frozen source review identity differs from the task")
    policy = review["candidate_policy"]
    scope_data = policy["analysis_scope"]
    scope = AnalysisScope(**{
        name: tuple(value) if name.endswith("_scope") else value
        for name, value in scope_data.items()
    })
    factor = policy["factor"]
    candidate = AtomicPolicyKey(
        scope,
        PolicyFactor(factor["actionable_feature_id"], Operation(factor["operation"])),
        policy["outcome_id"],
    )
    if (review["candidate_id"] != candidate.policy_key
            or task["language"] not in scope.language_scope):
        raise ValueError("frozen source review policy identity differs")
    source_axes = review["axes"]
    if not isinstance(source_axes, Mapping):
        raise ValueError("frozen source review axes are invalid")
    states = {}
    for axis in axes:
        item = source_axes.get(axis)
        if item is None:
            states[axis] = "unresolved"
            continue
        if (not isinstance(item, Mapping)
                or item.get("state") not in {"supported", "unresolved", "contradicted"}
                or not isinstance(item.get("evidence"), list)):
            raise ValueError("frozen source axis is invalid")
        state = item["state"]
        evidence = item["evidence"]
        if state != "unresolved" and not evidence:
            raise ValueError("resolved source axis lacks prompt evidence")
        for span in evidence:
            if (not isinstance(span, Mapping)
                    or type(span.get("start")) is not int
                    or type(span.get("end")) is not int
                    or not 0 <= span["start"] < span["end"] <= len(prompt)
                    or prompt[span["start"]:span["end"]] != span.get("text")):
                raise ValueError("frozen source evidence differs from the prompt")
        states[axis] = state
    return states


__all__ = ['screen_prepared_source_pool']
