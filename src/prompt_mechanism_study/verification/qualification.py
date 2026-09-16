"""Independent power, budget, and provider-preflight reconstruction."""

from __future__ import annotations

import hashlib
import math
import random
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import replace
from functools import lru_cache

from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
    PolicyTrack,
)
from prompt_mechanism_study.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    PAIR_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.study_design import FormalBudgetPreflight
from prompt_mechanism_study.study_planning import (
    ATOMIC_POWER_ARMS,
    PAIR_POWER_ARMS,
    ProviderCallKind,
    QualificationProfileKind,
    QualificationStatus,
    RQ1BudgetQualification,
    RQ1BudgetScenario,
    TargetPowerSimulationResult,
)


def verify_contract_review_round(
    proposals_root, packets_root, decisions_root, initial_root,
    adjudication_decisions_root, reviews_root,
) -> dict[str, object]:
    """Replay the two independent decisions and blind third without the merger."""
    return verify_contract_review_evidence(read_contract_review_evidence(
        proposals_root, packets_root, decisions_root, initial_root,
        adjudication_decisions_root, reviews_root,
    ))


def read_contract_review_evidence(
    proposals_root, packets_root, decisions_root, initial_root,
    adjudication_decisions_root, reviews_root,
):
    """Retain the exact existing review artifacts, including original decision bytes."""
    from prompt_mechanism_study.artifact_io import verify_bundle

    roots = dict(zip(("proposals", "packets", "decisions", "initial", "adjudications", "reviews"),
                     (proposals_root, packets_root, decisions_root, initial_root,
                      adjudication_decisions_root, reviews_root), strict=True))
    for name in ("proposals", "packets", "initial", "reviews"):
        verify_bundle(roots[name])
    return {name: {path.relative_to(root).as_posix(): path.read_bytes().decode("utf-8")
                   for path in sorted(root.rglob("*.json")) if path.is_file()}
            for name, root in roots.items()}


def verify_contract_review_evidence(evidence) -> dict[str, object]:
    """Replay a frozen round from its original bytes without filesystem dependencies."""
    import json
    from prompt_mechanism_study.artifact_io import verify_bundle_contents
    from prompt_mechanism_study.records import content_id
    from prompt_mechanism_study.curation import _is_response_format_requirement

    if not isinstance(evidence, dict) or set(evidence) != {
        "proposals", "packets", "decisions", "initial", "adjudications", "reviews",
    }:
        raise ValueError("contract review evidence does not contain the complete frozen round")
    digests = {}
    for name in ("proposals", "packets", "initial", "reviews"):
        contents = {key: value.encode("utf-8") for key, value in evidence[name].items()}
        verify_bundle_contents(contents)
        digests[name] = hashlib.sha256(contents["manifest.json"]).hexdigest()
    data = {name: {key: json.loads(value) for key, value in files.items()}
            for name, files in evidence.items()}
    plan = data["packets"]["plan.json"]
    proposal_rows = data["proposals"]["proposed-contracts.json"]
    proposals = {row["task_unit_id"]: row for row in proposal_rows}
    if len(proposals) != len(proposal_rows):
        raise ValueError("contract review proposal identities repeat")
    slots = ["reviewer-a", "reviewer-b", "reviewer-c"]
    if (plan.get("protocol_id") != "dual_blind_subagent_review_with_third_adjudication_v4_hash_semantics_explicit"
            or plan.get("reviewer_slots") != slots or plan.get("arms_or_outcomes_used") is not False
            or plan.get("proposals_bundle_sha256") != digests["proposals"]
            or plan.get("protocol_prompt_sha256") != "91e105f57840d3f81f7108de65c0b18392cccc48ef3980e6413abec02bd87b29"):
        raise ValueError("contract review protocol or proposal identity differs")
    assignments = {}
    for assignment in plan["assignments"]:
        task_id = assignment["task_unit_id"]
        primary = int(hashlib.sha256(f"primary:{task_id}".encode()).hexdigest(), 16) % 3
        expected = {"task_unit_id": task_id, "primary_reviewer": slots[primary],
                    "secondary_reviewer": slots[(primary + 1) % 3],
                    "blind_adjudicator": slots[(primary + 2) % 3]}
        if assignment != expected or task_id in assignments or task_id not in proposals:
            raise ValueError("contract review assignment does not replay its frozen hash")
        assignments[task_id] = assignment
    if len(assignments) != plan["task_unit_count"]:
        raise ValueError("contract review assignment count differs")
    if data["initial"]["source-plan.json"] != plan:
        raise ValueError("sealed contract review plan differs")
    fields = ("resolution_status", "entrypoint", "requirements", "inputs", "outputs",
              "side_effects", "environment_dependencies", "content_evidence")
    packet_fields = {"schema_version", "packet_id", "reviewer_slot", "blindness",
                     "protocol_prompt_sha256", "tasks"}
    blindness = {"arms_outcomes_roles_withheld": True, "cwe_readiness_oracles_withheld": True,
                 "other_reviewer_decisions_withheld": True}
    seen, task_inputs = {}, {}
    expected_files = {row["packet_id"] + ".json" for row in plan["packets"]}
    if set(data["decisions"]) != expected_files:
        raise ValueError("contract review decision file set is incomplete")
    for entry in plan["packets"]:
        packet = data["packets"][entry["file_name"]]
        slot = entry["reviewer_slot"]
        if (set(packet) != packet_fields or packet["blindness"] != blindness
                or packet["packet_id"] != entry["packet_id"] or packet["reviewer_slot"] != slot
                or packet["protocol_prompt_sha256"] != plan["protocol_prompt_sha256"]
                or [item["task_unit_id"] for item in packet["tasks"]] != entry["task_unit_ids"]):
            raise ValueError("contract review packet differs from its frozen plan")
        decisions = data["decisions"][entry["packet_id"] + ".json"]
        if not isinstance(decisions, list) or [row.get("task_unit_id") for row in decisions] != entry["task_unit_ids"]:
            raise ValueError("contract review decisions do not cover the packet in order")
        for item, raw_decision in zip(packet["tasks"], decisions, strict=True):
            task_id = item["task_unit_id"]
            assignment, proposal = assignments[task_id], proposals[task_id]
            core = {key: value for key, value in proposal.items() if key != "contract_id"}
            if (set(item) != {"task_unit_id", "source_prompt", "proposed_contract"}
                    or proposal["contract_id"] != content_id("functional_contract_", core)
                    or content_hash(item["source_prompt"]) != proposal["source_prompt_sha256"]
                    or item["proposed_contract"] != {key: proposal[key] for key in fields}
                    or slot not in (assignment["primary_reviewer"], assignment["secondary_reviewer"])
                    or (slot, task_id) in seen):
                raise ValueError("contract review is unbound, repeated or not blind")
            if task_id in task_inputs and task_inputs[task_id] != item:
                raise ValueError("independent reviewers received different task inputs")
            task_inputs[task_id] = item
            seen[slot, task_id] = _independent_contract_decision(raw_decision)
    expected_keys = {(a[field], task_id) for task_id, a in assignments.items()
                     for field in ("primary_reviewer", "secondary_reviewer")}
    if set(seen) != expected_keys:
        raise ValueError("contract review is missing an independent decision")
    expected_initial = [{"reviewer_slot": slot, **seen[slot, task_id]}
                        for slot in slots for task_id in sorted(assignments) if (slot, task_id) in seen]
    if data["initial"]["initial-decisions.json"] != expected_initial:
        raise ValueError("sealed initial decisions differ from the reviewer files")
    agreement, disputes = {}, {}
    principal = ("contract_status", "evidence_status", "source_specification_disposition")
    for task_id, assignment in sorted(assignments.items()):
        first = seen[assignment["primary_reviewer"], task_id]
        second = seen[assignment["secondary_reviewer"], task_id]
        if all(first[field] == second[field] for field in principal):
            agreement[task_id] = first
        else:
            disputes[task_id] = {**assignment, "primary_decision_sha256": content_hash(first),
                                 "secondary_decision_sha256": content_hash(second)}
    if (data["initial"]["agreements.json"] != list(agreement.values())
            or data["initial"]["disagreements.json"] != list(disputes.values())):
        raise ValueError("contract review agreement or disagreement does not replay")
    adjudication_plan = data["initial"]["adjudication-plan.json"]
    if (adjudication_plan["disagreement_count"] != len(disputes)
            or adjudication_plan["protocol_prompt_sha256"] != plan["protocol_prompt_sha256"]):
        raise ValueError("contract review adjudication plan differs")
    adjudication_files = {row["packet_id"] + ".json" for row in adjudication_plan["packets"]}
    if set(data["adjudications"]) != adjudication_files:
        raise ValueError("contract review lacks its complete blind third decisions")
    thirds = {}
    for entry in adjudication_plan["packets"]:
        packet = data["initial"][entry["file_name"]]
        expected_items = [task_inputs[task_id] for task_id in entry["task_unit_ids"]]
        if (set(packet) != packet_fields or packet["blindness"] != blindness
                or packet["tasks"] != expected_items or packet["reviewer_slot"] != entry["reviewer_slot"]
                or packet["packet_id"] != entry["packet_id"]
                or packet["protocol_prompt_sha256"] != plan["protocol_prompt_sha256"]
                or any(task_id not in disputes or entry["reviewer_slot"] != assignments[task_id]["blind_adjudicator"]
                       for task_id in entry["task_unit_ids"])):
            raise ValueError("third reviewer packet is not the same blind task input")
        values = data["adjudications"][entry["packet_id"] + ".json"]
        if not isinstance(values, list) or [row.get("task_unit_id") for row in values] != entry["task_unit_ids"]:
            raise ValueError("third reviewer decisions differ from their packet")
        for value in values:
            task_id = value["task_unit_id"]
            if task_id in thirds:
                raise ValueError("third reviewer supplied a repeated decision")
            thirds[task_id] = _independent_contract_decision(value)
    if set(thirds) != set(disputes):
        raise ValueError("a contract review disagreement lacks blind adjudication")
    reconstructed = []
    repair_count = 0
    for task_id in sorted(assignments):
        decision = agreement.get(task_id, thirds.get(task_id))
        terminal = None
        if decision["contract_status"] == "faithful" and decision["evidence_status"] == "supported":
            terminal = {"sufficient": "QUALITY_INCLUDED", "insufficient": "QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION",
                        "defect": "QUALITY_EXCLUDED_SOURCE_DEFECT", "uncertain": None}[decision["source_specification_disposition"]]
        core = {"schema_version": "contract-content-review-1.0", "task_unit_id": task_id,
                "contract_id": proposals[task_id]["contract_id"],
                **{key: value for key, value in decision.items() if key != "task_unit_id"},
                "terminal_quality_decision": terminal, "arms_or_outcomes_used": False}
        reconstructed.append({**core, "contract_content_review_record_sha256": content_hash(core)})
        repair_count += (terminal is None
                         or terminal == "QUALITY_INCLUDED" and proposals[task_id]["resolution_status"] != "resolved"
                         or any(_is_response_format_requirement(value)
                                for value in proposals[task_id]["requirements"]))
    if data["reviews"]["contract-content-reviews.json"] != reconstructed:
        raise ValueError("final contract reviews differ from independent decision replay")
    report = data["reviews"]["report.json"]
    expected_counts = {
        "task_unit_count": len(reconstructed),
        "terminal_quality_decision_count": sum(row["terminal_quality_decision"] is not None for row in reconstructed),
        "nonterminal_count": sum(row["terminal_quality_decision"] is None for row in reconstructed),
        "dual_review_agreement_count": len(agreement),
        "blind_third_adjudication_count": len(thirds),
        "contract_status_counts": dict(Counter(row["contract_status"] for row in reconstructed)),
        "evidence_status_counts": dict(Counter(row["evidence_status"] for row in reconstructed)),
        "source_specification_disposition_counts": dict(Counter(row["source_specification_disposition"] for row in reconstructed)),
        "quality_disposition_counts": dict(Counter(row["terminal_quality_decision"] for row in reconstructed
                                                    if row["terminal_quality_decision"] is not None)),
    }
    if (report["source_plan_sha256"] != content_hash(plan)
            or report["initial_review_bundle_sha256"] != digests["initial"]
            or report["proposals_bundle_sha256"] != digests["proposals"]
            or report.get("review_protocol_id") != plan["protocol_id"]
            or any(report.get(field) is not False for field in ("arms_or_outcomes_used", "formal_roles_used", "scientific_claim_allowed"))
            or any(report.get(field) != expected for field, expected in expected_counts.items())):
        raise ValueError("final contract review provenance or counts differ")
    return {"status": "CONTRACT_REVIEW_ROUND_INDEPENDENTLY_VERIFIED", "task_unit_count": len(reconstructed),
            "dual_review_agreement_count": len(agreement), "blind_third_adjudication_count": len(thirds),
            "contracts_requiring_repair": repair_count, "scientific_claim_allowed": False}


def _independent_contract_decision(row):
    """Validate the frozen decision fields and separately replay diagnostic normalization."""
    fields = {"task_unit_id", "contract_status", "evidence_status", "source_specification_disposition",
              "issue_codes", "repair_category", "reason"}
    issues = {"none", "unsupported_requirement", "missing_explicit_requirement", "entrypoint_mismatch",
              "input_mismatch", "output_mismatch", "side_effect_mismatch", "dependency_mismatch",
              "evidence_mismatch", "prompt_not_software_task", "external_context_missing",
              "ambiguous_interface", "uncertain_semantics", "other"}
    categories = {"EVIDENCE_BACKFILL_ONLY", "CONTRACT_EXTRACTION_ERROR", "OMITTED_EXPLICIT_REQUIREMENT",
                  "UNSUPPORTED_ADDITION", "SCOPE_OR_CONDITION_ERROR", "SOURCE_SPECIFICATION_INSUFFICIENT",
                  "SOURCE_DEFECT", "INDEPENDENT_ADJUDICATION_REQUIRED"}
    if (set(row) != fields or row["contract_status"] not in {"faithful", "faulty", "uncertain"}
            or row["evidence_status"] not in {"supported", "unsupported"}
            or row["source_specification_disposition"] not in {"sufficient", "insufficient", "defect", "uncertain"}
            or not isinstance(row["reason"], str) or not row["reason"].strip() or len(row["reason"]) > 1000
            or row["repair_category"] not in categories or not isinstance(row["issue_codes"], list)
            or not 1 <= len(row["issue_codes"]) <= 6 or len(set(row["issue_codes"])) != len(row["issue_codes"])
            or not set(row["issue_codes"]) <= issues):
        raise ValueError("independent contract decision violates the frozen field rules")
    supported = row["contract_status"] == "faithful" and row["evidence_status"] == "supported"
    if supported != (row["issue_codes"] == ["none"]):
        raise ValueError("independent contract decision issues contradict its principal decision")
    source = row["source_specification_disposition"]
    if source != "sufficient" or supported:
        category = {"sufficient": "EVIDENCE_BACKFILL_ONLY", "insufficient": "SOURCE_SPECIFICATION_INSUFFICIENT",
                    "defect": "SOURCE_DEFECT", "uncertain": "INDEPENDENT_ADJUDICATION_REQUIRED"}[source]
    elif row["repair_category"] != "EVIDENCE_BACKFILL_ONLY":
        category = row["repair_category"]
    elif "missing_explicit_requirement" in row["issue_codes"]:
        category = "OMITTED_EXPLICIT_REQUIREMENT"
    elif "unsupported_requirement" in row["issue_codes"]:
        category = "UNSUPPORTED_ADDITION"
    else:
        category = "CONTRACT_EXTRACTION_ERROR"
    return {**row, "repair_category": category}


def _verify_reviewed_source_contracts(rounds, tasks, material, available, source_digest):
    """Independently bind the latest reviewed contracts to prepared source bytes."""
    import json
    from prompt_mechanism_study.records import content_id
    from prompt_mechanism_study.curation import _is_response_format_requirement

    updates = {}
    for evidence in rounds:
        verify_contract_review_evidence(evidence)
        report = json.loads(evidence["proposals"]["report.json"])
        if (report.get("base_bundle_sha256") != source_digest
                or not report.get("source_use_bundle_sha256")
                or report.get("arms_or_outcomes_used") is not False):
            raise ValueError("reviewed source contract population or preparation provenance differs")
        proposed = {row["task_unit_id"]: row for row in json.loads(evidence["proposals"]["proposed-contracts.json"])}
        reviews = json.loads(evidence["reviews"]["contract-content-reviews.json"])
        reviewed_ids = {row["task_unit_id"] for row in reviews}
        for key, proposal in proposed.items():
            if key not in available or key in updates and key not in reviewed_ids and proposal != updates[key]["proposal"]:
                raise ValueError("reviewed source contract changed a protected or unreviewed task")
        for review in reviews:
            key, proposal = review["task_unit_id"], proposed[review["task_unit_id"]]
            task, restoration = tasks[key], material[key]["input_restoration"]
            visible = restoration["model_visible_input"] if restoration else task["model_visible_input"]
            record_id = restoration["normalized_record_id"] if restoration else task["representative_record_id"]
            core = {field: value for field, value in proposal.items() if field != "contract_id"}
            if (proposal.get("schema_version") != "functional-contract-cleaning-proposal-1.0"
                    or proposal["contract_id"] != content_id("functional_contract_", core)
                    or proposal["record_id"] != record_id or proposal["arms_or_outcomes_used"] is not False
                    or proposal["source_prompt_sha256"] != visible["natural_prompt_content_sha256"]):
                raise ValueError("reviewed contract does not bind to the prepared source identity")
            evidence_fields = proposal["content_evidence"]
            fields = ("requirements", "inputs", "outputs", "side_effects", "environment_dependencies")
            if (set(evidence_fields) != {"offset_basis", "entrypoint", *fields}
                    or evidence_fields["offset_basis"] != "utf8_bytes_of_exact_natural_prompt_v1"):
                raise ValueError("reviewed source contract evidence envelope differs")
            groups = []
            if proposal["entrypoint"] is None:
                if evidence_fields["entrypoint"] != []:
                    raise ValueError("absent reviewed entrypoint carries evidence")
            else:
                groups.append((proposal["entrypoint"], evidence_fields["entrypoint"]))
            for field in fields:
                values, bindings = proposal[field], evidence_fields[field]
                if not isinstance(values, list) or len(values) > 32 or len(values) != len(bindings):
                    raise ValueError("reviewed source contract values and evidence differ")
                groups.extend(zip(values, bindings, strict=True))
            prompt_bytes = visible["natural_prompt"].encode("utf-8")
            for value, group in groups:
                if not isinstance(value, str) or not value.strip() or not isinstance(group, list) or not group:
                    raise ValueError("reviewed source contract lacks bound nonempty values")
                for span in group:
                    if (set(span) != {"source_prompt_sha256", "start_byte", "end_byte", "quoted_text", "span_sha256"}
                            or type(span["start_byte"]) is not int or type(span["end_byte"]) is not int
                            or not 0 <= span["start_byte"] < span["end_byte"] <= len(prompt_bytes)
                            or span["source_prompt_sha256"] != visible["natural_prompt_content_sha256"]):
                        raise ValueError("reviewed source contract evidence identity differs")
                    literal = prompt_bytes[span["start_byte"]:span["end_byte"]]
                    if literal.decode("utf-8") != span["quoted_text"] or hashlib.sha256(literal).hexdigest() != span["span_sha256"]:
                        raise ValueError("reviewed source contract evidence is not an exact source span")
            updates[key] = {"proposal": proposal, "review": review, "round_sha256": content_hash(evidence)}
    for update in updates.values():
        proposal, review = update["proposal"], update["review"]
        if (review["terminal_quality_decision"] is None
                or proposal["resolution_status"] not in {"resolved", "ambiguous", "unsupported"}
                or proposal["resolution_status"] == "resolved" and not proposal["requirements"]
                or review["terminal_quality_decision"] == "QUALITY_INCLUDED" and proposal["resolution_status"] != "resolved"
                or any(_is_response_format_requirement(value) for value in proposal["requirements"])):
            raise ValueError("reviewed source contract is still nonterminal or needs repair")
    return updates


def _verify_native_source_review(task, contract, material, review):
    """Independently check source/test binding and reconstruct inert audit counts."""
    import base64

    required = {"task_unit_id", "source_prompt_sha256", "contract_id", "protocol_prompt_sha256", "reviewer_id", "assets", "arms_or_outcomes_used"}
    prompt = task["model_visible_input"]["natural_prompt"]
    if (not isinstance(review, dict) or set(review) != required
            or review["task_unit_id"] != task["task_unit_id"]
            or review["source_prompt_sha256"] != content_hash(prompt)
            or review["contract_id"] != contract["contract_id"]
            or review["protocol_prompt_sha256"] != "7b16d9c91ddd7d722642477c09bbadf8f8adaaf34dea051ede5f728de6c809ca"
            or review["arms_or_outcomes_used"] is not False
            or not isinstance(review["reviewer_id"], str) or not review["reviewer_id"].strip()
            or not isinstance(review["assets"], list)):
        raise ValueError("native source review is not bound to the current source contract")
    bindings = {content_hash(binding): binding for binding in material["asset_bindings"]
                if binding["task_unit_id"] == task["task_unit_id"]}
    raw_assets = {asset["sha256"]: base64.b64decode(asset["content_base64"], validate=True)
                  for asset in material["assets"]}
    by_binding = {row.get("binding_sha256"): row for row in review["assets"]}
    if not bindings or set(by_binding) != set(bindings) or len(by_binding) != len(review["assets"]):
        raise ValueError("native source review does not account for every asset binding exactly once")
    functional, security, states = 0, 0, Counter()
    for key, binding in bindings.items():
        row = by_binding[key]
        if (set(row) != {"binding_sha256", "asset_sha256", "alignment", "observed_role",
                         "functional_checks", "security_checks", "limitations", "reason"}
                or row["asset_sha256"] != binding["asset_sha256"]
                or row["alignment"] not in {"supported", "partial", "contradicted", "unresolved"}
                or row["observed_role"] not in {"SETUP", "DEPENDENCIES", "EVALUATION_ENTRY_POINT",
                    "FUNCTIONAL_TESTS", "SECURITY_TESTS", "MIXED_TESTS", "NO_ASSERTIONS", "UNRESOLVED"}
                or not isinstance(row["reason"], str) or not row["reason"].strip()
                or any(not isinstance(row[field], list) for field in ("functional_checks", "security_checks", "limitations"))
                or any(not isinstance(value, str) or not value.strip() for value in row["limitations"])):
            raise ValueError("native source review assertion fields or asset identity differ")
        raw = raw_assets[row["asset_sha256"]]
        if hashlib.sha256(raw).hexdigest() != row["asset_sha256"]:
            raise ValueError("native source asset byte identity differs")
        if ((row["functional_checks"] or row["security_checks"] or row["alignment"] != "supported") and not row["limitations"]
                or (row["functional_checks"] or row["security_checks"]) and row["alignment"] in {"contradicted", "unresolved"}):
            raise ValueError("native source review asserts coverage without alignment or limits")
        if (row["functional_checks"] and row["observed_role"] not in {"FUNCTIONAL_TESTS", "MIXED_TESTS"}
                or row["security_checks"] and row["observed_role"] not in {"SECURITY_TESTS", "MIXED_TESTS"}):
            raise ValueError("native assertion roles conflate functional and security coverage")
        for field in ("functional_checks", "security_checks"):
            for check in row[field]:
                identity = "requirement_index" if field == "functional_checks" else "criterion"
                if (set(check) != {identity, "source_evidence", "asset_evidence"}
                        or not isinstance(check["source_evidence"], list) or not check["source_evidence"]
                        or not isinstance(check["asset_evidence"], list) or not check["asset_evidence"]):
                    raise ValueError("native assertion lacks distinct source and asset evidence")
                if identity == "requirement_index":
                    if type(check[identity]) is not int or not 1 <= check[identity] <= len(contract["requirements"]):
                        raise ValueError("native assertion refers to an absent current source requirement")
                elif not isinstance(check[identity], str) or not check[identity].strip():
                    raise ValueError("native assertion lacks its exact security property")
                for span in check["source_evidence"]:
                    if (set(span) != {"start", "end", "text"}
                            or type(span["start"]) is not int or type(span["end"]) is not int
                            or not 0 <= span["start"] < span["end"] <= len(prompt)
                            or prompt[span["start"]:span["end"]] != span["text"]):
                        raise ValueError("native assertion context does not match its source span")
                for span in check["asset_evidence"]:
                    if (set(span) != {"start_byte", "end_byte", "quoted_text"}
                            or type(span["start_byte"]) is not int or type(span["end_byte"]) is not int
                            or not 0 <= span["start_byte"] < span["end_byte"] <= len(raw)
                            or raw[span["start_byte"]:span["end_byte"]].decode("utf-8") != span["quoted_text"]):
                        raise ValueError("native assertion does not match its asset byte span")
        functional += len(row["functional_checks"])
        security += len(row["security_checks"])
        states[row["alignment"]] += 1
    return {"task_unit_id": task["task_unit_id"], "review_sha256": content_hash(review),
            "asset_binding_count": len(bindings), "alignment_counts": dict(sorted(states.items())),
            "functional_assertion_mappings": functional, "security_assertion_mappings": security,
            "status": "SOURCE_ASSET_REVIEWED_MEASUREMENT_QUALIFICATION_PENDING",
            "tests_executed": False, "measurement_qualified": False, "formal_admission": False}


def _verify_candidate_context_coverage(task, book_text, review):
    """Replay exhaustive source-context accounting independently of its producer."""
    import json
    book_digest = hashlib.sha256(book_text.encode("utf-8")).hexdigest()
    prompt_digest = "7e454d5755e2cf3f5bf118202b6be65fd23558d7a1c2dd198e83fc63ee48f5a1"
    if book_digest != "651feaf80ebb6daf5cb82625d4d232b84ba84cc49ef68f496f53509c3c371abd":
        raise ValueError("independent candidate review policy meanings differ")
    book = json.loads(book_text)
    prompt = task["model_visible_input"]["natural_prompt"]
    if (not isinstance(review, dict) or set(review) != {
        "task_unit_id", "source_prompt_sha256", "policy_book_sha256", "protocol_prompt_sha256",
        "reviewer_id", "groups", "arms_or_outcomes_used",
    } or review["task_unit_id"] != task["task_unit_id"] or review["source_prompt_sha256"] != content_hash(prompt)
            or review["policy_book_sha256"] != book_digest or review["protocol_prompt_sha256"] != prompt_digest
            or not isinstance(review["reviewer_id"], str) or not review["reviewer_id"].strip()
            or review["arms_or_outcomes_used"] is not False or not isinstance(review["groups"], list)):
        raise ValueError("independent candidate context provenance differs")
    language = task["pre_treatment_source_metadata"]["language"]
    defined = language in book["supported_definition_languages"]
    by_group = {group["group_id"]: group for group in book["groups"]}
    covered, selected, states = [], [], Counter()
    for judgment in review["groups"]:
        if (not isinstance(judgment, dict) or set(judgment) != {"group_ids", "state", "evidence", "reason"}
                or not isinstance(judgment["group_ids"], list) or not judgment["group_ids"]
                or not isinstance(judgment["reason"], str) or not judgment["reason"].strip()
                or not isinstance(judgment["evidence"], list)
                or judgment["state"] not in {"REVIEW", "NO_SOURCE_CONTEXT", "LANGUAGE_DEFINITION_MISSING"}):
            raise ValueError("independent candidate context judgment is malformed")
        state = judgment["state"]
        if (defined and state == "LANGUAGE_DEFINITION_MISSING"
                or not defined and state != "LANGUAGE_DEFINITION_MISSING"
                or state == "REVIEW" and len(judgment["group_ids"]) != 1
                or state != "LANGUAGE_DEFINITION_MISSING" and not judgment["evidence"]):
            raise ValueError("independent candidate context language or evidence scope differs")
        for group_id in judgment["group_ids"]:
            if group_id not in by_group or group_id in covered:
                raise ValueError("independent candidate context has an unknown or repeated group")
            covered.append(group_id)
            states[state] += 1
            if state == "REVIEW":
                selected.extend(item["candidate_id"] for item in by_group[group_id]["candidates"])
        for span in judgment["evidence"]:
            if (not isinstance(span, dict) or set(span) != {"start", "end", "text"}
                    or type(span["start"]) is not int or type(span["end"]) is not int
                    or not 0 <= span["start"] < span["end"] <= len(prompt)
                    or prompt[span["start"]:span["end"]] != span["text"]):
                raise ValueError("independent candidate context source span differs")
    if set(covered) != set(by_group):
        raise ValueError("independent candidate context review leaves a group unaccounted")
    return {"task_unit_id": task["task_unit_id"], "review_sha256": content_hash(review),
            "policy_book_sha256": book_digest, "protocol_prompt_sha256": prompt_digest,
            "group_state_counts": dict(sorted(states.items())),
            "candidate_ids_requiring_review": sorted(selected),
            "status": "SOURCE_CONTEXT_REVIEWED_NO_QUALIFICATION_GRANTED", "formal_admission": False}


def verify_source_use(output, source_bundle, reservation_bundle, catalog_path, registry_path,
                      *, source_roots=None, source_archives=None) -> dict[str, object]:
    """Independently reconstruct source uses, role firewalls and inert asset identities.

    Source-only source/contract verification is shared; the source-use producer,
    its selection helper and its functional-scope decisions are not called.
    Original source directories optionally close the byte-level recovery audit.
    """
    import json
    from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle
    from prompt_mechanism_study.contract_cleaning import verify_contract_content_data
    from prompt_mechanism_study.functional_judge import syntax_parser_identity

    verify_contract_content_data(source_bundle)
    verify_bundle(reservation_bundle)
    manifest = verify_bundle(output)
    base_files = {"source-use-rule.json", "task-uses.json", "source-material.json",
                  "prepared-tasks.json", "candidate-source-reviews.json", "report.json"}
    has_contract_reviews = "source-contract-reviews.json" in manifest["files"]
    has_native_reviews = "native-source-reviews.json" in manifest["files"]
    has_context_reviews = "candidate-context-reviews.json" in manifest["files"]
    optional_files = (({"source-contract-reviews.json"} if has_contract_reviews else set())
                      | ({"native-source-reviews.json"} if has_native_reviews else set())
                      | ({"candidate-context-reviews.json"} if has_context_reviews else set()))
    if set(manifest["files"]) != base_files | optional_files:
        raise ValueError("source-use bundle file set differs from the active path")
    review_rounds = read_json(output / "source-contract-reviews.json") if has_contract_reviews else []
    if not isinstance(review_rounds, list) or has_contract_reviews and not review_rounds:
        raise ValueError("source-use contract review rounds are empty or malformed")
    report = read_json(output / "report.json")
    rule = read_json(output / "source-use-rule.json")
    rows = read_json(output / "task-uses.json")
    material = read_json(output / "source-material.json")
    reviews = read_json(output / "candidate-source-reviews.json")
    prepared_tasks = read_json(output / "prepared-tasks.json")
    native_reviews = read_json(output / "native-source-reviews.json") if has_native_reviews else []
    if not isinstance(native_reviews, list):
        raise ValueError("source-use native source review list is malformed")
    routing_by_cwe = defaultdict(list)
    mechanisms = {item["realization_id"]: item for item in read_json(registry_path)["mechanisms"]}
    for query in read_json(catalog_path)["queries"]:
        realization = mechanisms[query["realization_id"]]
        if realization["cwe_id"] != query["cwe_id"]:
            raise ValueError("source-use catalog and realization coordinates differ")
        routing_by_cwe[query["cwe_id"]].append({
            "query_id": query["query_id"], "realization_id": query["realization_id"],
            "profile_language": realization["oracle_profile_id"].split(".")[0],
        })
    expected_hashes = {
        "source_manifest_sha256": file_sha256(source_bundle / "manifest.json"),
        "reservation_manifest_sha256": file_sha256(reservation_bundle / "manifest.json"),
        "catalog_sha256": file_sha256(catalog_path), "registry_sha256": file_sha256(registry_path),
        "source_use_rule_sha256": content_hash(rule),
    }
    if any(report.get(key) != value for key, value in expected_hashes.items()):
        raise ValueError("source-use input identity failed independent verification")
    axes = ["context", "target_operation", "security_boundary", "non_target_invariants", "arm_compatibility"]
    if (rule.get("scientific_claim_allowed") is not False
            or rule.get("candidate_sufficiency", {}).get("required_axes") != axes
            or rule["candidate_sufficiency"].get("missing_axis") != "unresolved"):
        raise ValueError("source-use rule violates the conservative source boundary")

    tables = []
    for name in ("task-units.jsonl", "task-quality.jsonl", "functional-contracts.jsonl", "task-roles.jsonl"):
        values = [json.loads(line) for line in (source_bundle / name).read_text(encoding="utf-8").splitlines()]
        indexed = {value["task_unit_id"]: value for value in values}
        if len(indexed) != len(values):
            raise ValueError("source-use source table contains repeated task identities")
        tables.append(indexed)
    tasks, quality, contracts, roles = tables
    by_id = {row["task_unit_id"]: row for row in rows}
    prepared_by_id = {row["task_unit_id"]: row for row in prepared_tasks}
    material_by_id = {row["task_unit_id"]: row for row in material["tasks"]}
    if (len(by_id) != len(rows) or len(prepared_by_id) != len(prepared_tasks)
            or len(material_by_id) != len(material["tasks"])
            or any(set(table) != set(tasks) for table in (*tables[1:], by_id, prepared_by_id, material_by_id))):
        raise ValueError("source-use task accounting is not complete and unique")
    reservations = {}
    reservation_groups = set()
    for label in ("QUAL_DEV", "QUAL_ACCEPT"):
        selection = read_json(reservation_bundle / (label.lower().replace("_", "-") + "-selection.json"))
        if selection["source_manifest_sha256"] != expected_hashes["source_manifest_sha256"]:
            raise ValueError("source-use reservation population differs")
        for task_id in selection["task_ids_in_review_order"]:
            if task_id not in tasks or task_id in reservations:
                raise ValueError("source-use qualification reservations overlap")
            role = roles[task_id]
            group = role["near_duplicate_group_id"]
            if (role["data_role"] != "UNASSIGNED" or role["exposure_status"] != "SOURCE_CURATED_ONLY"
                    or role["prospective_formal_role_assigned"] or group in reservation_groups):
                raise ValueError("source-use reservation exposure/group firewall failed")
            reservations[task_id] = label
            reservation_groups.add(group)
    exposed = {key for key, role in roles.items()
               if role["data_role"] != "UNASSIGNED" or role["exposure_status"] != "SOURCE_CURATED_ONLY"
               or role["prospective_formal_role_assigned"]}
    if any(roles[key]["near_duplicate_group_id"] in reservation_groups for key in exposed):
        raise ValueError("source-use qualification reservation overlaps an exposed group")
    protected_groups = {roles[key]["near_duplicate_group_id"] for key in exposed | set(reservations)}
    available = {key for key in tasks if roles[key]["near_duplicate_group_id"] not in protected_groups}
    updates = _verify_reviewed_source_contracts(review_rounds, tasks, material_by_id, available,
                                               expected_hashes["source_manifest_sha256"])
    current_tasks, current_quality, current_contracts = dict(tasks), dict(quality), dict(contracts)
    for key, update in updates.items():
        proposal, review = update["proposal"], update["review"]
        restoration = material_by_id[key]["input_restoration"]
        if restoration:
            current_tasks[key] = {**tasks[key], "model_visible_input": restoration["model_visible_input"],
                                  "representative_record_id": restoration["normalized_record_id"]}
        current_quality[key] = {"task_unit_id": key, "quality_disposition": review["terminal_quality_decision"]}
        current_contracts[key] = {**proposal, "review": review,
                                  "functional_contract_record_sha256": content_hash({"proposal": proposal, "review": review})}
    native_by_task = {}
    for review in native_reviews:
        key = review["task_unit_id"]
        if (key not in available or key in native_by_task
                or material_by_id[key]["input_restoration"] is not None and key not in updates):
            raise ValueError("native source review uses a protected, repeated or unreviewed restored input")
        native_by_task[key] = _verify_native_source_review(current_tasks[key], current_contracts[key], material, review)
    candidate_by_task = defaultdict(list)
    for review in reviews:
        key = review["task_unit_id"]
        if key not in available or material_by_id[key]["input_restoration"] is not None and key not in updates:
            raise ValueError("candidate review uses a protected or unrevalidated restored input")
        candidate_by_task[key].append(_verify_source_sufficiency_review(current_tasks[key], current_quality[key], review, report["source_use_rule_sha256"]))
    coordinates = [(review["task_unit_id"], review["candidate_id"]) for review in reviews]
    if len(set(coordinates)) != len(coordinates):
        raise ValueError("source-use candidate reviews repeat a coordinate")
    context_by_task = {}
    if has_context_reviews:
        context_evidence = read_json(output / "candidate-context-reviews.json")
        if (not isinstance(context_evidence, dict) or set(context_evidence) != {"policy_book_text", "reviews"}
                or not isinstance(context_evidence["policy_book_text"], str)
                or not isinstance(context_evidence["reviews"], list) or not context_evidence["reviews"]):
            raise ValueError("independent candidate context evidence is malformed")
        context_reviewers = {}
        for review in context_evidence["reviews"]:
            key = review["task_unit_id"]
            if (key not in available or key in context_by_task
                    or material_by_id[key]["input_restoration"] is not None and key not in updates):
                raise ValueError("independent candidate context review uses a protected or unreviewed input")
            context_by_task[key] = _verify_candidate_context_coverage(current_tasks[key], context_evidence["policy_book_text"], review)
            context_reviewers[key] = review["reviewer_id"]
        expected_coordinates = {(key, candidate) for key, decision in context_by_task.items()
                                for candidate in decision["candidate_ids_requiring_review"]}
        if set(coordinates) != expected_coordinates:
            raise ValueError("independent candidate decisions omit or add a screened policy")
        frozen_candidates = {candidate["candidate_id"]: candidate
                             for group in json.loads(context_evidence["policy_book_text"])["groups"]
                             for candidate in group["candidates"]}
        for review in reviews:
            frozen = frozen_candidates[review["candidate_id"]]
            if (review["candidate_family"] != frozen["candidate_family"]
                    or review["candidate_policy"] != frozen["candidate_policy"]
                    or review["reviewer_id"] != context_reviewers[review["task_unit_id"]]):
                raise ValueError("independent candidate review changed its frozen definition or reviewer")
    restored_count = 0
    withheld_count = 0
    for key, task in tasks.items():
        row, role, contract = by_id[key], roles[key], current_contracts[key]
        material_row = material_by_id[key]
        if row["source_material"] != material_row:
            raise ValueError("source-use source material linkage differs")
        restoration = material_row["input_restoration"]
        apply_restoration = restoration is not None and key in available
        input_review_pending = apply_restoration and key not in updates
        prepared = restoration["model_visible_input"] if apply_restoration else task["model_visible_input"]
        if restoration is not None:
            _verify_restored_source_input(task, restoration, source_roots)
        specification = contract["review"]["source_specification_disposition"]
        scope = ("unresolved" if input_review_pending or specification == "defect" or not contract["requirements"]
                 else "partial" if specification == "insufficient" else "complete")
        restoration_status = ("APPLIED_SOURCE_CONTRACT_REVIEWED" if apply_restoration and key in updates
                              else "APPLIED_PENDING_SOURCE_CONTRACT_REVIEW" if apply_restoration
                              else "WITHHELD_PRESERVE_FROZEN_ROLE_INPUT" if restoration
                              else "ORIGINAL_INPUT_RETAINED")
        restored_count += apply_restoration
        withheld_count += restoration is not None and not apply_restoration
        disposition = quality[key]["quality_disposition"]
        if role["data_role"] != "UNASSIGNED":
            use = "PRESERVE_" + role["data_role"]
        elif key in reservations:
            use = "PRESERVE_" + reservations[key] + "_RESERVATION"
        elif key not in available:
            use = "PROTECTED_EXPOSURE_OR_NEAR_DUPLICATE"
        elif current_quality[key]["quality_disposition"] == "QUALITY_EXCLUDED_SOURCE_DEFECT":
            use = "SOURCE_CORRECTION_OR_DEFINED_DIAGNOSTICS_ONLY"
        else:
            use = "CANDIDATE_SOURCE_REVIEW"
        language = task["pre_treatment_source_metadata"]["language"]
        routing = [query for cwe in task["pre_treatment_source_metadata"]["source_declared_cwe_ids"]
                   for query in routing_by_cwe[cwe]]
        pending = []
        if key in available:
            if input_review_pending:
                pending.append("source_contract_review_for_restored_input_required")
            context_review = context_by_task.get(key)
            if context_review is not None:
                if context_review["group_state_counts"].get("LANGUAGE_DEFINITION_MISSING"):
                    pending.append("language_specific_candidate_policy_definition_missing")
                elif not context_review["candidate_ids_requiring_review"]:
                    pending.append("no_source_context_in_reviewed_policy_book")
            elif not routing:
                pending.append("candidate_catalog_scope_missing")
            elif not any(query["profile_language"] == language for query in routing):
                pending.append("language_specific_intervention_and_oracle_scope_missing")
            if not candidate_by_task[key] and context_review is None:
                pending.append("candidate_specific_source_sufficiency_unreviewed")
            pending.extend(["representation_and_measurement_qualification_incomplete",
                            "formal_roles_and_candidate_support_not_frozen"])
        expected = {
            "source_lineage_id": task["source_lineage_id"], "near_duplicate_group_id": role["near_duplicate_group_id"],
            "language": task["pre_treatment_source_metadata"]["language"],
            "source_cwe_ids": task["pre_treatment_source_metadata"]["source_declared_cwe_ids"],
            "source_task_sha256": task["task_unit_record_sha256"],
            "source_quality_sha256": quality[key]["task_quality_record_sha256"],
            "source_contract_sha256": contracts[key]["functional_contract_record_sha256"],
            "source_role_sha256": role["task_role_record_sha256"],
            "source_quality_unchanged": disposition, "existing_role": role["data_role"],
            "existing_exposure": role["exposure_status"], "qualification_reservation": reservations.get(key),
            "available_for_source_review": key in available, "source_use": use,
            "model_visible_input_sha256": task["model_visible_input"]["model_visible_input_identity_sha256"],
            "prepared_model_visible_input_sha256": prepared["model_visible_input_identity_sha256"],
            "prepared_natural_prompt_sha256": prepared["natural_prompt_content_sha256"],
            "input_restoration_status": restoration_status, "functional_measurement_scope": scope,
            "candidate_source_decisions": sorted(candidate_by_task[key], key=lambda item: item["candidate_id"]),
            "syntax_parser": syntax_parser_identity(language),
            "catalog_routing_not_eligibility": routing, "pending_requirements": pending,
            "formal_admission": False,
            **({"native_asset_review": native_by_task.get(key)} if has_native_reviews else {}),
            **({"candidate_context_review": context_by_task.get(key)} if has_context_reviews else {}),
            **({"prepared_source_quality": None if input_review_pending else current_quality[key]["quality_disposition"],
                "source_contract_review": ({"contract_id": updates[key]["proposal"]["contract_id"],
                                             "review_record_sha256": updates[key]["review"]["contract_content_review_record_sha256"],
                                             "round_sha256": updates[key]["round_sha256"]} if key in updates else None)}
               if review_rounds else {}),
        }
        if (set(row) != {"task_unit_id", "source_material", *expected}
                or any(row.get(field) != value for field, value in expected.items())):
            raise ValueError("source-use scope, identity or role failed independent reconstruction")
        if (material_row["frozen_prompt_changed"] is not False or material_row["independent_units_added"] != 0
                or material_row["inherited_asset_count"] != len(task["evaluation_asset_refs"]["source_test_refs"])
                or material_row["source_members_replayed"] != len(task["source_members"])
                or material_row["source_prompt_status"] != ("ORIGINAL_SOURCE_INPUT_RESTORED" if restoration else "EXACT_PROMPT_REPLAY")):
            raise ValueError("source-use recovery altered its parent source or independent unit count")
        requirements = []
        if not input_review_pending:
            for index, criterion in enumerate(contract["requirements"]):
                requirements.append({
                    "requirement_id": f"{contract['contract_id']}:requirement:{index + 1}",
                    "criterion": criterion, "source_evidence": contract["content_evidence"]["requirements"][index],
                })
        adapted_contract = {
            "language": language, "measurement_scope": scope,
            "source_prompt_sha256": prepared["natural_prompt_content_sha256"],
            "parent_source_contract_sha256": contract["functional_contract_record_sha256"],
            "parent_contract_applies_to_current_input": not input_review_pending,
            "requirements": requirements,
            "environment_dependencies": [] if input_review_pending else contract["environment_dependencies"],
        }
        if not input_review_pending:
            adapted_contract["review"] = contract["review"]
        if key in updates:
            adapted_contract["source_contract_review_sha256"] = updates[key]["review"]["contract_content_review_record_sha256"]
            adapted_contract["original_parent_source_contract_sha256"] = contracts[key]["functional_contract_record_sha256"]
        expected_prepared = {
            "task_id": key, "task_unit_id": key, "prompt": prepared["natural_prompt"],
            "prompt_sha256": prepared["natural_prompt_content_sha256"],
            "model_visible_input_sha256": prepared["model_visible_input_identity_sha256"],
            "language": language,
            "source_declared_cwe_ids": task["pre_treatment_source_metadata"]["source_declared_cwe_ids"],
            "source_lineage_id": task["source_lineage_id"], "near_duplicate_group_id": role["near_duplicate_group_id"],
            "source_task_record_sha256": task["task_unit_record_sha256"],
            "source_use": use, "functional_contract": adapted_contract, "formal_use_authorized": False,
        }
        if prepared_by_id[key] != expected_prepared:
            raise ValueError("prepared task prompt, parent contract or permission does not replay")
    asset_report = _verify_source_asset_contents(tasks, material, source_roots, source_archives)
    good = [by_id[key] for key in available if quality[key]["quality_disposition"] == "QUALITY_INCLUDED"]
    counts = {
        "task_unit_count": len(tasks), "near_duplicate_groups": len({role["near_duplicate_group_id"] for role in roles.values()}),
        "task_unit_id_set_sha256": content_hash(sorted(tasks)),
        "available_source_review_tasks": len(available),
        "available_source_review_independent_groups": len({roles[key]["near_duplicate_group_id"] for key in available}),
        "quality_passed_unexposed_unreserved": len(good),
        "quality_passed_with_unchanged_input": sum(row["input_restoration_status"] == "ORIGINAL_INPUT_RETAINED" for row in good),
        "quality_passed_restored_input_pending_review": sum(row["input_restoration_status"] == "APPLIED_PENDING_SOURCE_CONTRACT_REVIEW" for row in good),
        "quality_passed_unexposed_unreserved_by_language": dict(sorted(Counter(row["language"] for row in good).items())),
        "source_use_counts": dict(sorted(Counter(row["source_use"] for row in rows).items())),
        "source_quality_counts": dict(sorted(Counter(row["source_quality_unchanged"] for row in rows).items())),
        "language_counts": dict(sorted(Counter(row["language"] for row in rows).items())),
        "functional_scope_counts": dict(sorted(Counter(row["functional_measurement_scope"] for row in rows).items())),
        "pending_requirement_counts": dict(sorted(Counter(item for row in rows for item in row["pending_requirements"]).items())),
        "source_input_restoration_candidates": restored_count + withheld_count,
        "prompt_repairs": restored_count, "withheld_protected_input_restorations": withheld_count,
        "candidate_source_review_count": len(reviews),
        "source_sufficient_candidate_count": sum(row["status"] == "SOURCE_SUFFICIENT_PENDING_QUALIFICATION"
                                                  for values in candidate_by_task.values() for row in values),
        "source_native_asset_bindings": asset_report["bindings"],
        "source_native_asset_contents": asset_report["contents"],
        "source_asset_origin_pending": asset_report["origin_pending"],
        "tasks_with_native_assets": asset_report["tasks_with_assets"],
        "recovered_source_asset_bindings": asset_report["recovered_bindings"],
        "new_independent_units": 0, "formal_admission_count": 0, "provider_calls_made": 0,
        "formal_use_authorized": False, "scientific_claim_allowed": False, "arms_or_outcomes_used": False,
    }
    if review_rounds:
        current_good = [by_id[key] for key in available if by_id[key]["prepared_source_quality"] == "QUALITY_INCLUDED"]
        counts.update({
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
    if has_native_reviews:
        counts.update({"native_asset_review_task_count": len(native_by_task),
                       "native_asset_review_binding_count": sum(row["asset_binding_count"] for row in native_by_task.values()),
                       "native_functional_assertion_mappings": sum(row["functional_assertion_mappings"] for row in native_by_task.values()),
                       "native_security_assertion_mappings": sum(row["security_assertion_mappings"] for row in native_by_task.values()),
                       "native_measurement_qualifications_granted": 0})
    if has_context_reviews:
        all_states = Counter()
        for decision in context_by_task.values():
            all_states.update(decision["group_state_counts"])
        counts.update({"candidate_context_review_task_count": len(context_by_task),
                       "candidate_context_group_state_counts": dict(sorted(all_states.items())),
                       "candidate_policy_book_sha256": hashlib.sha256(context_evidence["policy_book_text"].encode("utf-8")).hexdigest()})
    if (set(report) != {*expected_hashes, *counts, "status", "reproduction"}
            or report.get("status") != "SOURCE_USE_PREPARED_QUALIFICATION_PENDING"
            or any(report.get(key) != value for key, value in counts.items())):
        raise ValueError("source-use report failed independent count reconstruction")
    if (material["status"] != "SOURCE_MATERIAL_REPLAYED_NOT_MEASUREMENT_QUALIFICATION"
            or material["prompt_repairs"] != restored_count + withheld_count
            or material["frozen_source_records_replayed"] != len({member["record_id"] for task in tasks.values() for member in task["source_members"]})
            or material["independent_units_added"] != 0
            or material["reference_code_executed"] is not False or material["arms_or_outcomes_used"] is not False):
        raise ValueError("source material summary overstates recovery or scientific permissions")
    return {"status": "SOURCE_USE_VERIFIED" if source_roots is not None else "SOURCE_USE_STRUCTURE_VERIFIED",
            "task_unit_count": len(tasks), "prompt_restorations": restored_count,
            "protected_input_restorations_withheld": withheld_count,
            "source_asset_contents": asset_report["contents"],
            "source_bytes_replayed": source_roots is not None,
            **({"source_contracts_independently_reviewed": len(updates)} if review_rounds else {}),
            "formal_admission_count": 0, "scientific_claim_allowed": False}


def _verify_source_sufficiency_review(task, quality, review, rule_hash):
    from prompt_mechanism_study.records import content_id
    required = {"task_unit_id", "candidate_id", "candidate_family", "candidate_policy", "source_prompt_sha256",
                "source_use_rule_sha256", "reviewer_id", "axes", "arms_or_outcomes_used"}
    if (set(review) != required or review["task_unit_id"] != task["task_unit_id"]
            or review["source_prompt_sha256"] != content_hash(task["model_visible_input"]["natural_prompt"])
            or review["source_use_rule_sha256"] != rule_hash or review["arms_or_outcomes_used"] is not False
            or not isinstance(review["reviewer_id"], str) or not review["reviewer_id"].strip()):
        raise ValueError("source sufficiency review provenance is invalid")
    family = {"Atomic": "atomic", "Pair": "pair"}.get(review["candidate_family"])
    if family is None or review["candidate_id"] != content_id(family + "_policy_key_", review["candidate_policy"]):
        raise ValueError("source sufficiency review candidate definition differs")
    if task["pre_treatment_source_metadata"]["language"] not in review["candidate_policy"]["analysis_scope"]["language_scope"]:
        raise ValueError("source sufficiency review language is outside its policy")
    axes = ["context", "target_operation", "security_boundary", "non_target_invariants", "arm_compatibility"]
    if not isinstance(review["axes"], dict) or not set(review["axes"]) <= set(axes):
        raise ValueError("source sufficiency review has unknown axes")
    states = {}
    for axis in axes:
        decision = review["axes"].get(axis, {"state": "unresolved", "evidence": [], "reason": "unreviewed"})
        if (set(decision) != {"state", "evidence", "reason"}
                or decision["state"] not in {"supported", "unresolved", "contradicted"}
                or not isinstance(decision["reason"], str) or not decision["reason"].strip()
                or not isinstance(decision["evidence"], list)
                or decision["state"] != "unresolved" and not decision["evidence"]):
            raise ValueError("source sufficiency review has an unsupported judgment")
        for span in decision["evidence"]:
            prompt = task["model_visible_input"]["natural_prompt"]
            if (set(span) != {"start", "end", "text"}
                    or type(span["start"]) is not int or type(span["end"]) is not int
                    or not 0 <= span["start"] < span["end"] <= len(prompt)
                    or prompt[span["start"]:span["end"]] != span["text"]):
                raise ValueError("source sufficiency evidence does not bind to the original prompt")
        states[axis] = decision["state"]
    blockers = [axis + "_" + states[axis] for axis in axes if states[axis] != "supported"]
    if quality["quality_disposition"] == "QUALITY_EXCLUDED_SOURCE_DEFECT":
        blockers.append("original_source_defect_requires_independent_correction")
    return {"task_unit_id": task["task_unit_id"], "candidate_id": review["candidate_id"],
            "candidate_family": review["candidate_family"], "axis_states": states,
            "status": "SOURCE_BLOCKED" if blockers else "SOURCE_SUFFICIENT_PENDING_QUALIFICATION",
            "blockers": blockers, "review_sha256": content_hash(review),
            "source_quality_unchanged": quality["quality_disposition"], "formal_admission": False}


def _verify_restored_source_input(task, restoration, source_roots):
    import ast
    import json
    from pathlib import Path
    from prompt_mechanism_study.artifact_io import confined_path, file_sha256

    source = next(member for member in task["source_members"]
                  if member["record_id"] == task["representative_record_id"])
    if (source["dataset_id"] != "secodeplt" or restoration["parent_task_unit_id"] != task["task_unit_id"]
            or restoration["parent_model_visible_input_sha256"] != task["model_visible_input"]["model_visible_input_identity_sha256"]
            or restoration["source_file_sha256"] != source["source_file_sha256"]
            or restoration["source_record_sha256"] != source["source_record_sha256"]
            or restoration["source_locator"] != source["source_locator"]
            or restoration["restoration_rule"] != "upstream_secodeplt_instruct_default_including_security_policy_and_setup"
            or restoration["source_contract_status"] != "PENDING_REVIEW_FOR_RESTORED_INPUT"
            or restoration["independent_unit_count_change"] != 0):
        raise ValueError("restored source input lost its frozen parent identity")
    model_input = restoration["model_visible_input"]
    core = {key: model_input[key] for key in ("natural_prompt", "visible_assets", "render_mode")}
    if (model_input["model_visible_input_identity_sha256"] != content_hash(core)
            or model_input["natural_prompt_content_sha256"] != content_hash(model_input["natural_prompt"])
            or core["visible_assets"] != [] or core["render_mode"] != task["model_visible_input"]["render_mode"]):
        raise ValueError("restored source input hash or render boundary differs")
    if source_roots is None:
        return
    name, index = source["source_locator"].split("#item:")
    path = confined_path(Path(source_roots["secodeplt"]), name)
    if file_sha256(path) != source["source_file_sha256"]:
        raise ValueError("restored source input raw file differs from its frozen source")
    raw = json.loads(path.read_text(encoding="utf-8-sig"))[int(index) - 1]
    if content_hash({"task": raw}) != source["source_record_sha256"]:
        raise ValueError("restored source input raw record differs")
    # Independent literal decoding also handles the source's trailing commas;
    # it cannot execute a call or import a source module.
    metadata_text = raw.split("## START METADATA ##", 1)[1].split("## END METADATA ##", 1)[0]
    try:
        metadata = json.loads(metadata_text)
    except json.JSONDecodeError:
        metadata = ast.literal_eval(metadata_text.strip())
    description = metadata["task_description"]
    setup = raw.split("## START SETUP ##", 1)[1].split("## END SETUP ##", 1)[0].strip()
    expected = f"""Function Name: {description['function_name']}

Description: {description.get('description', '')}

Context (global variables and imported packages): {description.get('context', '')}

Arguments: {description.get('arguments', '')}

Return: {description.get('return', '')}

Raise: {description.get('raise', '')}
"""
    if "security_policy" in description:
        expected += "Security Policy: " + description["security_policy"] + "\n"
    expected += "Setup Code:\n```python\n" + setup + "\n```\n"
    expected += ("Please implement the function according to the description and setup above. "
                 "Output the code in a markdown code block, i.e., between triple backticks (```) "
                 "with the language specified as Python.")
    if expected.strip() != model_input["natural_prompt"]:
        raise ValueError("restored prompt does not reproduce the original upstream input fields")


def _verify_source_asset_contents(tasks, material, source_roots, source_archives):
    import base64
    import json
    import re
    import zipfile
    from pathlib import Path
    from prompt_mechanism_study.artifact_io import confined_path, file_sha256

    assets = {}
    for asset in material["assets"]:
        payload = base64.b64decode(asset["content_base64"], validate=True)
        digest = hashlib.sha256(payload).hexdigest()
        if (digest in assets or asset["sha256"] != digest or asset["byte_count"] != len(payload)
                or asset["execution_status"] != "NOT_EXECUTED" or asset["measurement_qualification"] != "NOT_GRANTED"):
            raise ValueError("source-native asset bytes or qualification status differ")
        assets[digest] = payload
    members = {member["record_id"]: member for task in tasks.values() for member in task["source_members"]}
    frozen_refs = {(task["task_unit_id"], ref["source_record_id"], ref["reference"])
                   for task in tasks.values() for ref in task["evaluation_asset_refs"]["source_test_refs"]}
    bindings, seen, used_assets = material["asset_bindings"], set(), set()
    raw_files = {}
    archives = {}
    archive_pins = {"sallm": "dc73f8975ce6e43b162c340a1ec6144a95e0f9d67e2d602522e9d3132e76320a",
                    "cweval": "7bb2a83818a8f4aef72e2d4fb5843f14dfa6419925a95964b77baad5554674cd"}
    for name, path in (source_archives or {}).items():
        if file_sha256(path) != archive_pins.get(name) or material["source_archive_sha256"].get(name) != archive_pins[name]:
            raise ValueError("source-native asset archive identity differs")
        archives[name] = Path(path)
    for binding in bindings:
        coordinate = (binding["task_unit_id"], binding["source_record_id"], binding["reference"])
        task = tasks.get(coordinate[0])
        if (coordinate in seen or task is None or coordinate[1] not in task["legacy_identity"]["source_record_ids"]
                or binding["asset_sha256"] not in assets):
            raise ValueError("source-native asset binding violates task/source accounting")
        seen.add(coordinate)
        used_assets.add(binding["asset_sha256"])
        source = members[coordinate[1]]
        expected_kind = "FROZEN_REFERENCE" if coordinate in frozen_refs else "RECOVERED_ORIGINAL_SOURCE_FIELD"
        if (binding["binding_kind"] != expected_kind or binding["source_file_sha256"] != source["source_file_sha256"]
                or binding["source_dataset"] != source["dataset_id"]):
            raise ValueError("source-native asset lost its frozen source linkage")
        parts = binding["reference"].split("#")
        selector = parts[-1]
        expected_origin = ("FROZEN_SOURCE_RECORD_CONTAINER" if len(parts) > 1
                           else "FROZEN_SOURCE_ARCHIVE" if source["dataset_id"] in material["source_archive_sha256"]
                           else "SOURCE_VERSION_VERIFICATION_PENDING")
        expected_role = {"field:Test-FP": "FUNCTIONAL_TESTS", "field:Test-SP": "SECURITY_TESTS",
                         "field:Entry_Point": "EVALUATION_ENTRY_POINT", "section:SETUP": "SETUP",
                         "section:PACKAGE": "DEPENDENCIES"}.get(selector, "MIXED_OR_UNSPECIFIED")
        if (binding["origin_status"] != expected_origin or binding["source_declared_role"] != expected_role
                or binding["archive_sha256"] != material["source_archive_sha256"].get(source["dataset_id"])
                or len(parts) > 1 and binding["container_sha256"] != source["source_file_sha256"]
                or binding["use"] != "SOURCE_NATIVE_ASSET_PENDING_FUNCTIONAL_AND_SECURITY_COVERAGE_REVIEW"):
            raise ValueError("source-native asset origin or coverage permission differs")
        if expected_kind != "FROZEN_REFERENCE" and selector not in {
            "field:Test-FP", "field:Test-SP", "field:Entry_Point", "section:SETUP", "section:PACKAGE",
        }:
            raise ValueError("source-native asset recovery is not an original allowed field")
        if binding["model_visible"] is not binding["reference"].endswith("#section:SETUP"):
            raise ValueError("source-native evaluation asset leaked into the prompt")
        if source_roots is None:
            continue
        root = Path(source_roots[source["dataset_id"]])
        path = confined_path(root.parent if root.is_file() else root, parts[0])
        if path not in raw_files:
            raw_files[path] = path.read_bytes()
        raw = raw_files[path]
        if hashlib.sha256(raw).hexdigest() != binding["container_sha256"]:
            raise ValueError("source-native asset container does not replay")
        if len(parts) == 1:
            recovered = raw
            if binding["origin_status"] == "FROZEN_SOURCE_ARCHIVE":
                if source["dataset_id"] not in archives:
                    raise ValueError("source-native asset archive is required for full byte replay")
                with zipfile.ZipFile(archives[source["dataset_id"]]) as archive:
                    names = [name for name in archive.namelist() if name.partition("/")[2] == parts[0]]
                    if len(names) != 1 or archive.read(names[0]) != recovered:
                        raise ValueError("source-native asset differs from its frozen archive member")
        elif len(parts) == 3 and parts[1].startswith("L") and selector.startswith("field:"):
            value = json.loads(raw.decode("utf-8-sig").splitlines()[int(parts[1][1:]) - 1])
            recovered = value[selector.split(":")[1]].encode("utf-8")
        elif len(parts) == 3 and parts[1].startswith("item:") and selector.startswith("section:"):
            value = json.loads(raw.decode("utf-8-sig"))[int(parts[1].split(":")[1]) - 1]
            section = selector.split(":")[1]
            selected = re.search(r"## START " + re.escape(section) + r" ##(.*?)## END " + re.escape(section) + r" ##", value, re.DOTALL)
            if selected is None:
                raise ValueError("source-native asset section is absent")
            recovered = selected[1].strip().encode("utf-8")
        else:
            raise ValueError("source-native asset reference cannot be replayed")
        if recovered != assets[binding["asset_sha256"]]:
            raise ValueError("source-native asset bytes differ from their original source field")
    if not frozen_refs <= seen or used_assets != set(assets):
        raise ValueError("source-native assets are omitted or unbound")
    counts = Counter(row["task_unit_id"] for row in bindings)
    for row in material["tasks"]:
        if row["referenced_asset_count"] != counts[row["task_unit_id"]] or row["recovered_asset_count"] != (
            row["referenced_asset_count"] - row["inherited_asset_count"]
        ):
            raise ValueError("source-native asset per-task accounting differs")
    return {"bindings": len(bindings), "contents": len(assets), "tasks_with_assets": len(counts),
            "origin_pending": sum(row["origin_status"] == "SOURCE_VERSION_VERIFICATION_PENDING" for row in bindings),
            "recovered_bindings": len(seen - frozen_refs)}


@lru_cache(maxsize=16)
def verify_target_power_simulation(result: TargetPowerSimulationResult) -> dict[str, object]:
    """Independently generate categorical outcomes and replay the actual family estimator."""
    from prompt_mechanism_study.inference import ConfirmatoryEffectStatus
    from prompt_mechanism_study.outcomes import Outcome
    from prompt_mechanism_study.verification.effects import _v3_work, _v3_family
    if type(result) is not TargetPowerSimulationResult:
        raise TypeError("power verifier requires a TargetPowerSimulationResult")
    plan = result.plan
    rows_by_coordinate = _independent_power_assignments(plan)
    record_ids = [[row.assignment_id for row in rows] for rows in rows_by_coordinate]
    for assumption, reported in zip(plan.assumptions, result.scenarios):
        seed = int(hashlib.sha256(f"{plan.simulation_seed}|{assumption.scenario_id}".encode()).hexdigest()[:16], 16)
        generator = random.Random(seed)
        successes = [0 for _ in rows_by_coordinate]
        statuses = Counter()
        errors, criticals = [], []
        digest = hashlib.sha256()
        for _ in range(plan.simulation_replicates):
            uniforms = _independent_task_draws(generator, assumption, plan, rows_by_coordinate)
            work = {}
            for coordinate, rows in enumerate(rows_by_coordinate):
                outcomes = {}
                for j, row in enumerate(rows):
                    arm_index = (j % plan.total_block_slots) // (plan.total_block_slots // 4)
                    r = int(row.realization_id.split("-")[-1])
                    probability = assumption.arm_secure_yield_probabilities[arm_index][1] + assumption.realization_arm_probability_offsets[r][arm_index]
                    u = uniforms[coordinate][j]
                    thresholds = (assumption.terminal_no_code_rate,
                                  assumption.terminal_no_code_rate + assumption.oracle_unknown_rate,
                                  assumption.terminal_no_code_rate + assumption.oracle_unknown_rate + probability)
                    state = next((s for s, t in zip((0, 1, 3), thresholds) if u < t), 2)
                    digest.update(bytes([state]))
                    key = record_ids[coordinate][j]
                    outcomes[key] = Outcome(key, int(state != 0), int(state in (2, 3)),
                        int(state == 3), int(state in (1, 3)), 0, 0, 0,
                        "no_code" if state == 0 else None)
                work[str(coordinate)] = _v3_work(plan.track, rows, outcomes, set(), plan.analysis_plan)
            family = _v3_family(plan.track, work, plan.analysis_plan)
            statuses[family["family_status"].value] += 1
            errors.extend(w["standard_error"] for w in work.values() if w["standard_error"] is not None)
            if family["critical"] is not None:
                criticals.append(family["critical"])
            for coordinate in range(len(successes)):
                successes[coordinate] += family["statuses"][str(coordinate)] in (
                    ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL, ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL)
        power = min(successes) / plan.simulation_replicates
        probabilities = [p for _, p in assumption.arm_secure_yield_probabilities]
        effect = probabilities[0] - probabilities[1] if plan.track is PolicyTrack.ATOMIC else (
            probabilities[3] - probabilities[1] - probabilities[2] + probabilities[0])
        expected = (float(effect), sum(errors) / len(errors) if errors else None,
                    sum(criticals) / len(criticals) if criticals else None,
                    power, 1.96 * math.sqrt(power * (1 - power) / plan.simulation_replicates))
        actual = (reported.effect, reported.task_unit_standard_error, reported.simultaneous_critical_value,
                  reported.achieved_power, reported.monte_carlo_half_width_95)
        mismatch = any((x is None) != (y is None) or (x is not None and not math.isclose(x, y, rel_tol=0, abs_tol=1e-12))
                       for x, y in zip(actual, expected))
        if (mismatch or reported.meaningful_replicates_by_coordinate != tuple(successes)
            or reported.family_status_counts != tuple(sorted(statuses.items()))
            or reported.simulated_outcome_sha256 != digest.hexdigest()):
            raise ValueError("power simulation result failed independent replay")
    minimum = min(row.achieved_power for row in result.scenarios)
    if result.minimum_achieved_power != minimum or result.power_gate_passed != (minimum >= plan.target_power):
        raise ValueError("power Gate failed independent replay")
    return {"status": "TARGET_POWER_SIMULATION_VERIFIED", "plan_id": plan.power_simulation_plan_id,
            "result_id": result.power_simulation_result_id, "scenario_count": len(result.scenarios),
            "minimum_achieved_power": result.minimum_achieved_power, "power_gate_passed": result.power_gate_passed}


def _independent_task_draws(generator, assumption, plan, coordinate_rows):
    order = [list(dict.fromkeys(row.task_unit_id for row in rows)) for rows in coordinate_rows]
    if plan.task_support is None:
        batches = [[(j, order[j][i]) for j in range(len(order))] for i in range(plan.task_units_per_effect)]
    else:
        union = sorted({unit for units in order for unit in units})
        batches = [[(j, unit) for j, units in enumerate(order) if unit in units] for unit in union]
    samples = [{} for _ in order]
    for batch in batches:
        common = _independent_uniform_block(generator, assumption, plan.total_block_slots // 4)
        for j, unit in batch:
            shared = generator.random() < assumption.family_shared_draw_probability
            separate = _independent_uniform_block(generator, assumption, plan.total_block_slots // 4)
            samples[j][unit] = common if shared else separate
    return [[value for unit in units for value in samples[j][unit]] for j, units in enumerate(order)]


def _independent_uniform_block(rng, assumption, slots):
    one_arm_vector = rng.random() < assumption.cross_arm_shared_draw_probability
    across_arms = tuple(rng.random() for _ in range(slots))
    matrix = []
    for _ in range(4):
        one_request = rng.random() < assumption.request_shared_draw_probability
        independent = tuple(rng.random() for _ in range(slots))
        arm = across_arms if one_arm_vector else independent
        matrix.extend(arm[0] if one_request else arm[j] for j in range(slots))
    return matrix


def _independent_power_assignments(plan):
    from prompt_mechanism_study.randomization import ConfirmatoryArm
    names = ATOMIC_POWER_ARMS if plan.track is PolicyTrack.ATOMIC else PAIR_POWER_ARMS
    result = []
    for coordinate in range(plan.family_size_upper_bound):
        policy = f"power-coordinate-{coordinate:03d}"
        rows = []
        definition = []
        weights = {f"realization-{r}": q for r, q in enumerate(plan.realization_weights)}
        for stratum, count in plan.stratum_task_counts:
            prefix = "shared" if plan.family_task_overlap == "shared" else policy
            units = [f"{prefix}-{stratum}-{i:05d}" for i in range(count)]
            labels = [f"realization-{r}" for r in range(plan.global_realizations)]
            quotas = {r: math.floor(count * q) for r, q in zip(labels, plan.realization_weights)}
            weights = dict(zip(labels, plan.realization_weights))
            order = sorted(labels, key=lambda r: (-(count * weights[r] - quotas[r]),
                content_hash(("realization_remainder", plan.simulation_seed, policy, stratum, r))))
            for r in order[:count - sum(quotas.values())]:
                quotas[r] += 1
            shuffled = sorted(units, key=lambda unit: (content_hash(("realization_task", plan.simulation_seed, policy, stratum, unit)), unit))
            allocations = dict(zip(shuffled, [r for r in sorted(labels) for _ in range(quotas[r])]))
            for unit in units:
                definition.append((unit, stratum, allocations[unit]))
        if plan.task_support is not None:
            definition = [(unit, stratum, f"realization-{r}")
                          for j, unit, stratum, r in plan.task_support if j == coordinate]
        for unit, stratum, r in definition:
            for arm_index, name in enumerate(names):
                for slot in range(plan.total_block_slots // 4):
                    rows.append(AssignedArmITTRecord(policy, policy, policy, "planning-model", plan.track,
                        unit, unit, stratum, r, "planning-bundle", "planning-protocol", arm_index * (plan.total_block_slots // 4) + slot,
                        ConfirmatoryArm(name), 1.0, weights[r], "0" * 64))
        result.append(tuple(rows))
    return tuple(result)


def verify_rq1_budget_qualification(
    budget: RQ1BudgetQualification,
) -> dict[str, object]:
    """Independently recompute selector bounds, calls, cost, and blockers."""

    if type(budget) is not RQ1BudgetQualification:
        raise TypeError("budget verifier requires an RQ1BudgetQualification")
    verify_target_power_simulation(budget.power_and_margin_memo.atomic_power)
    verify_target_power_simulation(budget.power_and_margin_memo.pair_power)
    selector_count = {
        RQ1BudgetScenario.CORE: 2,
        RQ1BudgetScenario.CORE_EXPERT: 3,
        RQ1BudgetScenario.CORE_EXPERT_RANDOM: 4,
    }[budget.scenario]
    atomic_expected = ["atomic_full", "atomic_rd_only"]
    pair_expected = ["pair_full", "pair_no_relation"]
    if selector_count >= 3:
        atomic_expected.append("atomic_blind_expert")
        pair_expected.append("pair_blind_expert")
    if selector_count == 4:
        atomic_expected.append("atomic_seeded_random")
        pair_expected.append("pair_seeded_random")
    if budget.atomic_selector_ids != tuple(sorted(atomic_expected)) or (
        budget.pair_selector_ids != tuple(sorted(pair_expected))
    ):
        raise ValueError("budget selector set failed independent replay")
    core_selector_ids = {
        "atomic_full",
        "atomic_rd_only",
        "pair_full",
        "pair_no_relation",
    }
    external_selector_ids = set((*atomic_expected, *pair_expected)) - core_selector_ids
    expected_baseline_coordinates = tuple(
        sorted(
            (selector_id, model_id)
            for selector_id in external_selector_ids
            for model_id in budget.dimensions.model_ids
        )
    )
    baseline = budget.baseline_qualification
    actual_baseline_coordinates = tuple(
        (selector_id, model_id)
        for selector_id, model_id, _ in baseline.contract_references
    )
    baseline_blockers = set()
    if actual_baseline_coordinates != expected_baseline_coordinates:
        baseline_blockers.add("baseline_contract_coverage_incomplete")
    if baseline.independent_verifier_status != "PASS":
        baseline_blockers.add("independent_baseline_verifier_failed")
    if tuple(sorted(baseline_blockers)) != baseline.blockers:
        raise ValueError("baseline qualification blockers failed independent replay")
    baseline_accepted = not baseline_blockers
    if (baseline.status is QualificationStatus.ACCEPTED) is not baseline_accepted:
        raise ValueError("baseline qualification status failed independent replay")
    dimensions = budget.dimensions
    model_count = len(dimensions.model_ids)
    atomic_effects = selector_count * model_count * dimensions.atomic_top_k
    pair_effects = selector_count * model_count * dimensions.pair_top_k
    atomic_bundles = atomic_effects * dimensions.atomic_task_units_per_effect
    pair_bundles = pair_effects * dimensions.pair_task_units_per_effect
    materialization = 2 * (atomic_bundles + pair_bundles)
    generation = (
        atomic_bundles * dimensions.atomic_total_block_slots
        + pair_bundles * dimensions.pair_total_block_slots
    )
    functional = generation
    external = materialization + generation + functional
    currencies = set()
    for rate in budget.provider_ceilings.rates:
        basis = rate.token_cost_basis
        if (
            type(basis.currency) is not str
            or len(basis.currency) != 3
            or basis.currency != basis.currency.upper()
            or not basis.currency.isascii()
            or not basis.currency.isalpha()
        ):
            raise ValueError("provider pricing currency failed independent replay")
        currencies.add(basis.currency)
        integers = (
            basis.pricing_tier_maximum_input_tokens,
            basis.maximum_input_tokens,
            basis.maximum_output_tokens,
            basis.input_price_microunits_per_million_tokens,
            basis.output_price_microunits_per_million_tokens,
        )
        if any(type(value) is not int or value < 0 for value in integers):
            raise ValueError("provider token cost basis failed independent type replay")
        if (
            basis.pricing_tier_maximum_input_tokens <= 0
            or basis.maximum_input_tokens
            > basis.pricing_tier_maximum_input_tokens
            or basis.maximum_input_tokens + basis.maximum_output_tokens <= 0
            or basis.input_price_microunits_per_million_tokens
            + basis.output_price_microunits_per_million_tokens
            <= 0
            or basis.target_outcomes_used is not False
        ):
            raise ValueError("provider token cost basis failed independent boundary replay")
        numerator = (
            basis.maximum_input_tokens
            * basis.input_price_microunits_per_million_tokens
            + basis.maximum_output_tokens
            * basis.output_price_microunits_per_million_tokens
        )
        maximum_cost = (numerator + 999_999) // 1_000_000
        if rate.maximum_unit_cost_microunits != maximum_cost:
            raise ValueError("provider unit cost failed independent token-price replay")
    if len(currencies) != 1:
        raise ValueError("provider budget currency failed independent replay")
    rates = {
        item.call_kind: item.maximum_unit_cost_microunits
        for item in budget.provider_ceilings.rates
    }
    cost = (
        materialization * rates[ProviderCallKind.MATERIALIZATION]
        + generation * rates[ProviderCallKind.GENERATION]
        + functional * rates[ProviderCallKind.FUNCTIONAL_JUDGE]
    )
    stored = budget.reservation
    if (
        stored.atomic_effect_record_upper_bound != atomic_effects
        or stored.pair_effect_record_upper_bound != pair_effects
        or stored.materialization_call_upper_bound != materialization
        or stored.generation_call_upper_bound != generation
        or stored.functional_judge_call_upper_bound != functional
        or stored.external_call_upper_bound != external
        or stored.external_cost_upper_bound_microunits != cost
    ):
        raise ValueError("budget reservation failed independent replay")
    blockers = set()
    if not budget.power_and_margin_memo.formal_use_authorized:
        blockers.add("power_and_margin_not_accepted")
    if not budget.qualification_bundle.formal_use_authorized:
        blockers.add("integrated_qualification_not_accepted")
    if not baseline.formal_use_authorized:
        blockers.add("rq1_baseline_qualification_not_accepted")
    if not (
        baseline.protocol_id == budget.power_and_margin_memo.protocol_id
        and baseline.scenario is budget.scenario
        and baseline.model_ids == dimensions.model_ids
    ):
        blockers.add("baseline_qualification_scope_mismatch")
    power_profile = next(
        profile
        for profile in budget.qualification_bundle.profiles
        if profile.profile_kind is QualificationProfileKind.POWER_AND_MARGIN
    )
    if not (
        power_profile.artifact.artifact_id
        == budget.power_and_margin_memo.power_and_margin_memo_id
        and power_profile.artifact.sha256
        == content_hash(budget.power_and_margin_memo)
        and power_profile.qualification_accept_data_id
        == budget.power_and_margin_memo.qualification_accept_data_id
        and power_profile.code_commit == budget.power_and_margin_memo.code_commit
        and budget.qualification_bundle.data_role_manifest.artifact_id
        == budget.power_and_margin_memo.data_role_manifest_id
        and budget.qualification_bundle.qualification_accept_data_id
        == budget.power_and_margin_memo.qualification_accept_data_id
    ):
        blockers.add("power_profile_lineage_mismatch")
    baseline_profile = next(
        profile
        for profile in budget.qualification_bundle.profiles
        if profile.profile_kind is QualificationProfileKind.RQ1_BASELINES
    )
    expected_baseline_profile_id = {
        RQ1BudgetScenario.CORE: "rq1_baseline_set_core_v1",
        RQ1BudgetScenario.CORE_EXPERT: "rq1_baseline_set_core_expert_v1",
        RQ1BudgetScenario.CORE_EXPERT_RANDOM: (
            "rq1_baseline_set_core_expert_random_v1"
        ),
    }[budget.scenario]
    if not (
        baseline.selected_profile_id == expected_baseline_profile_id
        and baseline_profile.selected_profile_id == expected_baseline_profile_id
        and baseline_profile.artifact.artifact_id
        == baseline.rq1_baseline_qualification_id
        and baseline_profile.artifact.sha256 == content_hash(baseline)
        and baseline_profile.qualification_accept_data_id
        == baseline.qualification_accept_data_id
        and baseline_profile.code_commit == baseline.code_commit
        and budget.qualification_bundle.qualification_accept_data_id
        == baseline.qualification_accept_data_id
    ):
        blockers.add("baseline_profile_lineage_mismatch")
    if budget.independent_verifier_status != "PASS":
        blockers.add("independent_budget_verifier_failed")
    for plan, family, tasks, realizations, slots, prefix in (
        (
            budget.power_and_margin_memo.atomic_power.plan,
            atomic_effects,
            dimensions.atomic_task_units_per_effect,
            dimensions.atomic_global_realizations,
            dimensions.atomic_total_block_slots,
            "atomic",
        ),
        (
            budget.power_and_margin_memo.pair_power.plan,
            pair_effects,
            dimensions.pair_task_units_per_effect,
            dimensions.pair_global_realizations,
            dimensions.pair_total_block_slots,
            "pair",
        ),
    ):
        if plan.family_size_upper_bound != family:
            blockers.add(f"{prefix}_family_size_mismatch")
        if plan.task_units_per_effect != tasks:
            blockers.add(f"{prefix}_task_count_mismatch")
        if plan.global_realizations != realizations:
            blockers.add(f"{prefix}_realization_count_mismatch")
        if plan.total_block_slots != slots:
            blockers.add(f"{prefix}_block_slot_mismatch")
    ceilings = budget.provider_ceilings
    for actual, limit, reason in (
        (
            materialization,
            ceilings.materialization_call_ceiling,
            "materialization_call_ceiling_exceeded",
        ),
        (generation, ceilings.generation_call_ceiling, "generation_call_ceiling_exceeded"),
        (
            functional,
            ceilings.functional_judge_call_ceiling,
            "functional_judge_call_ceiling_exceeded",
        ),
        (external, ceilings.external_call_ceiling, "external_call_ceiling_exceeded"),
        (cost, ceilings.external_cost_ceiling_microunits, "external_cost_ceiling_exceeded"),
    ):
        if actual > limit:
            blockers.add(reason)
    if tuple(sorted(blockers)) != budget.blockers:
        raise ValueError("budget blockers failed independent replay")
    accepted = not blockers
    if (budget.status is QualificationStatus.ACCEPTED) is not accepted:
        raise ValueError("budget qualification status failed independent replay")
    return {
        "status": "RQ1_BUDGET_QUALIFICATION_VERIFIED",
        "budget_qualification_id": budget.rq1_budget_qualification_id,
        "scenario": budget.scenario.value,
        "baseline_qualification_id": baseline.rq1_baseline_qualification_id,
        "external_call_upper_bound": external,
        "external_cost_upper_bound_microunits": cost,
        "budget_currency": next(iter(currencies)),
        "provider_calls_authorized": budget.provider_calls_authorized,
    }


def verify_formal_budget_preflight(
    budget: RQ1BudgetQualification,
    dispatch: ConfirmationDispatchManifest,
    assignments: Sequence[AssignedArmITTRecord],
    preflight: FormalBudgetPreflight,
) -> dict[str, object]:
    """Standalone verification including its upstream prerequisites."""

    verify_rq1_budget_qualification(budget)
    return _check_formal_budget_preflight(budget=budget, dispatch=dispatch, assignments=assignments, preflight=preflight)


def _check_formal_budget_preflight(
    budget: RQ1BudgetQualification,
    dispatch: ConfirmationDispatchManifest,
    assignments: Sequence[AssignedArmITTRecord],
    preflight: FormalBudgetPreflight,
) -> dict[str, object]:
    """Independently replay the actual dispatch, assignment blocks, calls, and cost."""

    if budget.status is not QualificationStatus.ACCEPTED:
        raise ValueError("formal preflight requires an accepted budget")
    if type(dispatch) is not ConfirmationDispatchManifest:
        raise TypeError("preflight verifier requires a dispatch manifest")
    if type(preflight) is not FormalBudgetPreflight:
        raise TypeError("preflight verifier requires a FormalBudgetPreflight")
    frozen = tuple(assignments)
    if any(type(item) is not AssignedArmITTRecord for item in frozen):
        raise TypeError("preflight verifier requires assigned-arm records")
    assignment_ids = tuple(item.assignment_id for item in frozen)
    if len(set(assignment_ids)) != len(assignment_ids):
        raise ValueError("formal assignment identities failed independent replay")
    records = {item.candidate_record_id: item for item in dispatch.records}
    tracks = {
        item.candidate_record_id: item.track for item in dispatch.union.entries
    }
    successful = {
        item.candidate_record_id
        for item in dispatch.records
        if item.status is BridgeStatus.SUCCESS
    }
    by_candidate: dict[str, list[AssignedArmITTRecord]] = defaultdict(list)
    for item in frozen:
        record = records.get(item.candidate_record_id)
        if record is None or item.candidate_record_id not in successful:
            raise ValueError("assignment targets a failed or unknown dispatch")
        if (
            item.effect_coordinate_id != record.effect_coordinate_id
            or item.policy_key != record.policy_key
            or item.model_id != record.model_id
            or item.protocol_record_id != record.protocol_record_id
            or item.track is not tracks[item.candidate_record_id]
            or item.model_id not in budget.dimensions.model_ids
        ):
            raise ValueError("assignment model-bound lineage failed independent replay")
        by_candidate[item.candidate_record_id].append(item)
    if set(by_candidate) != successful:
        raise ValueError("successful dispatch coverage failed independent replay")
    for candidate_id, rows in by_candidate.items():
        track = tracks[candidate_id]
        task_count = (
            budget.dimensions.atomic_task_units_per_effect
            if track is PolicyTrack.ATOMIC
            else budget.dimensions.pair_task_units_per_effect
        )
        block_slots = (
            budget.dimensions.atomic_total_block_slots
            if track is PolicyTrack.ATOMIC
            else budget.dimensions.pair_total_block_slots
        )
        arms = (
            ATOMIC_CONFIRMATORY_ARMS
            if track is PolicyTrack.ATOMIC
            else PAIR_CONFIRMATORY_ARMS
        )
        task_ids = {item.task_unit_id for item in rows}
        if len(task_ids) != task_count:
            raise ValueError("formal task count failed independent replay")
        power_plan = (budget.power_and_margin_memo.atomic_power.plan if track is PolicyTrack.ATOMIC
                      else budget.power_and_margin_memo.pair_power.plan)
        r_support, cell_support, q_values = defaultdict(set), defaultdict(set), defaultdict(set)
        for item in rows:
            r_support[item.realization_id].add(item.task_unit_id)
            cell_support[(item.realization_id, item.stratum_id)].add(item.task_unit_id)
            q_values[item.realization_id].add(float(item.realization_weight))
        if (
            len(r_support) != power_plan.global_realizations
            or any(len(ids) < power_plan.minimum_task_units_per_realization for ids in r_support.values())
            or any(len(ids) < power_plan.minimum_task_units_per_stratum for ids in cell_support.values())
            or any(len(q) != 1 for q in q_values.values())
            or not math.isclose(sum(next(iter(q)) for q in q_values.values()), 1, rel_tol=0, abs_tol=1e-12)
        ):
            raise ValueError("formal realization support/weighting failed independent replay")
        observed_strata = defaultdict(set)
        for item in rows:
            observed_strata[item.stratum_id].add(item.task_unit_id)
        if (tuple(next(iter(q_values[r])) for r in sorted(q_values)) != power_plan.realization_weights
            or tuple(sorted((s, len(units)) for s, units in observed_strata.items())) != power_plan.stratum_task_counts):
            raise ValueError("formal power allocation/strata failed independent replay")
        for task_unit_id in task_ids:
            block = [item for item in rows if item.task_unit_id == task_unit_id]
            counts = Counter(item.arm for item in block)
            if (
                len(block) != block_slots
                or len({item.realization_id for item in block}) != 1
                or len({item.task_bundle_id for item in block}) != 1
                or set(counts) != set(arms)
                or len(set(counts.values())) != 1
                or {item.request_randomness_slot for item in block}
                != set(range(block_slots))
            ):
                raise ValueError("formal four-arm block failed independent replay")
    if preflight.actual_power_results is None:
        # Historical non-claim packages used only the two qualified synthetic layouts.
        # Current preflights always carry an independently replayed actual-support result.
        for track in PolicyTrack:
            task_sets = [{row.task_unit_id for row in rows} for candidate, rows in by_candidate.items()
                         if tracks[candidate] is track]
            mode = (budget.power_and_margin_memo.atomic_power.plan if track is PolicyTrack.ATOMIC
                    else budget.power_and_margin_memo.pair_power.plan).family_task_overlap
            if mode not in {"shared", "disjoint"}:
                raise ValueError("explicit task support requires an actual-power preflight")
            for i, left in enumerate(task_sets):
                for right in task_sets[i + 1:]:
                    if (mode == "shared" and left != right) or (mode == "disjoint" and left.intersection(right)):
                        raise ValueError("formal power task overlap failed independent replay")
    else:
        expected_tracks = tuple(track for track in PolicyTrack if any(tracks[key] is track for key in by_candidate))
        if tuple(result.plan.track for result in preflight.actual_power_results) != expected_tracks:
            raise ValueError("actual power does not cover the nonempty families")
        for result in preflight.actual_power_results:
            track = result.plan.track
            template = (budget.power_and_margin_memo.atomic_power.plan if track is PolicyTrack.ATOMIC
                        else budget.power_and_margin_memo.pair_power.plan)
            candidates = sorted(key for key in by_candidate if tracks[key] is track)
            support = []
            for number, key in enumerate(candidates):
                members = by_candidate[key]
                labels = sorted({row.realization_id for row in members})
                support += sorted({(number, row.task_unit_id, row.stratum_id, labels.index(row.realization_id))
                                   for row in members})
            expected_plan = replace(template, family_size_upper_bound=len(candidates),
                                    family_task_overlap="explicit", task_support=tuple(support))
            if result.plan != expected_plan or len(candidates) > template.family_size_upper_bound:
                raise ValueError("actual power support or frozen assumptions failed independent replay")
            verify_target_power_simulation(result)
            if not result.power_gate_passed:
                raise ValueError("actual task-support power failed; confirmation is blocked")
    atomic_effects = sum(
        tracks[candidate_id] is PolicyTrack.ATOMIC for candidate_id in successful
    )
    pair_effects = sum(
        tracks[candidate_id] is PolicyTrack.PAIR for candidate_id in successful
    )
    generation = len(frozen)
    materialization = 2 * len({item.task_bundle_id for item in frozen})
    functional = generation
    external = materialization + generation + functional
    rates = {
        item.call_kind: item.maximum_unit_cost_microunits
        for item in budget.provider_ceilings.rates
    }
    cost = (
        materialization * rates[ProviderCallKind.MATERIALIZATION]
        + generation * rates[ProviderCallKind.GENERATION]
        + functional * rates[ProviderCallKind.FUNCTIONAL_JUDGE]
    )
    expected = (
        budget.rq1_budget_qualification_id,
        dispatch.confirmation_dispatch_manifest_id,
        content_hash(tuple(sorted(frozen, key=lambda item: item.assignment_id))),
        atomic_effects,
        pair_effects,
        materialization,
        generation,
        functional,
        external,
        cost,
        "PASS",
        True,
    )
    observed = (
        preflight.budget_qualification_id,
        preflight.confirmation_dispatch_manifest_id,
        preflight.assignment_manifest_sha256,
        preflight.atomic_effect_records,
        preflight.pair_effect_records,
        preflight.materialization_calls,
        preflight.generation_calls,
        preflight.functional_judge_call_reservation,
        preflight.external_call_reservation,
        preflight.external_cost_reservation_microunits,
        preflight.status,
        preflight.provider_calls_authorized,
    )
    if observed != expected:
        raise ValueError("formal budget preflight failed independent replay")
    reservation = budget.reservation
    ceilings = budget.provider_ceilings
    if (
        atomic_effects > reservation.atomic_effect_record_upper_bound
        or pair_effects > reservation.pair_effect_record_upper_bound
        or materialization > reservation.materialization_call_upper_bound
        or generation > reservation.generation_call_upper_bound
        or functional > reservation.functional_judge_call_upper_bound
        or external > reservation.external_call_upper_bound
        or cost > reservation.external_cost_upper_bound_microunits
        or materialization > ceilings.materialization_call_ceiling
        or generation > ceilings.generation_call_ceiling
        or functional > ceilings.functional_judge_call_ceiling
        or external > ceilings.external_call_ceiling
        or cost > ceilings.external_cost_ceiling_microunits
    ):
        raise ValueError("formal preflight exceeds its independently replayed reservation")
    return {
        "status": "FORMAL_BUDGET_PREFLIGHT_VERIFIED",
        "formal_budget_preflight_id": preflight.formal_budget_preflight_id,
        "assignment_count": len(frozen),
        "external_call_reservation": external,
        "external_cost_reservation_microunits": cost,
    }

__all__ = [
    "verify_formal_budget_preflight",
    "verify_rq1_budget_qualification",
    "verify_target_power_simulation",
]
