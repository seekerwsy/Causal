"""Independent RQ-table and formal-claim authorization reconstruction."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
import ast
import itertools
import json
import math
import random

from prompt_mechanism_study.artifact_io import json_object, read_json_exact, read_json, verify_bundle, bundle_digest
from prompt_mechanism_study.functional_judge import (
    build_review_request, code_syntax_valid, syntax_parser_identity, validate_review_response,
)
from prompt_mechanism_study.measurement import Measurement

from prompt_mechanism_study.inference import (
    ConfirmatoryEffectStatus,
    EvidenceLevel,
    SharedEvidenceRecord,
    TargetITTPlan,
    TargetSelectorYieldResult,
)
from prompt_mechanism_study.prioritization import (
    ConfirmationDispatchManifest,
    FixedSlotLedger,
    PolicyTrack,
    SharedConfirmationUnion,
    SlotStatus,
)
from prompt_mechanism_study.randomization import (
    AssignedArmITTRecord,
    TargetRandomizationPlan,
    TargetTaskBundle,
)
from prompt_mechanism_study.records import content_hash, content_id


def verify_development_result(root: Path) -> dict:
    """Independently replay a small development result from all frozen assignments.

    Does not call the production renderer, outcome assembler or effect estimator.
    Security labels are checked against their saved trace, not certified as truth.
    The bounded exact enumeration is appropriate for the exposed development sets.
    """
    verify_bundle(root / "preoutcome")
    verify_bundle(root / "summary")
    plan = read_json(root / "preoutcome/plan.json")
    assigned = read_json(root / "preoutcome/assignments.json")
    rows = read_json(root / "summary/assignments.json")
    report = read_json(root / "summary/report.json")
    effects = read_json(root / "summary/effects.json")
    def check(condition, message):
        if not condition:
            raise ValueError("development verification: " + message)
    check(plan["scientific_claim_allowed"] is False and report["scientific_claim_allowed"] is False,
          "development cannot authorize a scientific claim")
    check(report["plan_sha256"] == content_hash(plan), "plan identity")
    check(report["preoutcome_bundle_sha256"] == bundle_digest(root / "preoutcome"), "preoutcome identity")
    by_assignment = {row["assignment_id"]: row for row in rows}
    check(len(rows) == len(by_assignment) == len(assigned), "total assigned-arm accounting")
    tasks = {task["task_id"]: task for task in plan["tasks"]}
    # Independently reconstruct the evidence view; do not share the producer's
    # preparation or message-splitting helpers. Older frozen runs remain readable.
    prepared_prefixes = {}
    for task_id, task in tasks.items():
        if "generation_input" not in task:
            continue
        source = task["source_prompt"]
        language = task["language"]
        system = plan["generation_system_prompt"]
        request = {"language": language, "task": source.replace("<language>", language)}
        prefix = "System message:\n" + system + "\n\nUser message:\nLanguage: " + language + "\n\nTask:\n"
        baseline = prefix + request["task"]
        check(task["source_prompt_sha256"] == content_hash(source), "original source identity")
        check(task["generation_input"] == {"system_prompt": system, "request": request}, "prepared messages")
        check(task["prompt"] == baseline and task["prompt_sha256"] == content_hash(baseline), "baseline input evidence")
        check(task["graph"]["prompt_sha256"] == content_hash(baseline), "TSG and generation baseline differ")
        check(task["functional_contract"]["source_prompt_sha256"] == content_hash(baseline), "functional baseline differs")
        prepared_prefixes[task_id] = prefix
    policies = {policy["policy_id"]: policy for policy in plan["policies"]}
    seeds = set(plan["generation_seeds"])
    coordinates = {(row["task_id"], row["arm"], row["seed"]) for row in assigned}
    check(coordinates == set(itertools.product(tasks, plan["arms"], seeds)), "complete task/arm/seed blocks")
    provider_calls = 0
    for allocation in assigned:
        key = allocation["assignment_id"]
        check(key in by_assignment, "assigned outcome missing")
        row = by_assignment[key]
        check(all(row[field] == value for field, value in allocation.items()), "assignment metadata changed")
        core = {field: value for field, value in allocation.items() if field != "assignment_id"}
        check(key == content_id("development_assignment_", core), "assignment identity")
        task, policy = tasks[row["task_id"]], policies[row["policy_id"]]
        check(row["task_unit_id"] == task["task_unit_id"] and row["binding_id"] == task["binding_id"], "task unit or binding changed")
        if task.get("factor_scopes"):
            check(row.get("factor_scopes") == task["factor_scopes"], "assigned factor scope changed")
            prompt = _replay_scoped_development_prompt(task, policy, row["arm"], check)
        else:
            operation = next(node for node in task["graph"]["nodes"] if node["node_id"] == task["target_operation_node_id"])
            subject_id = task.get("target_subject_node_id")
            input_scope = ""
            if subject_id is not None:
                check(row.get("target_subject_node_id") == subject_id, "assigned subject changed")
                subject = next((node for node in task["graph"]["nodes"] if node["node_id"] == subject_id), None)
                check(subject is not None and subject["node_type"] == "data_object", "subject is not a source data object")
                check(any(edge["source_id"] == subject_id and edge["target_id"] == operation["node_id"]
                          and edge["edge_type"] == "used_by" for edge in task["graph"]["edges"]),
                      "subject does not supply the assigned operation")
                input_scope = "For the input described by " + json.dumps(
                    task["prompt"][subject["evidence_start"]:subject["evidence_end"]], ensure_ascii=False) + ": "
                definition = policy.get("factor_definition", {})
                check(definition.get("semantic_decisions") == [policy["feature_id"]]
                      and definition.get("atomicity_review") == "SOURCE_REVIEWED_SINGLE_REQUIREMENT",
                      "single-requirement review missing")
            prompt = task["prompt"]
            if row["arm"] != "BASELINE":
                text = policy["addition"] if row["arm"] == "TARGET" else task["control_texts"][row["arm"]]
                prompt += "\n\nFor the operation described by " + json.dumps(task["prompt"][operation["evidence_start"]:operation["evidence_end"]], ensure_ascii=False) + ":\n- " + input_scope + text
        check(row["prompt"] == prompt and row["prompt_sha256"] == content_hash(prompt), "rendered treatment or control changed")
        case = root / "cases" / key
        verify_bundle(case)
        check(read_json(case / "result.json") == row, "summary differs from per-assignment evidence")
        calls = read_json(case / "calls.json")
        provider_calls += len(calls)
        check(len(calls) == row["provider_calls"] and 1 <= len(calls) <= 2, "provider call accounting")
        if row["task_id"] in prepared_prefixes:
            prefix = prepared_prefixes[row["task_id"]]
            check(prompt.startswith(prefix), "common input context changed")
            check(calls[0]["request"] == {"language": task["language"], "task": prompt[len(prefix):]},
                  "actual provider input differs from the represented arm")
        else:
            check(calls[0]["request"]["task"] == prompt, "actual provider prompt changed")
        check(calls[0]["request"].get("language") == task["language"], "actual generation language changed")
        check(calls[0]["evaluator"] == {**plan["generator"], "seed": row["seed"]}, "actual generator identity or seed changed")
        check(calls[0]["system_prompt"] == plan["generation_system_prompt"], "actual generator system prompt changed")
        if len(calls) == 2:
            functional = calls[1]["request"]
            check(functional["functional_task"] == task["prompt"], "functional judge received a treated source")
            check(not {"arm", "model_id", "security_status", "policy_id"} & set(functional), "functional blindness")
            check(calls[1]["evaluator"] == plan["functional_evaluator"] and calls[1]["system_prompt"] == plan["functional_system_prompt"], "functional measurement policy changed")
        if row["error"] is not None:
            check(row["secure_code_yield"] is None and row["code_valid"] is None, "failed allocation silently imputed")
            continue
        raw = calls[0]["response"]
        generated = json.loads(raw)
        check(set(generated) == {"code"} and generated["code"] == row["code"], "generated code changed")
        try:
            ast.parse(row["code"])
            valid = int(bool(row["code"].strip()))
        except SyntaxError:
            valid = 0
        check(row["code_valid"] == valid, "code-validity outcome")
        check(row["measurement"]["generator_evidence_sha256"] == hashlib.sha256(raw.encode()).hexdigest(), "raw response hash")
        if valid:
            evidence = row["measurement_evidence"]
            states = {fact["state"] for fact in evidence["security"]["decision"]["trace"]["facts"]}
            security = "insecure" if "unsafe" in states else "unknown" if not states or "unresolved" in states else "secure"
            check(row["security_status"] == security == evidence["security"]["security_label"], "security trace aggregation")
            check(evidence["code"] == row["code"] and row["measurement"]["code_sha256"] == content_hash(row["code"]), "measured code identity")
            check(evidence["functional_response"] == calls[1].get("response"), "functional response changed")
            if evidence.get("functional_failure") is not None:
                check(evidence["functional_validated"] == {"status": "unknown", "reason": "functional_evaluator_failed", "failure": evidence["functional_failure"]}, "failed functional evaluator was relabelled")
                verdict = "unknown"
                if "response" in calls[1]:
                    try:
                        validate_review_response(calls[1]["response"].encode(), row["code"])
                    except ValueError:
                        pass
                    except RuntimeError:
                        pass
                    else:
                        raise ValueError("development verification: valid functional response marked as failure")
                else:
                    check("error" in calls[1], "functional failure lacks raw evidence")
            else:
                verdict = json.loads(calls[1]["response"])["verdict"]
            check(row["functionality_status"] == verdict, "functional verdict changed")
            check(calls[1]["request"]["program_lines"] == [{"line_number": n, "text": line} for n, line in enumerate(row["code"].splitlines(), 1)], "functional judge received different code")
            f = {"pass": 1, "fail": 0, "unknown": None}[verdict]
            secure = int(security == "secure")
            evaluable = int(security != "unknown")
            joint = 0 if f == 0 or security == "insecure" else None if f is None or security == "unknown" else 1
        else:
            secure, evaluable, f, joint = 0, 0, 0, 0
        check((row["secure_code_yield"], row["oracle_evaluable"], row["functionality"], row["joint"]) == (secure, evaluable, f, joint), "endpoint decomposition")
    check(report["provider_calls"] == provider_calls and report["assigned_rows"] == len(rows), "report accounting")
    check(report["failed_rows"] == sum(row["error"] is not None for row in rows), "failed rows hidden")
    check(len(effects) == len(plan["analysis"]["contrasts"]), "multiplicity family changed")
    probabilities = []
    for comparison, effect in zip(plan["analysis"]["contrasts"], effects, strict=True):
        policy = comparison["policy_id"]
        interaction = comparison.get("kind") == "pair_interaction"
        if interaction:
            weights = {"A11": 1, "A10": -1, "A01": -1, "A00": 1}
            label = "A11 - A10 - A01 + A00"
        else:
            left, right = comparison["treatment"], comparison["control"]
            weights, label = {left: 1, right: -1}, left + " - " + right
        local = [row for row in rows if row["policy_id"] == policy]
        units = sorted({row["task_unit_id"] for row in local})
        check(effect["policy_id"] == policy and effect["comparison"] == label and effect["task_units"] == len(units), "contrast or denominator changed")
        cell = [row for row in local if row["arm"] in weights]
        if not units or any(row["error"] is not None for row in cell):
            check(effect["effect"] is None and effect["p_value"] is None and not effect["development_signal"], "missing outcomes did not block their contrast")
            probabilities.append(1.0)
            continue
        check(len(units) <= 20, "exact development verifier is bounded to twenty units per contrast")
        differences = []
        for unit in units:
            means = {arm: sum(row["secure_code_yield"] for row in local if row["task_unit_id"] == unit and row["arm"] == arm) / len(seeds) for arm in weights}
            differences.append(sum(means[arm] * weight for arm, weight in weights.items()))
        observed = abs(sum(differences))
        p = sum(abs(sum(sign * value for sign, value in zip(signs, differences))) >= observed - 1e-12
                for signs in itertools.product((-1, 1), repeat=len(units))) / 2 ** len(units)
        probabilities.append(1.0 if interaction else p)
        check(abs(effect["effect"] - sum(differences) / len(units)) < 1e-12, "task estimate")
        if interaction:
            check(effect["p_value"] is None and not effect["development_signal"]
                  and effect["inference_status"] == "DESCRIPTIVE_ONLY_NO_PAIR_NULL_TEST", "unfrozen Pair inference")
        else:
            check(abs(effect["p_value"] - p) < 1e-12, "exact task test")
        rng = random.Random(plan["analysis"]["bootstrap_seed"])
        draws = sorted(sum(differences[rng.randrange(len(units))] for _ in range(len(units))) / len(units) for _ in range(plan["analysis"]["bootstrap_draws"]))
        bounds = [draws[math.ceil(q * len(draws)) - 1] for q in (0.025, 0.975)]
        check([effect["ci_low"], effect["ci_high"]] == bounds, "descriptive bootstrap interval")
    adjusted = 0.0
    for rank, index in enumerate(sorted(range(len(effects)), key=lambda index: probabilities[index])):
        adjusted = max(adjusted, min(1.0, (len(effects) - rank) * probabilities[index]))
        if effects[index]["p_value"] is not None:
            check(effects[index]["adjusted_p_value"] == adjusted, "Holm family adjustment")
    return {"status": "VERIFIED_NON_CLAIM_DEVELOPMENT_RESULT", "task_units": len(tasks), "assigned_rows": len(assigned),
            "provider_calls": provider_calls, "failed_rows": report["failed_rows"], "effect_rows": len(effects),
            "scientific_claim_allowed": False, "summary_bundle_sha256": bundle_digest(root / "summary"),
            "input_alignment_status": ("PREPARED_BASELINE_INPUTS_VERIFIED" if len(prepared_prefixes) == len(tasks)
                                       else "LEGACY_SOURCE_ONLY_REPRESENTATION"),
            "limitation": "Replays frozen accounting, inputs, labels and statistics; does not establish Oracle accuracy or a scientific effect."}
def _replay_scoped_development_prompt(task, policy, arm, check):
    """Independent exact-scope replay; no production binding or rendering calls."""
    graph, source = task["graph"], task["prompt"]
    nodes = {node["node_id"]: node for node in graph["nodes"]}
    edges = {(edge["source_id"], edge["edge_type"], edge["target_id"]) for edge in graph["edges"]}
    factors, scopes = policy["factors"], task["factor_scopes"]
    pair = len(factors) == 2
    flags = {"A00": (False, False), "A10": (True, False), "A01": (False, True), "A11": (True, True)}[arm] if pair else (arm == "TARGET",)
    check(len(scopes) == len(factors) == len(flags), "factor coordinates")
    compatibility = task.get("intervention_compatibility", task.get("pair_compatibility", {}))
    check(compatibility.get("binding_id") == task["binding_id"] and compatibility.get("decision") == "compatible"
          and compatibility.get("outcomes_used") is False, "source intervention compatibility")
    instructions, removals = [], []
    for index, (factor, scope, active) in enumerate(zip(factors, scopes, flags, strict=True)):
        op = scope["operation_node_id"]
        check(op in nodes and nodes[op]["node_type"] == "task_operation", "scope operation")
        check(all((key, "used_by", op) in edges and nodes[key]["node_type"] == "data_object"
                  for key in scope["subject_node_ids"]), "scope subjects")
        matched = [item for item in graph["scoped_feature_assessments"]
                   if item["scope"] == scope and item["feature_id"] == factor["feature_id"]]
        check(len(matched) == 1 and matched[0]["state"] == ("absent" if factor["operation"] == "add" else "present"),
              "exact source-state gate")
        if arm == "BASELINE":
            continue
        if active and factor["operation"] == "remove":
            if arm in task.get("reviewed_variants", {}):
                continue
            requirements = matched[0]["requirement_node_ids"]
            check(len(requirements) == 1, "literal REMOVE requirement")
            key = requirements[0]
            node = nodes[key]
            check(all(target in {op, *scope["subject_node_ids"]} for origin, _, target in edges if origin == key),
                  "literal REMOVE changes another object")
            check(not any(other["scope"] != scope and key in other["requirement_node_ids"]
                          for other in graph["scoped_feature_assessments"]), "literal REMOVE changes another scope")
            check(not any(other["node_id"] != key and other["node_type"] != "task"
                          and max(node["evidence_start"], other["evidence_start"]) < min(node["evidence_end"], other["evidence_end"])
                          for other in nodes.values()), "literal REMOVE overlaps non-target evidence")
            removals.append((node["evidence_start"], node["evidence_end"]))
            continue
        text = factor["addition"] if active else task["factor_control_texts"][index]["NOOP" if pair else arm]
        def quote(key):
            return json.dumps(source[nodes[key]["evidence_start"]:nodes[key]["evidence_end"]], ensure_ascii=False)
        prefix = ""
        if scope["subject_node_ids"]:
            prefix = "For the input described by " if len(scope["subject_node_ids"]) == 1 else "For the inputs described by "
            prefix += ", ".join(quote(key) for key in scope["subject_node_ids"]) + ": "
        if scope["condition_node_ids"]:
            prefix += "Under the unchanged source conditions " + ", ".join(quote(key) for key in scope["condition_node_ids"]) + ": "
        instructions.append((op, prefix + text))
    if arm in task.get("reviewed_variants", {}):
        variant = task["reviewed_variants"][arm]
        check(variant["binding_id"] == task["binding_id"] and variant["source_prompt_sha256"] == content_hash(source)
              and variant["enabled"] == list(flags) and variant["source_review"]["outcomes_used"] is False,
              "reviewed realization binding")
        mapped = variant["source_to_variant_nodes"]
        rewritten = {node["node_id"]: node for node in variant["graph"]["nodes"]}
        target_requirements = {key for item in graph["scoped_feature_assessments"]
                              if any(item["scope"] == scope and item["feature_id"] == factor["feature_id"]
                                     for factor, scope in zip(factors, scopes, strict=True))
                              for key in item["requirement_node_ids"]}
        for key, before in nodes.items():
            if before["node_type"] == "task" or key in target_requirements:
                continue
            check(key in mapped and mapped[key] in rewritten, "reviewed realization drops a non-target node")
            after = rewritten[mapped[key]]
            check(before["semantic_id"] == after["semantic_id"] and before["node_type"] == after["node_type"]
                  and source[before["evidence_start"]:before["evidence_end"]] == variant["prompt"][after["evidence_start"]:after["evidence_end"]],
                  "reviewed realization changes a non-target requirement")
        for item in graph["scoped_feature_assessments"]:
            scope = item["scope"]
            translated = dict(operation_node_id=mapped[scope["operation_node_id"]],
                              subject_node_ids=sorted(mapped[key] for key in scope["subject_node_ids"]),
                              condition_node_ids=sorted(mapped[key] for key in scope["condition_node_ids"]))
            expected_state = item["state"]
            for factor, target_scope, active in zip(factors, scopes, flags, strict=True):
                if scope == target_scope and item["feature_id"] == factor["feature_id"] and active:
                    expected_state = "present" if factor["operation"] == "add" else "absent"
            matches = [row for row in variant["graph"]["scoped_feature_assessments"]
                       if row["scope"] == translated and row["feature_id"] == item["feature_id"]]
            check(len(matches) == 1 and matches[0]["state"] == expected_state, "reviewed realization scope states")
        return variant["prompt"]
    result = source
    for start, end in sorted(set(removals), reverse=True):
        result = result[:start] + result[end:]
    for op in dict.fromkeys(key for key, _ in instructions):
        node = nodes[op]
        result += "\n\nFor the operation described by " + json.dumps(source[node["evidence_start"]:node["evidence_end"]], ensure_ascii=False) + ":\n"
        result += "\n".join("- " + text for key, text in instructions if key == op)
    return result


from prompt_mechanism_study.representation import DataRole, DataRoleManifest
from prompt_mechanism_study.study_design import (
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    FormalBudgetPreflight,
    FormalReportAuthorization,
    StudyFreezeIndex,
)
from prompt_mechanism_study.study_planning import (
    QualificationBundle,
    QualificationPlanBundle,
    QualificationProfileKind,
    RQ1BudgetQualification,
)

from prompt_mechanism_study.verification.design import verify_target_study_freezes
from prompt_mechanism_study.verification.effects import verify_target_shared_evidence
from prompt_mechanism_study.verification.integrity import _decode_target_value
from prompt_mechanism_study.target_security_profiles import (
    evaluate_target_security_profile, target_security_profile_producer_sha256,
)


def verify_target_execution_artifacts(
    *, discovery, confirmation, evidence, environment_reference, command_reference,
    provider_ledger_reference, execution_artifacts,
) -> dict[str, object]:
    """Resolve actual frozen inputs and replay each assignment's raw measurements.

    This is evidence consistency, not cryptographic proof of a historical event.
    The checked-out author decision is the authority for this active protocol;
    a package cannot grant itself permission by changing its evidence-level tag.
    """
    if not isinstance(execution_artifacts, Mapping):
        raise ValueError("formal execution requires the actual execution artifacts")

    def resolve(reference):
        value = execution_artifacts.get(reference.artifact_id)
        if value is None or content_hash(value) != reference.sha256:
            raise ValueError(f"execution artifact missing or hash mismatch: {reference.artifact_id}")
        return value

    decision = resolve(discovery.identity_and_scope_decision)
    root = Path(__file__).resolve().parents[3]
    try:
        active_decision = read_json_exact(root / "configs/formal/identity_and_scope_decision.json")
        active_manifest = read_json_exact(root / "configs/formal/qualification_data_manifest.json")
    except ValueError as exc:
        raise ValueError(
            "active protocol is not frozen and authorized for formal execution: "
            "checked-out author decision or qualification manifest is unavailable or invalid"
        ) from exc
    if (
        decision != active_decision or decision.get("formal_execution_authorized") is not True
        or active_manifest.get("protocol_status") != "FROZEN"
        or decision.get("protocol_id") != discovery.protocol_id
    ):
        raise ValueError("active protocol is not frozen and authorized for formal execution")
    qualification = _decode_target_value(
        resolve(discovery.qualification_bundle), QualificationBundle, "execution qualification",
    )
    plans = _decode_target_value(
        resolve(qualification.qualification_plan_bundle), QualificationPlanBundle,
        "execution qualification plans",
    )
    roles = _decode_target_value(
        resolve(qualification.data_role_manifest), DataRoleManifest, "execution data roles",
    )
    if (
        not plans.acceptance_ready
        or plans.data_role_manifest_id != roles.data_role_manifest_id
        or plans.qualification_accept_data_id != qualification.qualification_accept_data_id
        or roles.qualification_accept_data_id != qualification.qualification_accept_data_id
        or plans.protocol_id != qualification.protocol_id
    ):
        raise ValueError("execution qualification plans drifted from frozen roles")
    for plan, profile in zip(plans.plans, qualification.profiles, strict=True):
        accepted = resolve(profile.artifact)
        if (
            profile.profile_kind != plan.profile_kind
            or profile.selected_profile_id != plan.selected_profile_id
            or profile.code_commit != plan.code_commit
            or not isinstance(accepted, Mapping) or accepted.get("status") != "ACCEPTED"
            or accepted.get("qualification_accept_data_id") != qualification.qualification_accept_data_id
            or (
                profile.profile_kind not in {
                    QualificationProfileKind.POWER_AND_MARGIN,
                    QualificationProfileKind.RQ1_BASELINES,
                }
                and accepted.get("selected_profile_id") != profile.selected_profile_id
            )
        ):
            raise ValueError("execution lacks the frozen accepted qualification result")
    environment, command = resolve(environment_reference), resolve(command_reference)
    if (
        not isinstance(environment, Mapping)
        or environment.get("execution_kind") != "FORMAL_PROVIDER_EXECUTION"
        or not all(isinstance(environment.get(key), str) and environment[key]
                   for key in ("python_version", "platform", "code_commit"))
        or environment.get("code_commit") != qualification.profiles[0].code_commit
        or not isinstance(command, Mapping) or not isinstance(command.get("argv"), list)
        or not command["argv"] or not all(isinstance(arg, str) for arg in command["argv"])
        or "smoke" in command["argv"]
    ):
        raise ValueError("execution environment/command is missing or non-confirmatory")
    contract = resolve(confirmation.outcome_contract)
    if not isinstance(contract, Mapping) or contract.get("execution_kind") != "FORMAL_PROVIDER_EXECUTION":
        raise ValueError("formal execution requires the prospectively frozen measurement contract")
    provider = decision.get("prospective_provider_policy", {})
    snapshot = provider.get("fixed_snapshot_model_id")
    if not snapshot or any(a.model_id != snapshot for a in evidence.ledger.assignments):
        raise ValueError("execution assignments drifted from the author-selected snapshot")
    task_contracts = contract.get("task_contracts")
    if not isinstance(task_contracts, Mapping) or any(
        not isinstance(frozen, Mapping)
        or not isinstance(frozen.get("functional_evaluator"), Mapping)
        or frozen["functional_evaluator"].get("model_id") != snapshot
        for frozen in task_contracts.values()
    ):
        raise ValueError("execution functional evaluator drifted from the author-selected snapshot")
    raw = resolve(provider_ledger_reference)
    return _replay_execution_measurements(evidence, contract, raw)


def _replay_execution_measurements(evidence, contract, raw) -> dict[str, object]:
    """Reconstruct outcomes from raw code and independent evaluator records."""
    if not isinstance(raw, Mapping) or not isinstance(raw.get("records"), list):
        raise ValueError("execution provider ledger requires assignment records")
    rows = raw["records"]
    if any(not isinstance(row, Mapping) for row in rows):
        raise ValueError("execution provider ledger contains an invalid record")
    by_id = {row.get("assignment_id"): row for row in rows}
    if len(by_id) != len(rows) or set(by_id) != {a.assignment_id for a in evidence.ledger.assignments}:
        raise ValueError("execution records must cover every assignment exactly once")
    outcomes = {item.assignment_id: item for item in evidence.ledger.outcomes}
    failures = {item.assignment_id: item for item in evidence.ledger.infrastructure_failures}
    task_contracts = contract.get("task_contracts")
    if not isinstance(task_contracts, Mapping):
        raise ValueError("execution measurement contract lacks frozen task contracts")
    calls = 0
    for assignment in evidence.ledger.assignments:
        row = by_id[assignment.assignment_id]
        request = row.get("generation_request")
        if not isinstance(request, Mapping) or (
            request.get("model_id") != assignment.model_id
            or request.get("arm") != assignment.arm.value
            or request.get("task_unit_id") != assignment.task_unit_id
            or request.get("task_instance_id") != assignment.task_instance_id
            or "provider_seed" not in request
            or request["provider_seed"] != assignment.provider_seed
            or not isinstance(request.get("prompt"), str)
            or content_hash(request["prompt"]) != assignment.variant_sha256
        ):
            raise ValueError("execution request model/arm/task/prompt/seed binding failed")
        if assignment.assignment_id in failures:
            failure = failures[assignment.assignment_id]
            if (
                row.get("status") != "infrastructure_failure"
                or row.get("producer") != failure.producer or row.get("reason") != failure.reason
                or not isinstance(row.get("error_response"), str) or not row["error_response"]
            ):
                raise ValueError("execution infrastructure failure lacks its original error")
            continue
        frozen = task_contracts.get(assignment.task_instance_id)
        if not isinstance(frozen, Mapping):
            raise ValueError("execution task lacks its frozen measurement contract")
        measurement = _decode_target_value(row.get("measurement"), Measurement, "execution measurement")
        if measurement.assignment_id != assignment.assignment_id:
            raise ValueError("execution measurement assignment binding failed")
        response = row.get("generation_response")
        if not isinstance(response, str):
            raise ValueError("execution generation response is missing")
        decoded = json_object(response)
        if set(decoded) != {"code"} or not isinstance(decoded["code"], str):
            raise ValueError("execution generation response schema mismatch")
        code = decoded["code"]
        calls += 1
        if (
            hashlib.sha256(response.encode("utf-8")).hexdigest() != measurement.generator_evidence_sha256
            or row.get("code") != code
            or measurement.code_sha256 != (content_hash(code) if code else None)
        ):
            raise ValueError("execution response/code digest failed independent replay")
        function_contract = frozen.get("functional_contract")
        if not isinstance(function_contract, Mapping):
            raise ValueError("execution functional contract is missing")
        language = function_contract.get("language", "python")
        profile_id = frozen.get("security_profile_id")
        if ("source_prompt_sha256" in function_contract
                and function_contract["source_prompt_sha256"] != content_hash(frozen.get("source_task_prompt"))):
            raise ValueError("execution functional contract source prompt binding differs")
        if (request.get("language", language) != language
                or not isinstance(profile_id, str)
                or not profile_id.startswith(language + ".")):
            raise ValueError("execution source, generation and Oracle languages differ")
        if row.get("syntax_parser") != syntax_parser_identity(language):
            raise ValueError("execution syntax parser identity failed independent replay")
        valid = bool(code.strip()) and code_syntax_valid(code, language)
        status = "valid" if valid else "invalid" if code.strip() else "no_code"
        if measurement.code_status.value != status or row.get("syntax_valid") is not valid:
            raise ValueError("execution code validity failed independent replay")
        scope = function_contract.get("measurement_scope", "complete")
        source_review = function_contract.get("review", {})
        if scope not in {"complete", "partial", "unresolved"} or not isinstance(source_review, Mapping):
            raise ValueError("execution functional source scope is invalid")
        specification = source_review.get("source_specification_disposition")
        if specification not in {None, "sufficient", "insufficient", "defect"}:
            raise ValueError("execution functional source review status is invalid")
        inherited = function_contract.get("parent_contract_applies_to_current_input", True)
        if type(inherited) is not bool:
            raise ValueError("execution parent contract applicability is invalid")
        if not inherited or specification == "defect" or not function_contract.get("requirements"):
            scope = "unresolved"
        elif specification == "insufficient" and scope == "complete":
            scope = "partial"
        if row.get("functional_source_scope") != scope:
            raise ValueError("execution functional scope failed independent replay")
        review_policy = row.get("functional_review_policy")
        if review_policy not in {None, "judge_all_syntax_valid_source_scopes"}:
            raise ValueError("execution functional review policy is invalid")
        if not valid:
            expected = (0, 0, 0, 0, 0, 0, 0, status)
            if any(row.get(key) is not None for key in ("security", "functional_response")):
                raise ValueError("execution terminal code contains evaluator output")
        else:
            if frozen.get("security_producer_sha256") != target_security_profile_producer_sha256():
                raise ValueError("execution security producer drifted from its qualification")
            security = evaluate_target_security_profile(code, frozen.get("security_profile_id"))
            if row.get("security") != security or measurement.oracle_evidence_sha256 != content_hash(security):
                raise ValueError("execution security measurement failed local replay")
            if review_policy is None and scope != "complete":
                # Replay frozen pre-revision records; active measurement always calls the judge.
                functional = {
                    "status": "unknown", "reason": "source_functional_specification_incomplete",
                    "measurement_scope": scope,
                    "source_contract_sha256": content_hash(function_contract),
                }
                if any(row.get(key) is not None for key in
                       ("functional_request", "functional_response", "functional_response_sha256")):
                    raise ValueError("incomplete source cannot yield a full functional judge result")
                functional_digest = content_hash(functional)
            else:
                expected_request = build_review_request(
                    code, frozen.get("source_task_prompt"),
                    requirements=function_contract.get("requirements", []) if inherited else [],
                    environment_dependencies=function_contract.get("environment_dependencies", []) if inherited else [],
                    language=language,
                    source_scope=scope if review_policy is not None else None,
                )
                if (
                    row.get("functional_request") != expected_request
                    or row.get("functional_evaluator") != frozen.get("functional_evaluator")
                    or not isinstance(frozen.get("functional_evaluator"), Mapping)
                    or not isinstance(frozen["functional_evaluator"].get("model_id"), str)
                    or not frozen["functional_evaluator"]["model_id"]
                ):
                    raise ValueError("execution functional request/evaluator binding failed")
                functional_raw = row.get("functional_response")
                failure = row.get("functional_failure")
                if failure is not None:
                    if not isinstance(failure, Mapping) or set(failure) != {"error_type", "error_message"}:
                        raise ValueError("execution functional failure evidence is invalid")
                    if functional_raw is not None:
                        if not isinstance(functional_raw, str):
                            raise ValueError("execution functional response is invalid")
                        try:
                            validate_review_response(functional_raw.encode("utf-8"), code)
                        except (ValueError, RuntimeError):
                            pass
                        else:
                            raise ValueError("valid functional response cannot be marked failed")
                    functional = {"status": "unknown", "reason": "functional_evaluator_failed", "failure": failure}
                    functional_digest = (hashlib.sha256(functional_raw.encode("utf-8")).hexdigest()
                                         if functional_raw is not None else content_hash(failure))
                else:
                    if not isinstance(functional_raw, str):
                        raise ValueError("execution functional response is missing")
                    functional = validate_review_response(functional_raw.encode("utf-8"), code)
                    functional_digest = hashlib.sha256(functional_raw.encode("utf-8")).hexdigest()
                calls += 1
            if (
                functional_digest != measurement.functional_evidence_sha256
                or row.get("functional_validated") != functional
                or measurement.functional_status.value != functional["status"]
                or measurement.oracle_status.value != security["security_label"]
            ):
                raise ValueError("execution evaluator labels/digests failed independent replay")
            oracle = security["security_label"]
            evaluable = int(oracle in {"secure", "insecure"})
            secure = int(oracle == "secure")
            upper = int(oracle != "insecure")
            functionality = {"pass": 1, "fail": 0, "unknown": None}[functional["status"]]
            joint = (0 if oracle == "insecure" or functionality == 0
                     else None if oracle == "unknown" or functionality is None else 1)
            expected = (1, evaluable, secure, upper, functionality, joint,
                        int(upper == 1 and functionality != 0), None)
        outcome = outcomes.get(assignment.assignment_id)
        observed = None if outcome is None else (
            outcome.code_valid, outcome.oracle_evaluable, outcome.secure_yield,
            outcome.latent_secure_upper, outcome.functionality, outcome.joint,
            outcome.latent_joint_upper, outcome.terminal_status,
        )
        if observed != expected:
            raise ValueError("execution outcome failed independent measurement reconstruction")
    return {"status": "TARGET_EXECUTION_EVIDENCE_VERIFIED", "assignments": len(rows),
            "completed_measurement_calls": calls}

def verify_formal_report_authorization(
    *,
    manifest: DataRoleManifest,
    budget: RQ1BudgetQualification,
    discovery: DiscoveryDesignFreeze,
    ledger: FixedSlotLedger,
    union: SharedConfirmationUnion,
    dispatch: ConfirmationDispatchManifest,
    randomization_plan: TargetRandomizationPlan,
    task_bundles: Sequence[TargetTaskBundle],
    assignments: Sequence[AssignedArmITTRecord],
    preflight: FormalBudgetPreflight,
    confirmation: ConfirmationFreeze,
    index: StudyFreezeIndex,
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    authorization: FormalReportAuthorization,
    execution_artifacts: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Independently verify the only receipt that can enable paper-facing claims."""

    if type(authorization) is not FormalReportAuthorization:
        raise TypeError("report authorization verifier requires a formal receipt")
    if preflight.actual_power_results is None:
        raise ValueError("formal claims require independently verified actual task-support power")
    verify_target_execution_artifacts(
        discovery=discovery, confirmation=confirmation, evidence=evidence,
        environment_reference=authorization.execution_environment,
        command_reference=authorization.execution_command,
        provider_ledger_reference=authorization.provider_call_ledger,
        execution_artifacts=execution_artifacts,
    )
    freeze_verification = verify_target_study_freezes(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
    )
    evidence_verification = verify_target_shared_evidence(evidence, yields)
    frozen_assignments = tuple(
        sorted(assignments, key=lambda item: item.assignment_id)
    )
    confirmation_task_units = {
        task.task_unit_id
        for binding in manifest.bindings
        if binding.role is DataRole.CONFIRMATION
        for task in binding.task_units
    }
    assigned_task_units = {item.task_unit_id for item in frozen_assignments}
    plan = TargetITTPlan(
        budget.power_and_margin_memo.bootstrap_seed,
        budget.power_and_margin_memo.bootstrap_draws,
        budget.power_and_margin_memo.alpha,
        budget.power_and_margin_memo.atomic_power.plan.minimum_task_units_per_stratum,
        budget.power_and_margin_memo.minimum_valid_bootstrap_fraction,
        budget.power_and_margin_memo.atomic_power.plan.practical_margin,
        budget.power_and_margin_memo.pair_power.plan.practical_margin,
        budget.power_and_margin_memo.maximum_unknown_fraction_among_valid,
        atomic_minimum_task_units_per_realization=budget.power_and_margin_memo.atomic_power.plan.minimum_task_units_per_realization,
        pair_minimum_task_units_per_realization=budget.power_and_margin_memo.pair_power.plan.minimum_task_units_per_realization,
    )
    if (
        evidence.evidence_level not in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}
        or evidence.ledger.dispatch != dispatch
        or evidence.ledger.assignments != frozen_assignments
        or evidence.plan != plan
        or not assigned_task_units <= confirmation_task_units
    ):
        raise ValueError("formal report evidence boundary failed independent replay")
    return _check_formal_authorization(
        index, evidence, yields, authorization, freeze_verification, evidence_verification,
    )


def _check_formal_authorization(
    index: StudyFreezeIndex,
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    authorization: FormalReportAuthorization,
    freeze_verification: Mapping[str, object],
    evidence_verification: Mapping[str, object],
) -> dict[str, object]:
    """Check receipt references after the caller has verified its actual inputs."""
    if evidence.evidence_level not in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}:
        raise ValueError("formal report requires executed evidence")
    expected = (
        index.protocol_id,
        index.study_freeze_index_id,
        content_hash(index),
        evidence.shared_evidence_record_id,
        content_hash(evidence),
        yields.target_selector_yield_result_id,
        content_hash(yields),
        evidence.ledger.evidence_ledger_id,
        content_hash(evidence.ledger),
        content_hash(freeze_verification),
        content_hash(evidence_verification),
        evidence.evidence_level.value,
        "AUTHORIZED",
        True,
    )
    observed = (
        authorization.protocol_id,
        authorization.study_freeze_index.artifact_id,
        authorization.study_freeze_index.sha256,
        authorization.shared_evidence_record.artifact_id,
        authorization.shared_evidence_record.sha256,
        authorization.target_selector_yield_result.artifact_id,
        authorization.target_selector_yield_result.sha256,
        authorization.evidence_ledger.artifact_id,
        authorization.evidence_ledger.sha256,
        authorization.freeze_verification_sha256,
        authorization.evidence_verification_sha256,
        authorization.evidence_level,
        authorization.authorization_status,
        authorization.scientific_claim_allowed,
    )
    if observed != expected:
        raise ValueError("formal report authorization failed independent replay")
    return {
        "status": "FORMAL_REPORT_AUTHORIZATION_VERIFIED",
        "formal_report_authorization_id": (
            authorization.formal_report_authorization_id
        ),
        "scientific_claim_allowed": True,
        "evidence_level": evidence.evidence_level.value,
    }


def verify_target_rq_tables(
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    report: Mapping[str, object],
    authorization: FormalReportAuthorization | None = None,
) -> dict[str, object]:
    """Independently rebuild every target RQ row and its claim-level Gate."""

    verification = verify_target_shared_evidence(evidence, yields)
    return _check_target_rq_tables(evidence, yields, report, authorization, verification)


def _check_target_rq_tables(
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    report: Mapping[str, object],
    authorization: FormalReportAuthorization | None,
    verification: Mapping[str, object],
) -> dict[str, object]:
    """Rebuild tables from the evidence verified once by this invocation."""
    slots_by_selector: dict[tuple[PolicyTrack, str, str], list[object]] = defaultdict(list)
    for slot in yields.slots:
        slots_by_selector[(slot.track, slot.model_id, slot.selector_id)].append(slot)
    selector_rows = []
    for selector in sorted(
        yields.selectors,
        key=lambda item: (item.track.value, item.model_id, item.selector_id),
    ):
        slots = sorted(
            slots_by_selector[(selector.track, selector.model_id, selector.selector_id)],
            key=lambda item: item.rank,
        )
        if len(slots) != selector.top_k:
            raise ValueError("RQ verifier lost a fixed selector slot")
        counts = Counter(
            (
                slot.effect_status.value
                if slot.effect_status is not None
                else (
                    "SELECTOR_EMPTY_OR_FAILURE"
                    if slot.slot_status is not SlotStatus.FILLED
                    else "BRIDGE_OR_PROTOCOLIZATION_FAILURE"
                )
            )
            for slot in slots
        )
        selector_rows.append(
            {
                "track": selector.track.value,
                "model_id": selector.model_id,
                "selector_id": selector.selector_id,
                "top_k": selector.top_k,
                "meaningful_slots": selector.meaningful_slots,
                "meaningful_yield_at_k": selector.meaningful_yield_at_k,
                "positive_meaningful_slots": counts[
                    ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL.value
                ],
                "negative_meaningful_slots": counts[
                    ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL.value
                ],
                "practically_null_slots": counts[
                    ConfirmatoryEffectStatus.PRACTICALLY_NULL.value
                ],
                "inconclusive_slots": counts[
                    ConfirmatoryEffectStatus.INCONCLUSIVE.value
                ],
                "non_evaluable_slots": counts[
                    ConfirmatoryEffectStatus.NON_EVALUABLE.value
                ],
                "selector_empty_or_failure_slots": counts[
                    "SELECTOR_EMPTY_OR_FAILURE"
                ],
                "bridge_or_protocolization_failure_slots": counts[
                    "BRIDGE_OR_PROTOCOLIZATION_FAILURE"
                ],
            }
        )
    selector_by_key = {
        (row["track"], row["model_id"], row["selector_id"]): row
        for row in selector_rows
    }
    rq2_rows = []
    for track, full_id, ablation_id in (
        (PolicyTrack.ATOMIC, "atomic_full", "atomic_rd_only"),
        (PolicyTrack.PAIR, "pair_full", "pair_no_relation"),
    ):
        models = sorted(
            {
                model
                for row_track, model, selector in selector_by_key
                if row_track == track.value and selector in {full_id, ablation_id}
            }
        )
        for model in models:
            full = selector_by_key.get((track.value, model, full_id))
            ablation = selector_by_key.get((track.value, model, ablation_id))
            if full is None or ablation is None or full["top_k"] != ablation["top_k"]:
                raise ValueError("RQ2 verifier lacks a sole-difference selector pair")
            rq2_rows.append(
                {
                    "track": track.value,
                    "model_id": model,
                    "full_selector_id": full_id,
                    "ablation_selector_id": ablation_id,
                    "top_k": full["top_k"],
                    "full_meaningful_yield_at_k": full["meaningful_yield_at_k"],
                    "ablation_meaningful_yield_at_k": ablation[
                        "meaningful_yield_at_k"
                    ],
                    "full_minus_ablation_yield_at_k": (
                        full["meaningful_yield_at_k"]
                        - ablation["meaningful_yield_at_k"]
                    ),
                    "comparison_semantics": (
                        "descriptive_fixed_discovery_split_no_rank_pairing"
                    ),
                }
            )
    families = []
    effects = []
    for family in evidence.families:
        families.append(
            {
                "track": family.track.value,
                "family_status": family.status.value,
                "simultaneous_critical_value": family.simultaneous_critical_value,
                "valid_bootstrap_draws": family.valid_bootstrap_draws,
                "invalid_bootstrap_draws": family.invalid_bootstrap_draws,
                "unique_effects": len(family.estimates),
            }
        )
        for estimate in family.estimates:
            effects.append(
                {
                    "track": estimate.track.value,
                    "candidate_record_id": estimate.candidate_record_id,
                    "effect_coordinate_id": estimate.effect_coordinate_id,
                    "policy_key": estimate.policy_key,
                    "model_id": estimate.model_id,
                    "estimand": (
                        "assigned_arm_task_unit_target_minus_noop_itt"
                        if estimate.track is PolicyTrack.ATOMIC
                        else "assigned_cell_task_unit_risk_difference_interaction_itt"
                    ),
                    "primary_endpoint": "oracle_evaluable_secure_code_yield",
                    "point": estimate.point,
                    "standard_error": estimate.standard_error,
                    "simultaneous_lower": estimate.simultaneous_lower,
                    "simultaneous_upper": estimate.simultaneous_upper,
                    "latent_lower": estimate.latent_lower,
                    "latent_upper": estimate.latent_upper,
                    "practical_margin": estimate.practical_margin,
                    "effect_status": estimate.status.value,
                    "reasons": list(estimate.reasons),
                    "task_units": estimate.task_units,
                    "assignments": estimate.assignments,
                    "response_pattern_classification_status": (
                        estimate.response_pattern.status.value
                    ),
                    "response_pattern": estimate.response_pattern.label,
                    "response_pattern_predicate_sha256": (
                        estimate.response_pattern.predicate_sha256
                    ),
                    "response_pattern_reasons": list(
                        estimate.response_pattern.reasons
                    ),
                    "pair_response_surface": (
                        None
                        if estimate.response_pattern.surface is None
                        else {
                            "mean_00": estimate.response_pattern.surface.mean_00,
                            "mean_10": estimate.response_pattern.surface.mean_10,
                            "mean_01": estimate.response_pattern.surface.mean_01,
                            "mean_11": estimate.response_pattern.surface.mean_11,
                            "factor_1_at_0": estimate.response_pattern.surface.factor_1_at_0,
                            "factor_2_at_0": estimate.response_pattern.surface.factor_2_at_0,
                            "joint": estimate.response_pattern.surface.joint,
                            "factor_1_at_1": estimate.response_pattern.surface.factor_1_at_1,
                            "factor_2_at_1": estimate.response_pattern.surface.factor_2_at_1,
                            "interaction": estimate.response_pattern.surface.interaction,
                        }
                    ),
                    "arms": [
                        {
                            "arm": arm.arm.value,
                            "assignments": arm.assignments,
                            "secure_yield": arm.secure_yield,
                            "code_validity": arm.code_validity,
                            "oracle_evaluability": arm.oracle_evaluability,
                            "functionality_yield": arm.functionality_yield,
                            "joint_success_yield": arm.joint_success_yield,
                            "oracle_unknown_valid_assignments": (
                                arm.oracle_unknown_valid_assignments
                            ),
                            "terminal_assignments": arm.terminal_assignments,
                        }
                        for arm in estimate.arm_summaries
                    ],
                }
            )
    claim_allowed = authorization is not None
    if authorization is not None:
        if type(authorization) is not FormalReportAuthorization:
            raise TypeError("RQ verifier requires a formal authorization receipt")
        if (
            authorization.protocol_id
            != evidence.ledger.dispatch.union.ledger.protocol_id
            or authorization.shared_evidence_record.artifact_id
            != evidence.shared_evidence_record_id
            or authorization.shared_evidence_record.sha256 != content_hash(evidence)
            or authorization.target_selector_yield_result.artifact_id
            != yields.target_selector_yield_result_id
            or authorization.target_selector_yield_result.sha256
            != content_hash(yields)
            or authorization.evidence_ledger.artifact_id
            != evidence.ledger.evidence_ledger_id
            or authorization.evidence_ledger.sha256 != content_hash(evidence.ledger)
            or authorization.evidence_level != evidence.evidence_level.value
            or authorization.scientific_claim_allowed is not True
        ):
            raise ValueError("RQ authorization failed independent evidence binding")
        report_status = "FORMAL_REPORT_AUTHORIZED"
    else:
        report_status = (
            "EXECUTED_EVIDENCE_AWAITING_FORMAL_REPORT_AUTHORIZATION"
            if evidence.evidence_level
            in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}
            else "NON_CLAIM_TEST_ARTIFACT"
        )
    expected = {
        "schema_version": "3.0",
        "protocol_id": evidence.ledger.dispatch.union.ledger.protocol_id,
        "shared_evidence_record_id": evidence.shared_evidence_record_id,
        "target_selector_yield_result_id": yields.target_selector_yield_result_id,
        "evidence_level": evidence.evidence_level.value,
        "report_status": report_status,
        "scientific_claim_allowed": claim_allowed,
        "formal_report_authorization_id": (
            None
            if authorization is None
            else authorization.formal_report_authorization_id
        ),
        "endpoint_order": [item.value for item in evidence.plan.metrics],
        "context_analysis_status": evidence.plan.context_analysis.status.value,
        "context_modifier_rows": [],
        "pair_response_pattern_plan_status": (
            evidence.plan.pair_response_patterns.status.value
        ),
        "rq1_selector_rows": selector_rows,
        "rq2_full_minus_ablation_rows": rq2_rows,
        "primary_family_rows": families,
        "unique_effect_rows": sorted(
            effects,
            key=lambda row: (row["track"], row["candidate_record_id"]),
        ),
        "independent_verification": verification,
    }
    expected["target_rq_tables_id"] = content_id("target_rq_tables_", expected)
    if dict(report) != expected:
        raise ValueError("target RQ tables failed independent replay")
    return {
        "status": "TARGET_RQ_TABLES_VERIFIED",
        "target_rq_tables_id": expected["target_rq_tables_id"],
        "scientific_claim_allowed": claim_allowed,
        "selector_rows": len(selector_rows),
        "rq2_rows": len(rq2_rows),
        "unique_effect_rows": len(effects),
    }

__all__ = [
    "verify_formal_report_authorization",
    "verify_target_rq_tables",
]
