"""Independent source-review evidence and numerical power reconstruction."""


from __future__ import annotations
import hashlib
import math
import random
from collections import Counter
from functools import lru_cache
from prompt_mechanism_study.experiment.randomization import AssignedArmITTRecord
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.experiment.study_planning import ATOMIC_POWER_ARMS, TargetPowerSimulationResult


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
    from prompt_mechanism_study.data.curation import _is_response_format_requirement

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


@lru_cache(maxsize=16)
def verify_target_power_simulation(result: TargetPowerSimulationResult) -> dict[str, object]:
    """Independently generate categorical outcomes and replay the actual family estimator."""
    from prompt_mechanism_study.experiment.inference import ConfirmatoryEffectStatus
    from prompt_mechanism_study.experiment.outcomes import Outcome
    from prompt_mechanism_study.verification.effects import _v3_work, _v3_family

    if type(result) is not TargetPowerSimulationResult:
        raise TypeError("power verifier requires a TargetPowerSimulationResult")
    plan = result.plan
    rows_by_coordinate = _independent_power_assignments(plan)
    record_ids = [[row.assignment_id for row in rows] for rows in rows_by_coordinate]
    for assumption, reported in zip(plan.assumptions, result.scenarios):
        seed = int(
            hashlib.sha256(f"{plan.simulation_seed}|{assumption.scenario_id}".encode()).hexdigest()[
                :16
            ],
            16,
        )
        generator = random.Random(seed)
        successes = [0 for _ in rows_by_coordinate]
        statuses = Counter()
        errors, criticals = ([], [])
        digest = hashlib.sha256()
        for _ in range(plan.simulation_replicates):
            uniforms = _independent_task_draws(generator, assumption, plan, rows_by_coordinate)
            work = {}
            for coordinate, rows in enumerate(rows_by_coordinate):
                outcomes = {}
                for j, row in enumerate(rows):
                    arm_index = j % plan.total_block_slots // (plan.total_block_slots // 4)
                    r = int(row.realization_id.split("-")[-1])
                    probability = (
                        assumption.arm_secure_yield_probabilities[arm_index][1]
                        + assumption.realization_arm_probability_offsets[r][arm_index]
                    )
                    u = uniforms[coordinate][j]
                    thresholds = (
                        assumption.terminal_no_code_rate,
                        assumption.terminal_no_code_rate + assumption.oracle_unknown_rate,
                        assumption.terminal_no_code_rate
                        + assumption.oracle_unknown_rate
                        + probability,
                    )
                    state = next((s for s, t in zip((0, 1, 3), thresholds) if u < t), 2)
                    digest.update(bytes([state]))
                    key = record_ids[coordinate][j]
                    outcomes[key] = Outcome(
                        key,
                        int(state != 0),
                        int(state in (2, 3)),
                        int(state == 3),
                        int(state in (1, 3)),
                        0,
                        0,
                        0,
                        "no_code" if state == 0 else None,
                    )
                work[str(coordinate)] = _v3_work(
                    plan.track, rows, outcomes, set(), plan.analysis_plan
                )
            family = _v3_family(plan.track, work, plan.analysis_plan)
            statuses[family["family_status"].value] += 1
            errors.extend(
                (w["standard_error"] for w in work.values() if w["standard_error"] is not None)
            )
            criticals.extend(d[0] for d in family["diagnostics"].values() if d[0] is not None)
            for coordinate in range(len(successes)):
                successes[coordinate] += family["statuses"][str(coordinate)] in (
                    ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL,
                    ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL,
                )
        power = min(successes) / plan.simulation_replicates
        probabilities = [p for _, p in assumption.arm_secure_yield_probabilities]
        effect = probabilities[0] - probabilities[1]
        expected = (
            float(effect),
            sum(errors) / len(errors) if errors else None,
            sum(criticals) / len(criticals) if criticals else None,
            power,
            1.96 * math.sqrt(power * (1 - power) / plan.simulation_replicates),
        )
        actual = (
            reported.effect,
            reported.task_unit_standard_error,
            reported.simultaneous_critical_value,
            reported.achieved_power,
            reported.monte_carlo_half_width_95,
        )
        mismatch = any(
            (
                (x is None) != (y is None)
                or (x is not None and (not math.isclose(x, y, rel_tol=0, abs_tol=1e-12)))
                for x, y in zip(actual, expected)
            )
        )
        if (
            mismatch
            or reported.meaningful_replicates_by_coordinate != tuple(successes)
            or reported.family_status_counts != tuple(sorted(statuses.items()))
            or (reported.simulated_outcome_sha256 != digest.hexdigest())
        ):
            raise ValueError("power simulation result failed independent replay")
    minimum = min((row.achieved_power for row in result.scenarios))
    if result.minimum_achieved_power != minimum or result.power_gate_passed != (
        minimum >= plan.target_power
    ):
        raise ValueError("power Gate failed independent replay")
    return {
        "status": "TARGET_POWER_SIMULATION_VERIFIED",
        "plan_id": plan.power_simulation_plan_id,
        "result_id": result.power_simulation_result_id,
        "scenario_count": len(result.scenarios),
        "minimum_achieved_power": result.minimum_achieved_power,
        "power_gate_passed": result.power_gate_passed,
    }


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
    from prompt_mechanism_study.experiment.randomization import ConfirmatoryArm

    names = ATOMIC_POWER_ARMS
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
            order = sorted(
                labels,
                key=lambda r: (
                    -(count * weights[r] - quotas[r]),
                    content_hash(
                        ("realization_remainder", plan.simulation_seed, policy, stratum, r)
                    ),
                ),
            )
            for r in order[: count - sum(quotas.values())]:
                quotas[r] += 1
            shuffled = sorted(
                units,
                key=lambda unit: (
                    content_hash(("realization_task", plan.simulation_seed, policy, stratum, unit)),
                    unit,
                ),
            )
            allocations = dict(zip(shuffled, [r for r in sorted(labels) for _ in range(quotas[r])]))
            for unit in units:
                definition.append((unit, stratum, allocations[unit]))
        if plan.task_support is not None:
            definition = [
                (unit, stratum, f"realization-{r}")
                for j, unit, stratum, r in plan.task_support
                if j == coordinate
            ]
        for unit, stratum, r in definition:
            for arm_index, name in enumerate(names):
                for slot in range(plan.total_block_slots // 4):
                    rows.append(
                        AssignedArmITTRecord(
                            policy,
                            policy,
                            policy,
                            "planning-model",
                            plan.track,
                            unit,
                            unit,
                            stratum,
                            r,
                            "planning-bundle",
                            "planning-protocol",
                            arm_index * (plan.total_block_slots // 4) + slot,
                            ConfirmatoryArm(name),
                            1.0,
                            weights[r],
                            "0" * 64,
                        )
                    )
        result.append(tuple(rows))
    return tuple(result)
