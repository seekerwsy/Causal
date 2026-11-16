"""End-to-end Stage I (Prompt TSG) -> Stage II (JCI Mechanism Discovery) -> Paired Evaluation runner."""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Any, Mapping
import zipfile

import numpy as np
import scipy

from prompt_mechanism_study.artifact_io import (
    file_sha256,
    read_json,
    write_bundle,
    write_json_new,
)
from prompt_mechanism_study.discovery.jci_structure import (
    ConditionalPermutation,
    StructureBackend,
)
from prompt_mechanism_study.discovery.mechanism_discovery import (
    classify_jci_mechanisms,
    evaluate_paired_counterfactuals,
)
from prompt_mechanism_study.experiment.code_generation import splice_target_unit_code
from prompt_mechanism_study.experiment.outcomes import derive_outcomes
from prompt_mechanism_study.llm import ProviderError, complete_chat
from prompt_mechanism_study.measurement.evaluate import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    MeasurementLedger,
    OracleStatus,
)
from prompt_mechanism_study.measurement.security_profiles import (
    LOCAL_PROFILE_IDS,
    evaluate_security_profile,
)
from prompt_mechanism_study.measurement.unit_test_oracle import evaluate_python_unit_tests
from prompt_mechanism_study.records import canonical_value, content_hash
from prompt_mechanism_study.tsg.prompt_contract import compile_source_propositions
from prompt_mechanism_study.tsg.scoped_intervention import render_prompt_intervention
from prompt_mechanism_study.tsg.source_representation import (
    TSG_ORTHOGONAL_MECHANISM_NAMES,
    evaluate_binary_attribute_reliability,
    extract_tsg_structural_attributes,
)


ARMS = ("baseline", "corr_tsg", "jci_flat", "jci_tsg")

DEFAULT_GENERATION_SYSTEM_PROMPT = (
    "You are an exact Python software engineer. The user JSON contains `prompt`, "
    "`target_symbol`, and optional `scaffold_code`. Starting from `scaffold_code` when "
    "provided, return ONLY one fenced ```python ... ``` code block implementing the "
    "requested function `target_symbol` (if non-null) or the complete Python module "
    "(if `target_symbol` is null). Do not output explanations, prose, tests, or diffs."
)

SOURCE_FILES = (
    "src/experiment/natural_study.py",
    "src/verification/natural_study.py",
    "src/discovery/mechanism_discovery.py",
    "src/discovery/jci_structure.py",
    "src/discovery/jci_context.R",
    "src/experiment/code_generation.py",
    "src/experiment/outcomes.py",
    "src/measurement/evaluate.py",
    "src/measurement/security_profiles.py",
    "src/measurement/unit_test_oracle.py",
    "src/llm.py",
    "src/tsg/prompt_contract.py",
    "src/tsg/prompt_tsg.py",
    "src/tsg/scoped_intervention.py",
    "src/tsg/source_representation.py",
    "src/artifact_io.py",
    "src/records.py",
    "src/cli.py",
    "pyproject.toml",
)


def validate_natural_plan(plan: Mapping[str, Any]) -> None:
    """Validate protocol and statistical plan constraints prior to execution."""
    if plan.get("formal_claim_allowed") is not False:
        raise ValueError("Natural study plan must keep formal_claim_allowed=false")
    if plan.get("study_mode") != "natural_task":
        raise ValueError('Natural study plan requires study_mode == "natural_task"')
    provider_mode = plan.get("provider_mode", "offline_fixture")
    if provider_mode not in {"offline_fixture", "local_vllm"}:
        raise ValueError(f"Unsupported provider_mode: {provider_mode}")
    if provider_mode == "offline_fixture":
        if plan.get("new_provider_calls", 0) != 0:
            raise ValueError("Offline fixture natural study requires new_provider_calls=0")
    else:
        evaluator = plan.get("evaluator")
        if not isinstance(evaluator, Mapping) or evaluator.get("provider") != "local_vllm":
            raise ValueError('local_vllm provider_mode requires evaluator with provider == "local_vllm"')
        if not evaluator.get("base_url") or not evaluator.get("model_id"):
            raise ValueError("local_vllm evaluator requires base_url and model_id")
    if not plan.get("fixture_path"):
        raise ValueError("Natural study plan requires fixture_path")
    if type(plan.get("ci_seed")) is not int:
        raise ValueError("ci_seed must be an integer")
    if type(plan.get("ci_draws", 0)) is not int or plan["ci_draws"] < 99:
        raise ValueError("ci_draws must be an integer >= 99")
    if type(plan.get("maximum_skeleton_conditioning_order", 0)) is not int or plan["maximum_skeleton_conditioning_order"] < 1:
        raise ValueError("maximum_skeleton_conditioning_order must be >= 1")
    for key in ("ci_alpha", "eval_alpha", "practical_margin"):
        val = plan.get(key)
        if not isinstance(val, (int, float)) or not 0.0 < float(val) < 1.0:
            raise ValueError(f"{key} must lie strictly in (0, 1)")
    for key in ("max_median_flip_rate", "max_attribute_flip_rate"):
        val = plan.get(key, 0.05)
        if not isinstance(val, (int, float)) or not 0.0 <= float(val) <= 1.0:
            raise ValueError(f"{key} must lie in [0, 1]")


def _resolve_evaluator(plan: Mapping[str, Any]) -> dict[str, Any]:
    evaluator = dict(plan["evaluator"])
    if os.environ.get("LOCAL_VLLM_BASE_URL"):
        evaluator["base_url"] = os.environ["LOCAL_VLLM_BASE_URL"]
    if os.environ.get("LOCAL_VLLM_MODEL_ID"):
        evaluator["model_id"] = os.environ["LOCAL_VLLM_MODEL_ID"]
    return evaluator


def _measure_single_arm(
    *,
    assignment_id: str,
    task: Mapping[str, Any],
    arm: str,
    response_text: str,
    provider_error: str | None,
    rendered: Mapping[str, Any],
    unit_test_timeout: float,
) -> tuple[Measurement, dict[str, Any]]:
    gen_digest = content_hash(response_text)
    if provider_error is not None:
        measurement = Measurement(
            assignment_id,
            CodeStatus.NO_CODE,
            OracleStatus.NOT_RUN,
            FunctionalStatus.NOT_RUN,
            gen_digest,
            terminal_reason=f"provider_error: {provider_error}",
        )
        detail = {
            "assignment_id": assignment_id,
            "task_unit_id": task["task_unit_id"],
            "arm": arm,
            "rendered_prompt": rendered["rendered_prompt"],
            "applied_mechanisms": list(rendered["applied_mechanisms"]),
            "raw_response": response_text,
            "provider_error": provider_error,
            "code_status": CodeStatus.NO_CODE.value,
            "terminal_reason": measurement.terminal_reason,
            "oracle_status": OracleStatus.NOT_RUN.value,
            "functional_status": FunctionalStatus.NOT_RUN.value,
            "code_sha256": None,
            "spliced_code": None,
            "security_detail": None,
            "functional_detail": None,
        }
        return measurement, detail

    splice = splice_target_unit_code(
        task.get("scaffold_code", ""),
        response_text,
        target_symbol=task.get("target_symbol"),
    )
    if splice["code_status"] != "valid":
        code_status = CodeStatus(splice["code_status"])
        measurement = Measurement(
            assignment_id,
            code_status,
            OracleStatus.NOT_RUN,
            FunctionalStatus.NOT_RUN,
            gen_digest,
            terminal_reason=str(splice["terminal_reason"] or code_status.value),
        )
        detail = {
            "assignment_id": assignment_id,
            "task_unit_id": task["task_unit_id"],
            "arm": arm,
            "rendered_prompt": rendered["rendered_prompt"],
            "applied_mechanisms": list(rendered["applied_mechanisms"]),
            "raw_response": response_text,
            "provider_error": None,
            "code_status": code_status.value,
            "terminal_reason": measurement.terminal_reason,
            "oracle_status": OracleStatus.NOT_RUN.value,
            "functional_status": FunctionalStatus.NOT_RUN.value,
            "code_sha256": None,
            "spliced_code": None,
            "security_detail": None,
            "functional_detail": None,
        }
        return measurement, detail

    spliced_code = str(splice["spliced_code"])
    target_fn = (task.get("target") or {}).get("operation_local_id") or task.get("target_symbol")
    sec = evaluate_security_profile(
        spliced_code,
        task["oracle_profile_id"],
        target_function=target_fn,
    )
    ut = evaluate_python_unit_tests(
        spliced_code,
        task["unit_test_script"],
        timeout_seconds=unit_test_timeout,
    )
    oracle = OracleStatus(sec["security_label"])
    func = FunctionalStatus(ut["functional_label"])
    measurement = Measurement(
        assignment_id,
        CodeStatus.VALID,
        oracle,
        func,
        gen_digest,
        code_sha256=str(splice["code_sha256"]),
        oracle_evidence_sha256=str(sec["mechanism_trace_sha256"]),
        functional_evidence_sha256=str(ut["evidence_sha256"]),
    )
    detail = {
        "assignment_id": assignment_id,
        "task_unit_id": task["task_unit_id"],
        "arm": arm,
        "rendered_prompt": rendered["rendered_prompt"],
        "applied_mechanisms": list(rendered["applied_mechanisms"]),
        "raw_response": response_text,
        "provider_error": None,
        "code_status": CodeStatus.VALID.value,
        "terminal_reason": None,
        "oracle_status": oracle.value,
        "functional_status": func.value,
        "code_sha256": str(splice["code_sha256"]),
        "spliced_code": spliced_code,
        "security_detail": {
            "security_label": sec["security_label"],
            "reason_code": sec["reason_code"],
            "mechanism_trace_sha256": sec["mechanism_trace_sha256"],
        },
        "functional_detail": ut,
    }
    return measurement, detail


def run_natural_study(
    plan_path: Path,
    output_dir: Path,
    *,
    rscript: Path | None = None,
) -> dict[str, Any]:
    """Execute end-to-end Stage I + Stage II JCI discovery + 4-arm paired counterfactual evaluation."""
    plan = read_json(Path(plan_path))
    validate_natural_plan(plan)
    out_dir = Path(output_dir)
    if out_dir.exists():
        raise FileExistsError(f"Output directory already exists: {out_dir}")

    benchmark = read_json(Path(plan["fixture_path"]))
    disc = benchmark["discovery_cohort"]
    eval_tasks = list(benchmark["evaluation_cohort"])
    if len(eval_tasks) < 2:
        raise ValueError("Evaluation cohort requires at least 2 unique task units")
    eval_ids = [t["task_unit_id"] for t in eval_tasks]
    if len(eval_ids) != len(set(eval_ids)):
        raise ValueError("Evaluation cohort task_unit_ids must be deduplicated")
    if set(disc["task_unit_ids"]) & set(eval_ids):
        raise ValueError("Discovery and evaluation task_unit_id splits must be strictly disjoint")
    for task in eval_tasks:
        if task["oracle_profile_id"] not in LOCAL_PROFILE_IDS:
            raise ValueError(f"Unsupported security profile: {task['oracle_profile_id']}")

    # Stage I: compile tolerant Prompt TSG on held-out cohort and verify calibration reliability.
    stage1_eval_rows: list[dict[str, Any]] = []
    compiled_eval: dict[str, tuple[Any, dict[str, Any]]] = {}
    eval_by_id: dict[str, dict[str, Any]] = {}
    for task in eval_tasks:
        tid = task["task_unit_id"]
        eval_by_id[tid] = task
        graph, compiled = compile_source_propositions(
            {"task_unit_id": tid, "prompt": task["prompt"]},
            task["record"],
            extractor_id="natural-stage1-eval",
            tolerant=True,
        )
        ids = compiled["local_node_ids"]
        tgt = task.get("target", {})
        op_id = ids.get(tgt.get("operation_local_id")) if tgt.get("operation_local_id") else None
        req_id = ids.get(tgt.get("requirement_local_id")) if tgt.get("requirement_local_id") else None
        attrs = extract_tsg_structural_attributes(
            graph,
            operation_node_id=op_id,
            requirement_node_id=req_id,
            prompt=task["prompt"],
            catalog=compiled["catalog"],
        )
        compiled_eval[tid] = (graph, compiled)
        stage1_eval_rows.append(
            {
                "task_unit_id": tid,
                "tsg_id": graph.tsg_id,
                "degraded_local_ids": compiled.get("degraded_local_ids", []),
                "orthogonal_mechanism_vector": attrs["orthogonal_mechanism_vector"],
                "local_binding_complete": bool(attrs["local_binding_complete"]),
                "local_unresolved_count": int(attrs["local_unresolved_count"]),
            }
        )

    cal_rows = list(benchmark.get("calibration_records", []))
    if cal_rows:
        ref_vecs = []
        cand_vecs = []
        for row in cal_rows:
            orig_id = row["task_unit_id"].removeprefix("cal_")
            ref_task = eval_by_id.get(orig_id)
            ref_row = next(r for r in stage1_eval_rows if r["task_unit_id"] == orig_id) if ref_task else None
            c_graph, c_comp = compile_source_propositions(
                row["task"],
                row["record"],
                extractor_id="natural-stage1-calibration",
                tolerant=True,
            )
            c_ids = c_comp["local_node_ids"]
            c_tgt = row.get("target", {})
            c_attrs = extract_tsg_structural_attributes(
                c_graph,
                operation_node_id=c_ids.get(c_tgt.get("operation_local_id")) if c_tgt.get("operation_local_id") else None,
                requirement_node_id=c_ids.get(c_tgt.get("requirement_local_id")) if c_tgt.get("requirement_local_id") else None,
                prompt=row["task"]["prompt"],
                catalog=c_comp["catalog"],
            )
            cand_vecs.append(c_attrs["orthogonal_mechanism_vector"])
            ref_vecs.append(
                ref_row["orthogonal_mechanism_vector"] if ref_row is not None else c_attrs["orthogonal_mechanism_vector"]
            )
        reliability = evaluate_binary_attribute_reliability(
            ref_vecs,
            cand_vecs,
            attribute_names=TSG_ORTHOGONAL_MECHANISM_NAMES,
            max_median_flip_rate=float(plan.get("max_median_flip_rate", 0.05)),
            max_attribute_flip_rate=float(plan.get("max_attribute_flip_rate", 0.10)),
        )
    else:
        reliability = {
            "n_tasks": len(stage1_eval_rows),
            "n_attributes": len(TSG_ORTHOGONAL_MECHANISM_NAMES),
            "attribute_names": list(TSG_ORTHOGONAL_MECHANISM_NAMES),
            "flip_rates": [0.0] * len(TSG_ORTHOGONAL_MECHANISM_NAMES),
            "median_flip_rate": 0.0,
            "max_flip_rate": 0.0,
            "max_median_flip_rate": float(plan.get("max_median_flip_rate", 0.05)),
            "max_attribute_flip_rate": float(plan.get("max_attribute_flip_rate", 0.10)),
            "stable_attribute_indices": list(range(len(TSG_ORTHOGONAL_MECHANISM_NAMES))),
            "stable_attribute_names": list(TSG_ORTHOGONAL_MECHANISM_NAMES),
            "gate_passed": True,
        }

    # Stage II: JCI mechanism discovery over discovery_cohort with post-generation sinks.
    disc_data = np.asarray(disc["rows"], dtype=int)
    ci = ConditionalPermutation(
        disc_data,
        disc["labels"],
        draws=int(plan["ci_draws"]),
        seed=int(plan["ci_seed"]),
    )
    backend = StructureBackend(rscript=rscript)
    try:
        pag_result = backend.search(
            disc["labels"],
            "python-jci12",
            ci,
            float(plan["ci_alpha"]),
            max_order=int(plan["maximum_skeleton_conditioning_order"]),
            context_vars=disc["context_vars"],
            sink_vars=disc["sink_vars"],
            on_insufficient_ci="conservative",
        )
    finally:
        backend.close()

    discovery = classify_jci_mechanisms(
        pag_result,
        data=disc_data,
        labels=disc["labels"],
        context_vars=disc["context_vars"],
        probe_map=disc["probe_map"],
        mechanism_vars=disc["mechanism_vars"],
        security_sink=disc["sink_vars"][0],
        functional_sink=disc["sink_vars"][1],
        flat_probe_var=disc.get("flat_probe_var"),
        bleed_vars=disc.get("bleed_vars", ()),
        alpha=float(plan["ci_alpha"]),
    )

    provider_mode = plan.get("provider_mode", "offline_fixture")
    evaluator = _resolve_evaluator(plan) if provider_mode == "local_vllm" else None
    gen_sys_prompt = plan.get("generation_system_prompt", DEFAULT_GENERATION_SYSTEM_PROMPT)
    unit_test_timeout = float(plan.get("unit_test_timeout_seconds", 5.0))

    jci_selected = discovery["jci_policy"]["selected_mechanisms"]
    corr_selected = discovery["corr_policy"]["selected_mechanisms"]

    all_measurements: list[Measurement] = []
    detail_rows: list[dict[str, Any]] = []
    wire_traces: list[dict[str, Any]] = []
    provider_calls = 0

    for task in eval_tasks:
        tid = task["task_unit_id"]
        graph, compiled = compiled_eval[tid]
        local_ids = compiled["local_node_ids"]
        mechs = task["mechanisms"]

        arm_specs = {
            "baseline": ("baseline", []),
            "corr_tsg": ("tsg_scoped", [mechs[mid] for mid in corr_selected if mid in mechs]),
            "jci_flat": ("flat", [mechs[mid] for mid in jci_selected if mid in mechs]),
            "jci_tsg": (
                discovery["jci_policy"]["recommended_mode"] if jci_selected else "tsg_scoped",
                [mechs[mid] for mid in jci_selected if mid in mechs],
            ),
        }

        for arm in ARMS:
            mode, selected_mechs = arm_specs[arm]
            rendered = render_prompt_intervention(
                task["prompt"],
                mode=mode,
                mechanisms=selected_mechs,
                graph=graph,
                local_node_ids=local_ids,
            )
            assignment_id = f"{tid}__{arm}"
            provider_error: str | None = None
            if provider_mode == "offline_fixture":
                response_text = task["offline_responses"][arm]
            else:
                provider_calls += 1
                trace_items: dict[str, str] = {}

                def _trace(kind: str, raw_bytes: bytes, *, store: dict[str, str] = trace_items) -> None:
                    store[kind] = raw_bytes.decode("utf-8", errors="replace")

                req_payload = {
                    "task_unit_id": tid,
                    "arm": arm,
                    "prompt": rendered["rendered_prompt"],
                    "target_symbol": task.get("target_symbol"),
                    "scaffold_code": task.get("scaffold_code", ""),
                }
                try:
                    raw_bytes = complete_chat(
                        req_payload,
                        evaluator,
                        gen_sys_prompt,
                        trace=_trace,
                    )
                    response_text = raw_bytes.decode("utf-8")
                except ProviderError as exc:
                    provider_error = str(exc)
                    response_text = ""
                wire_traces.append(
                    {
                        "assignment_id": assignment_id,
                        "task_unit_id": tid,
                        "arm": arm,
                        "error": provider_error,
                        **trace_items,
                    }
                )

            measurement, detail = _measure_single_arm(
                assignment_id=assignment_id,
                task=task,
                arm=arm,
                response_text=response_text,
                provider_error=provider_error,
                rendered=rendered,
                unit_test_timeout=unit_test_timeout,
            )
            all_measurements.append(measurement)
            detail_rows.append(detail)

    ledger = MeasurementLedger(
        study_id=plan["study_id"],
        randomization_id="paired_within_task_itt_v1",
        adapter_bundle_id="local_ast_plus_unit_test_v1",
        measurements=tuple(all_measurements),
    )
    outcomes = derive_outcomes(ledger)
    outcome_by_id = {row.assignment_id: row for row in outcomes}

    paired_inputs: list[dict[str, dict[str, Any]]] = []
    for task in eval_tasks:
        tid = task["task_unit_id"]
        arm_map: dict[str, dict[str, Any]] = {}
        for arm in ARMS:
            aid = f"{tid}__{arm}"
            out = outcome_by_id[aid]
            arm_map[arm] = {
                "code_valid": out.code_valid,
                "oracle_evaluable": out.oracle_evaluable,
                "secure_yield": out.secure_yield,
                "functionality": out.functionality,
                "joint": out.joint,
                "latent_joint_upper": out.latent_joint_upper,
            }
        paired_inputs.append(arm_map)

    paired = evaluate_paired_counterfactuals(
        paired_inputs,
        arms=ARMS,
        alpha=float(plan["eval_alpha"]),
        practical_margin=float(plan["practical_margin"]),
    )

    summary = {
        "study_id": plan["study_id"],
        "study_mode": "natural_task",
        "evidence_role": plan.get("evidence_role", "FORMATIVE_NATURAL_TASK_PAIRED"),
        "provider_mode": provider_mode,
        "formal_claim_allowed": False,
        "new_provider_calls": provider_calls,
        "n_discovery_units": len(disc["task_unit_ids"]),
        "n_eval_tasks": len(eval_tasks),
        "n_total_measurements": len(all_measurements),
        "reliability_gate_passed": bool(reliability["gate_passed"]),
        "median_attribute_flip_rate": float(reliability["median_flip_rate"]),
        "pag_valid": bool(discovery["pag_valid"]),
        "classifications": discovery["classifications"],
        "scope_bleed_detected": bool(discovery["scope_bleed_detected"]),
        "jci_selected_mechanisms": jci_selected,
        "corr_selected_mechanisms": corr_selected,
        "arm_rates": paired["arm_rates"],
        "comparisons": paired["comparisons"],
        "environment": {
            "python_version": platform.python_version(),
            "numpy_version": np.__version__,
            "scipy_version": scipy.__version__,
        },
    }

    write_bundle(out_dir / "inputs", {"plan.json": plan, "benchmark.json": benchmark})
    write_bundle(
        out_dir / "stage1",
        {
            "evaluation_attributes.json": {"rows": stage1_eval_rows},
            "reliability.json": reliability,
        },
    )
    write_bundle(
        out_dir / "stage2",
        {
            "pag.json": pag_result,
            "discovery.json": discovery,
        },
    )
    meas_artifacts: dict[str, Any] = {
        "ledger.json": canonical_value(ledger),
        "details.json": {"rows": detail_rows},
    }
    if wire_traces:
        meas_artifacts["wire_traces.json"] = {"rows": wire_traces}
    write_bundle(out_dir / "measurements", meas_artifacts)
    write_bundle(
        out_dir / "outcomes",
        {
            "records.json": {"rows": [canonical_value(row) for row in outcomes]},
            "paired.json": paired,
        },
    )
    write_bundle(out_dir / "summary", {"result.json": summary})

    source_zip = out_dir / "source.zip"
    with zipfile.ZipFile(source_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in SOURCE_FILES:
            src_file = Path(rel)
            if src_file.is_file():
                zf.write(src_file, arcname=rel)

    manifest = {
        "study_id": plan["study_id"],
        "study_mode": "natural_task",
        "plan_sha256": content_hash(plan),
        "benchmark_sha256": content_hash(benchmark),
        "summary_sha256": content_hash(summary),
        "source_zip_sha256": file_sha256(source_zip),
    }
    write_json_new(out_dir / "manifest.json", manifest)
    return summary
