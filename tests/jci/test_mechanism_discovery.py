"""Scientific invariant tests for Stage I TSG interventions & Stage II JCI mechanism discovery."""

from copy import deepcopy
from pathlib import Path
import shutil

import numpy as np
import pytest

from prompt_mechanism_study.artifact_io import read_json, write_bundle, write_json_new
from prompt_mechanism_study.cli import main as cli_main
from prompt_mechanism_study.discovery.jci_structure import (
    ConditionalPermutation,
    discover_jci_pag,
)
from prompt_mechanism_study.discovery.mechanism_discovery import (
    classify_jci_mechanisms,
    evaluate_paired_counterfactuals,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.tsg.prompt_contract import (
    compile_source_propositions,
    resolve_evidence_span,
)
from prompt_mechanism_study.tsg.prompt_tsg import PromptTSGError
from prompt_mechanism_study.tsg.scoped_intervention import render_prompt_intervention
from prompt_mechanism_study.verification.mechanism_discovery import verify_mechanism_study


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))


def test_sink_vars_separates_causal_driver_from_latent_and_env_proxies():
    rng = np.random.default_rng(2026111601)
    n = 600
    c_env = rng.binomial(1, 0.5, size=n)
    i_cau = rng.binomial(1, 0.3, size=n)
    i_lat = rng.binomial(1, 0.3, size=n)
    u = rng.binomial(1, 0.5, size=n)

    z_env = rng.binomial(1, _sigmoid(-1.8 + 3.6 * c_env))
    z_cau = rng.binomial(1, _sigmoid(-1.8 + 3.6 * i_cau))
    z_lat = rng.binomial(1, _sigmoid(-2.0 + 3.8 * u + 3.4 * i_lat))
    y_sec = rng.binomial(1, _sigmoid(-2.2 + 2.0 * c_env + 3.2 * u + 2.4 * z_cau))

    labels = ["C_env", "I_cau", "I_lat", "Z_env", "Z_cau", "Z_lat", "Y_sec"]
    data = np.column_stack([c_env, i_cau, i_lat, z_env, z_cau, z_lat, y_sec])
    ci = ConditionalPermutation(data, labels, draws=199, seed=42)
    pag_res = discover_jci_pag(
        labels,
        ci,
        0.05,
        context_vars=["C_env", "I_cau", "I_lat"],
        sink_vars=["Y_sec"],
        max_order=2,
        on_insufficient_ci="conservative",
    )
    pag = np.asarray(pag_res["pag"])
    idx = {name: i for i, name in enumerate(labels)}

    # Causal driver Z_cau -> Y_sec oriented via Zhang R1 (tail=3 at Z_cau, arrowhead=2 at Y_sec).
    assert pag[idx["Z_cau"], idx["Y_sec"]] == 2
    assert pag[idx["Y_sec"], idx["Z_cau"]] == 3
    # Latent confounder I_lat -> Z_lat <-> Y_sec oriented as bidirected collider.
    assert pag[idx["Z_lat"], idx["Y_sec"]] == 2
    assert pag[idx["Y_sec"], idx["Z_lat"]] == 2
    # Environment proxy Z_env d-separated from Y_sec given C_env.
    assert pag[idx["Z_env"], idx["Y_sec"]] == 0

    disc = classify_jci_mechanisms(
        pag_res,
        data=data,
        labels=labels,
        context_vars=["C_env", "I_cau", "I_lat"],
        probe_map={"Z_cau": "I_cau", "Z_lat": "I_lat"},
        mechanism_vars=["Z_env", "Z_cau", "Z_lat"],
        security_sink="Y_sec",
        functional_sink="Y_sec",
    )
    assert disc["classifications"]["Z_cau"] == "causal_security_driver"
    assert disc["classifications"]["Z_lat"] == "latent_confounded_proxy"
    assert disc["classifications"]["Z_env"] == "environment_confounded_proxy"
    assert disc["jci_policy"]["selected_mechanisms"] == ["Z_cau"]


def test_tolerant_prompt_tsg_grounding_and_scoped_intervention_rendering():
    prompt = (
        "Implement `run_sql(conn, req)` using `req['role']` and preserve `format_tag(req)` "
        "returning raw `'TAG:' + req['role']`."
    )
    assert resolve_evidence_span(prompt, "  run_sql(conn,   req) ") is not None
    assert resolve_evidence_span(prompt, "totally missing quote") is None

    record = {
        "task_unit_id": "t_tol_01",
        "concepts": {
            "op_sql": {"node_type": "task_operation", "meaning": "Target SQL op."},
            "op_fmt": {"node_type": "task_operation", "meaning": "Sibling format op."},
            "req_obj": {"node_type": "data_object", "meaning": "Shared req mapping."},
            "req_role": {"node_type": "data_object", "meaning": "Role field."},
            "fmt_rule": {"node_type": "presentation_control", "meaning": "Verbatim tag."},
            "missing_hint": {"node_type": "constraint", "meaning": "Unanchorable note."},
        },
        "facts": [
            {
                "local_id": "op_sql",
                "node_type": "task_operation",
                "semantic_id": "op_sql",
                "evidence_text": "  `run_sql(conn,   req)` ",
                "occurrence": 1,
                "attributes": {"binding_complete": True},
            },
            {
                "local_id": "op_fmt",
                "node_type": "task_operation",
                "semantic_id": "op_fmt",
                "evidence_text": "`format_tag(req)`",
                "occurrence": 1,
                "attributes": {"binding_complete": True},
            },
            {
                "local_id": "req_obj",
                "node_type": "data_object",
                "semantic_id": "req_obj",
                "evidence_text": "`format_tag(req)`",
                "occurrence": 1,
                "attributes": {"binding_complete": True},
            },
            {
                "local_id": "req_role",
                "node_type": "data_object",
                "semantic_id": "req_role",
                "evidence_text": "`req['role']`",
                "occurrence": 1,
                "attributes": {"binding_complete": True},
            },
            {
                "local_id": "fmt_rule",
                "node_type": "presentation_control",
                "semantic_id": "fmt_rule",
                "evidence_text": "returning raw `'TAG:' + req['role']`",
                "occurrence": 1,
                "attributes": {"binding_complete": True, "normative_force": True},
            },
            {
                "local_id": "missing_hint",
                "node_type": "constraint",
                "semantic_id": "missing_hint",
                "evidence_text": "nonexistent text absent from prompt",
                "occurrence": 1,
                "attributes": {"binding_complete": False, "normative_force": True},
            },
        ],
        "relations": [
            {"source": "req_role", "target": "req_obj", "edge_type": "part_of"},
            {"source": "req_obj", "target": "op_sql", "edge_type": "used_by"},
            {"source": "req_obj", "target": "op_fmt", "edge_type": "used_by"},
            {"source": "fmt_rule", "target": "op_fmt", "edge_type": "about_operation"},
            {"source": "missing_hint", "target": "op_fmt", "edge_type": "about_operation"},
        ],
        "unresolved_semantics": [],
        "unresolved_relations": [],
        "requirement_structures": {
            "fmt_rule": {"kind": "atom", "members": []},
            "missing_hint": {"kind": "atom", "members": []},
        },
        "requirement_scopes": {},
        "requirement_relations": {},
    }
    task = {"task_unit_id": "t_tol_01", "prompt": prompt}

    with pytest.raises(PromptTSGError):
        compile_source_propositions(task, deepcopy(record), extractor_id="strict-test", tolerant=False)

    graph, compiled = compile_source_propositions(task, record, extractor_id="tolerant-test", tolerant=True)
    assert "missing_hint" in compiled["degraded_local_ids"]
    assert "missing_hint" in graph.unresolved_semantics
    assert ("missing_hint", "about_operation", "op_fmt") in graph.unresolved_relations

    mechs = [
        {
            "mechanism_id": "Z_cau",
            "instruction": "Parameterize SQL queries with `?` placeholders",
            "operation_local_id": "op_sql",
            "subject_local_ids": ["req_role"],
        }
    ]
    base = render_prompt_intervention(prompt, mode="baseline", mechanisms=mechs, graph=graph, local_node_ids=compiled["local_node_ids"])
    flat = render_prompt_intervention(prompt, mode="flat", mechanisms=mechs, graph=graph, local_node_ids=compiled["local_node_ids"])
    scoped = render_prompt_intervention(prompt, mode="tsg_scoped", mechanisms=mechs, graph=graph, local_node_ids=compiled["local_node_ids"])

    assert base["rendered_prompt"] == prompt and base["applied_mechanisms"] == []
    assert "Apply uniformly across the entire module" in flat["rendered_prompt"]
    assert "req_role ->(part_of)-> req_obj" in scoped["rendered_prompt"]
    assert "op_fmt" in scoped["rendered_prompt"] and "returning raw" in scoped["rendered_prompt"]
    assert scoped["protected_siblings"][0]["operation_local_id"] == "op_fmt"


def test_paired_counterfactual_variance_reduction():
    # Correlated task baselines: paired SE must be strictly smaller than unpaired SE equivalent.
    rows = []
    for i in range(20):
        base_ok = 1 if i % 2 == 0 else 0
        rows.append(
            {
                "baseline": {"code_valid": 1, "oracle_evaluable": 1, "secure_yield": base_ok, "functionality": 1, "joint": base_ok},
                "corr_tsg": {"code_valid": 1, "oracle_evaluable": 1, "secure_yield": base_ok, "functionality": 1, "joint": base_ok},
                "jci_flat": {"code_valid": 1, "oracle_evaluable": 1, "secure_yield": 1, "functionality": 0, "joint": 0},
                "jci_tsg": {"code_valid": 1, "oracle_evaluable": 1, "secure_yield": 1, "functionality": 1, "joint": 1},
            }
        )
    res = evaluate_paired_counterfactuals(rows)
    comp = next(c for c in res["comparisons"] if c["id"] == "jci_tsg_vs_baseline")
    assert comp["estimate"] == pytest.approx(0.5)
    assert comp["se"] < comp["unpaired_se_equivalent"]
    assert comp["pairing_variance_reduction"] > 0.0
    assert comp["significant_positive"] is True


def test_mechanism_smoke_cli_and_tamper_rejection(tmp_path):
    out_dir = tmp_path / "mech-smoke"
    assert cli_main(["study", "smoke", str(out_dir), "--workers", "2"]) == 0
    assert cli_main(["study", "verify", str(out_dir), "--workers", "2"]) == 0

    summary = read_json(out_dir / "summary" / "result.json")
    assert summary["verdict"]["overall_passed"] is True
    assert summary["scenario_summaries"]["null_spurious_only"]["jci_false_discovery_cells"] == 0

    # Forged summary (even if re-hashed cleanly into bundle & manifest) must be rejected by independent replay.
    forged = deepcopy(summary)
    forged["verdict"]["overall_passed"] = False
    shutil.rmtree(out_dir / "summary")
    write_bundle(out_dir / "summary", {"result.json": forged})
    manifest = read_json(out_dir / "manifest.json")
    manifest["summary_sha256"] = content_hash(forged)
    (out_dir / "manifest.json").unlink()
    write_json_new(out_dir / "manifest.json", manifest)
    with pytest.raises(ValueError, match="verdict mismatch"):
        verify_mechanism_study(out_dir, workers=1)
