from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parents[1]
HOLDOUT = ROOT / "data" / "functional-judge" / "blind-calibration-v4"
HISTORICAL = ROOT / "data" / "functional-judge" / "blind-calibration-v3"
CONTRACTS = (
    ROOT
    / "data"
    / "e2e-pilot"
    / "five-cwe-held-out-policy-itt-inputs-20260819-02"
    / "task-functional-contracts.jsonl"
)
EXPECTED_HISTORICAL_SHA256 = "8e62c17753dd09c352a89571429aec5ecd4dc2b41280cdaeb8d3835fa9a8dca6"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _code_sha256(code_text: str) -> str:
    return hashlib.sha256(code_text.encode("utf-8")).hexdigest()


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _jsonl(path: Path) -> list[dict[str, object]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert all(type(row) is dict for row in rows)
    return rows


def _load_planner():
    path = ROOT / "scripts" / "plan_functional_judge_calibration.py"
    spec = importlib.util.spec_from_file_location("fresh_holdout_planner", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fresh_holdout_is_balanced_ast_valid_and_planner_compatible() -> None:
    planner = _load_planner()
    spec_path = HOLDOUT / "calibration-spec.json"
    cases_path = HOLDOUT / "validation-cases.jsonl"
    spec, family_specs = planner._load_spec(spec_path)
    rows = planner._load_validation_rows(cases_path, spec, family_specs)

    assert spec["calibration_id"] == "functional-judge-blind-calibration-v4-fresh-holdout"
    assert spec["validation_cases_sha256"] == _sha256(cases_path)
    assert len(rows) == 16
    assert Counter((row["family"], row["expected_status"]) for row in rows) == {
        ("gtf_fasta_append", "pass"): 2,
        ("gtf_fasta_append", "fail"): 2,
        ("pdf_bag_of_words", "pass"): 2,
        ("pdf_bag_of_words", "fail"): 2,
        ("slurm_exit_code", "pass"): 2,
        ("slurm_exit_code", "fail"): 2,
        ("sqlite_metadata", "pass"): 2,
        ("sqlite_metadata", "fail"): 2,
    }
    assert [row["seed_id"] for row in rows] == list(range(95_101, 95_117))
    for row in rows:
        assert ast.parse(str(row["code_text"])).body


def test_fresh_holdout_bindings_close_contract_requirements_and_gold() -> None:
    spec = _json(HOLDOUT / "calibration-spec.json")
    cases = _jsonl(HOLDOUT / "validation-cases.jsonl")
    bindings = _jsonl(HOLDOUT / "case-source-bindings.jsonl")
    policy = _json(HOLDOUT / "holdout-source-policy.json")
    family_specs = {str(row["family"]): row for row in spec["families"]}  # type: ignore[index]
    by_case = {str(row["case_id"]): row for row in bindings}
    basis_ids = {str(row["basis_id"]) for row in policy["source_basis_catalog"]}  # type: ignore[index]

    assert len(by_case) == len(bindings) == len(cases) == 16
    assert [row["selection_rank"] for row in bindings] == list(range(1, 17))
    assert all(row["derivation_rule_id"] == "adapter_contract_projection_v1" for row in bindings)
    for case in cases:
        binding = by_case[str(case["case_id"])]
        family = str(case["family"])
        family_spec = family_specs[family]
        requirement_ids = list(family_spec["functional_requirement_ids"])
        verdicts = binding["gold_requirement_verdicts"]
        assert type(verdicts) is dict
        assert binding["task_id"] == case["task_id"] == family_spec["task_id"]
        assert binding["family"] == family
        assert binding["expected_status"] == case["expected_status"]
        assert binding["functional_contract_id"] == family_spec["functional_contract_id"]
        assert binding["functional_requirement_ids"] == requirement_ids
        assert list(verdicts) == requirement_ids
        derived = "fail" if "not_met" in verdicts.values() else "pass"
        assert derived == case["expected_status"]
        assert binding["code_sha256"] == _code_sha256(str(case["code_text"]))
        assert set(binding["source_basis_ids"]) <= basis_ids

    contract_rows = {
        str(row["task_id"]): row
        for row in _jsonl(CONTRACTS)
        if str(row["task_id"]) in {str(item["task_id"]) for item in spec["families"]}  # type: ignore[index]
    }
    assert len(contract_rows) == 4
    for family_spec in spec["families"]:  # type: ignore[index]
        contract = contract_rows[str(family_spec["task_id"])]
        assert contract["contract_id"] == family_spec["functional_contract_id"]
        assert [row["requirement_id"] for row in contract["requirements"]] == family_spec[
            "functional_requirement_ids"
        ]


def test_fresh_holdout_is_disjoint_from_exposed_historical_validation() -> None:
    fresh = _jsonl(HOLDOUT / "validation-cases.jsonl")
    historical_path = HISTORICAL / "validation-cases.jsonl"
    historical = _jsonl(historical_path)

    assert _sha256(historical_path) == EXPECTED_HISTORICAL_SHA256
    assert {row["case_id"] for row in fresh}.isdisjoint({row["case_id"] for row in historical})
    assert {row["seed_id"] for row in fresh}.isdisjoint({row["seed_id"] for row in historical})
    assert {_code_sha256(str(row["code_text"])) for row in fresh}.isdisjoint(
        {_code_sha256(str(row["code_text"])) for row in historical}
    )


def test_holdout_policy_binds_sources_and_precreation_candidate_cutoff() -> None:
    policy = _json(HOLDOUT / "holdout-source-policy.json")
    active = policy["active_validation"]
    cutoff = policy["candidate_cutoff"]
    audit = policy["contamination_audit"]
    assert type(active) is dict
    assert type(cutoff) is dict
    assert type(audit) is dict

    assert policy["status"] == "FRESH_HOLDOUT_FROZEN_NO_PROVIDER_CALLS"
    assert policy["scientific_claim_allowed"] is False
    assert policy["official_artifact_replacement_allowed"] is False
    assert policy["derivation"] == {
        "case_kind": "static_contract_and_adapter_fixture_projection",
        "gold_aggregate_rule": "fail_if_any_requirement_not_met_else_pass",
        "gold_source": (
            "frozen_task_contract_requirement_closure_plus_preexisting_executable_adapter_"
            "fixture_semantics"
        ),
        "case_text_construction": (
            "codex_static_projection_of_frozen_contract_and_adapter_semantics"
        ),
        "llm_output_conditioned_case_selection": False,
        "runtime_test_reauthored_per_task": False,
        "selection_policy": (
            "In the frozen family sequence gtf_fasta_append, sqlite_metadata, pdf_bag_of_words, "
            "slurm_exit_code, retain exactly the two predeclared all-requirements-met projections "
            "and the two predeclared single-axis or paired-axis adapter counterexample "
            "projections; "
            "order by the frozen selection_rank. No reserve pool, replacement, reranking, or "
            "outcome-conditioned filtering exists."
        ),
        "selection_policy_id": "four_family_two_pass_two_fail_contract_adapter_projection_v1",
    }
    assert audit["model_output_dependent_case_selection"] is False
    assert audit["historical_validation"]["downgraded_role"] == (  # type: ignore[index]
        "exposed_historical_regression_only_not_fresh_validation_not_ranking"
    )
    assert active["validation_cases_sha256"] == _sha256(ROOT / str(active["validation_cases_path"]))
    assert active["case_source_bindings_sha256"] == _sha256(
        ROOT / str(active["case_source_bindings_path"])
    )
    for authority in policy["source_authorities"]:  # type: ignore[index]
        assert authority["sha256"] == _sha256(ROOT / str(authority["path"]))

    assert cutoff["provider_calls_on_fresh_holdout_before_freeze"] == 0
    assert cutoff["candidate_prompt_sha256_before_holdout_creation"] == _sha256(
        ROOT / str(cutoff["candidate_prompt_path"])
    )
    assert cutoff["candidate_config_sha256_before_holdout_creation"] == _sha256(
        ROOT / str(cutoff["candidate_config_path"])
    )
