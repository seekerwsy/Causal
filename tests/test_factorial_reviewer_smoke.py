import copy
import json
import re
import socket
from collections import Counter
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.factorial_experiment import (
    freeze_factorial_experiment,
    preflight_factorial_experiment,
    run_factorial_experiment,
)
from prompt_mechanism_study.factorial_freeze import verify_factorial_freeze_bundle
from prompt_mechanism_study.factorial_protocol import FactorialExperimentError
from prompt_mechanism_study.factorial_verify import verify_factorial_result_bundle
from prompt_mechanism_study.security_profiles import evaluate_security_profile


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/reviewer/factorial-schema11-offline-smoke-v1.json"
OFFLINE_MODEL_ID = "factorial-offline-reviewer-smoke-v1"
OFFLINE_PROVIDER = "offline_deterministic_test_fixture"


def _complete_prompt_rewrites(request: dict) -> dict:
    source = request["source_prompt"]
    source_graph = request["source_prompt_tsg"]
    source_nodes = [
        item for item in source_graph["nodes"] if item["semantic_id"] != "task.root"
    ]
    local_by_node = {
        item["node_id"]: f"source_{index}"
        for index, item in enumerate(source_nodes)
    }
    base_facts = [
        {
            "local_id": local_by_node[item["node_id"]],
            "node_type": item["node_type"],
            "semantic_id": item["semantic_id"],
            "evidence_text": source[item["evidence_start"] : item["evidence_end"]],
            "occurrence": 1,
            "attributes": dict(item["attributes"]),
        }
        for item in source_nodes
    ]
    base_relations = [
        {
            "edge_type": item["edge_type"],
            "source": local_by_node[item["source_id"]],
            "target": local_by_node[item["target_id"]],
        }
        for item in source_graph["edges"]
        if item["source_id"] in local_by_node
        and item["target_id"] in local_by_node
    ]
    states = {
        "a00": (False, False),
        "a10": (True, False),
        "a01": (False, True),
        "a11": (True, True),
    }
    result = {}
    for cell, state in states.items():
        selected = {
            1: request["factor_1"]["target" if state[0] else "noop"],
            2: request["factor_2"]["target" if state[1] else "noop"],
        }
        ordered = [selected[index] for index in request["application_order"]]
        suffix = (
            f"Reviewer-smoke cell {cell}; application order "
            f"{' then '.join(str(item) for item in request['application_order'])}. "
            + " ".join(ordered)
        )
        prompt = source.rstrip() + "\n\n" + suffix
        facts = copy.deepcopy(base_facts)
        for index, present in enumerate(state, start=1):
            if present:
                facts.append(
                    {
                        "local_id": f"factor_{index}",
                        "node_type": "safety_requirement",
                        "semantic_id": request["factor_ids"][index - 1],
                        "evidence_text": request[f"factor_{index}"]["target"],
                        "occurrence": 1,
                        "attributes": {},
                    }
                )
        result[cell] = {
            "prompt_text": prompt,
            "facts": facts,
            "relations": copy.deepcopy(base_relations),
            "unresolved_semantics": [],
        }
    return result


def _validation_response() -> dict:
    cell = {
        "task_preserved": True,
        "factor_1_state_correct": True,
        "factor_2_state_correct": True,
        "unintended_change_absent": True,
        "contradiction_absent": True,
    }
    return {
        **{name: dict(cell) for name in ("a00", "a10", "a01", "a11")},
        "cross_cell": {
            "functional_contract_preserved": True,
            "pair_context_preserved": True,
            "non_target_security_preserved": True,
            "presentation_policy_preserved": True,
            "no_third_requirement": True,
            "treatment_states_distinct": True,
        },
        "reason": "Deterministic reviewer fixture preserves the two frozen source tasks.",
    }


def _starter_code(prompt: str) -> str:
    match = re.search(
        r"Supplied implementation:\s*```python\s*(.*?)\s*```",
        prompt,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError("reviewer-smoke prompt lost its supplied implementation")
    return match.group(1).strip() + "\n"


@pytest.mark.milestone
def test_schema11_zero_network_reviewer_smoke(tmp_path: Path, monkeypatch) -> None:
    """Exercise the active 16-assignment path without producing effect evidence."""

    gold_cases = read_json(
        ROOT / "data/oracle-calibration/factorial-sql-v2-cases.json"
    )
    assert {
        item["cell"] for item in gold_cases
    } == {"a00", "a10", "a01", "a11"}
    assert all(
        evaluate_security_profile(item["code"], item["profile_id"])[
            "security_label"
        ]
        == item["expected_label"]
        for item in gold_cases
    )

    transport_kinds: list[str] = []

    def offline_complete(request: dict, evaluator: dict, _prompt: str) -> bytes:
        assert evaluator["provider"] == OFFLINE_PROVIDER
        assert evaluator["base_url"] == "https://offline.invalid/v1"
        assert evaluator["model_id"] == OFFLINE_MODEL_ID
        kind = request["request_kind"]
        transport_kinds.append(kind)
        if kind == "blind_factorial_complete_prompt_rewrite":
            value = _complete_prompt_rewrites(request)
        elif kind == "blind_factorial_prompt_validation":
            value = _validation_response()
        elif kind == "factorial_code_generation":
            # Returning the supplied vulnerable starter in every cell avoids
            # manufacturing a synthetic intervention effect for this smoke.
            value = {"code": _starter_code(request["task_prompt"])}
        elif kind == "blind_functional_evaluation":
            value = {
                "verdict": "pass",
                "evidence_lines": [1],
                "reason": "Offline response-schema fixture; not a semantic-accuracy claim.",
            }
        else:
            raise AssertionError(f"unexpected provider request: {kind}")
        return json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")

    def reject_network(*_args, **_kwargs):
        raise AssertionError("reviewer smoke attempted a real network connection")

    monkeypatch.setenv(
        "PROMPT_MECHANISM_STUDY_OFFLINE_FIXTURE_KEY", "offline-test-only"
    )
    monkeypatch.setattr(socket, "create_connection", reject_network)
    monkeypatch.setattr(
        "prompt_mechanism_study.factorial_experiment.bailian_complete",
        offline_complete,
    )

    freeze_root = tmp_path / "freeze"
    result_root = tmp_path / "result"
    claim_config = read_json(CONFIG)
    claim_config["phase"] = "confirmatory"
    claim_config["scientific_claim_allowed"] = True
    claim_config_path = tmp_path / "forbidden-claim-config.json"
    claim_config_path.write_text(
        json.dumps(claim_config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        FactorialExperimentError,
        match="structural-smoke-only functional qualification is not allowed",
    ):
        preflight_factorial_experiment(ROOT, claim_config_path)

    preflight = preflight_factorial_experiment(ROOT, CONFIG)
    frozen = freeze_factorial_experiment(ROOT, CONFIG, freeze_root)
    freeze_verification = verify_factorial_freeze_bundle(freeze_root)

    with pytest.raises(FactorialExperimentError, match="requires --freeze"):
        run_factorial_experiment(ROOT, CONFIG, tmp_path / "unfrozen-result")

    report = run_factorial_experiment(
        ROOT,
        CONFIG,
        result_root,
        freeze_root=freeze_root,
    )
    verified = verify_factorial_result_bundle(result_root)

    assert preflight["assignments"] == 16
    assert preflight["pair_ids"] == [
        "pair_0ae9a326b9bab7999154309964bbd9d945c51e857cd1642063ad71cce75bc390"
    ]
    assert preflight["models"] == [OFFLINE_MODEL_ID]
    assert frozen["assignments"] == 16
    assert freeze_verification["assignments"] == 16
    assert report["assignments"] == 16
    assert verified["assignments"] == 16
    assert report["tasks"] == 2
    assert report["realizations"] == 2
    assert report["models"] == [OFFLINE_MODEL_ID]
    assert report["scientific_claim_allowed"] is False
    assert report["claim_ready_coordinates"] == []
    assert report["security_interaction_claim_ready_coordinates"] == []
    assert report["practical_success_claim_ready_coordinates"] == []
    assert report["primary_gate"]["functionality_gate_status"] == "not_requested"
    assert report["primary_gate"]["functionality_noninferior"] is None

    calls = read_json(result_root / "provider-calls.json")
    assert Counter(item["stage"] for item in calls) == {
        "intervention": 4,
        "generation": 16,
        "functional": 16,
    }
    assert Counter(transport_kinds) == {
        "blind_factorial_complete_prompt_rewrite": 4,
        "blind_factorial_prompt_validation": 4,
        "factorial_code_generation": 16,
        "blind_functional_evaluation": 16,
    }

    records = read_json(result_root / "measurement-records.json")
    assert len(records) == 16
    assert len({item["measurement"]["assignment_id"] for item in records}) == 16
    assert all(item["measurement"]["code_status"] == "valid" for item in records)
    assert all(item["measurement"]["oracle_status"] == "insecure" for item in records)
    assert all(item["security"]["security_label"] == "insecure" for item in records)
    assert all(item["measurement"]["functional_status"] == "pass" for item in records)

    study = read_json(result_root / "study-freeze.json")
    assignments = study["randomization"]["assignments"]
    block_cells = Counter(
        (
            item["block"]["task_unit_id"],
            item["block"]["joint_realization_id"],
            item["block"]["model_id"],
        )
        for item in assignments
    )
    assert len(block_cells) == 4
    assert set(block_cells.values()) == {4}
