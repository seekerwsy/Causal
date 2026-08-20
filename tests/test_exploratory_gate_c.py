import hashlib
import json
from pathlib import Path

import pytest

from secaware.config import load_config
from secaware.exploratory import gate_c
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.intervention.append_boundary import (
    PYTHON_COMMENT_BOUNDARY_POLICY,
    python_parse_preservation,
    render_append_boundary,
)
from secaware.io.jsonl import read_jsonl
from secaware.schema.records import PromptRecord

_ROOT = Path(__file__).resolve().parents[1]


def test_gate_c_oracle_decision_modes_are_explicit_and_mutually_exclusive() -> None:
    assert (
        gate_c._oracle_decision_mode({"oracle_zero_finding_policy": "preserve_unknown_coverage"})
        == "preserve_unknown_coverage"
    )
    assert (
        gate_c._oracle_decision_mode({"oracle_decision_policy": "profile_scoped_decision"})
        == "profile_scoped_decision"
    )
    with pytest.raises(ValueError, match="Oracle decision policy"):
        gate_c._oracle_decision_mode(
            {
                "oracle_zero_finding_policy": "preserve_unknown_coverage",
                "oracle_decision_policy": "profile_scoped_decision",
            }
        )


def test_gate_c_cross_model_mapping_policy_is_explicit_and_bounded() -> None:
    assert gate_c._gate_b_mapping_policy({}) == "exact_variant_id_v1"
    assert (
        gate_c._gate_b_mapping_policy(
            {"gate_b_variant_mapping_policy": "task_arm_target_feature_v1"}
        )
        == "task_arm_target_feature_v1"
    )
    with pytest.raises(ValueError, match="mapping policy"):
        gate_c._gate_b_mapping_policy({"gate_b_variant_mapping_policy": "task_arm_only"})


def test_gate_c_direct_gate_b_schema_is_explicit_and_bounded() -> None:
    assert gate_c._gate_b_artifact_schema({}) == "revalidation_v1"
    assert (
        gate_c._gate_b_artifact_schema({"gate_b_artifact_schema": "direct_exploratory_v1"})
        == "direct_exploratory_v1"
    )
    with pytest.raises(ValueError, match="artifact schema"):
        gate_c._gate_b_artifact_schema({"gate_b_artifact_schema": "auto_detect"})


def test_gate_c_task_selection_distinguishes_canary_from_frozen_full_population() -> None:
    canary = ["task-a", "task-b"]
    assert gate_c._selected_task_ids({"selected_task_ids": canary}) == (
        "explicit_bounded_canary",
        tuple(canary),
    )
    full = [f"task-{index:02d}" for index in range(51)]
    assert gate_c._selected_task_ids(
        {
            "task_selection_policy": "all_gate_b_tasks",
            "selected_task_ids": full,
        }
    ) == ("all_gate_b_tasks", tuple(full))

    held_out = [f"confirm-task-{index:02d}" for index in range(42)]
    assert gate_c._selected_task_ids(
        {
            "task_selection_policy": "all_gate_b_tasks",
            "selected_task_ids": held_out,
        }
    ) == ("all_gate_b_tasks", tuple(held_out))

    development = [f"dev-task-{index:02d}" for index in range(12)]
    assert gate_c._selected_task_ids(
        {
            "task_selection_policy": "explicit_dev_canary",
            "selected_task_ids": development,
        }
    ) == ("explicit_dev_canary", tuple(development))

    with pytest.raises(ValueError, match="task selection"):
        gate_c._selected_task_ids(
            {
                "task_selection_policy": "all_gate_b_tasks",
                "selected_task_ids": full[:-1],
            }
        )


def test_gate_c_two_arm_protocol_is_strictly_development_only() -> None:
    development = {
        "task_selection_policy": "explicit_dev_canary",
        "arm_roles": ["target_patch", "noop_rewrite"],
    }
    assert gate_c._arm_roles(development, task_selection_policy="explicit_dev_canary") == (
        gate_c.ArmRole.TARGET_PATCH,
        gate_c.ArmRole.NOOP_REWRITE,
    )
    assert (
        gate_c._arm_roles({}, task_selection_policy="explicit_bounded_canary")
        == gate_c._LEGACY_ARMS
    )

    with pytest.raises(ValueError, match="restricted to the development canary"):
        gate_c._arm_roles(development, task_selection_policy="explicit_bounded_canary")
    with pytest.raises(ValueError, match="requires the frozen two-arm protocol"):
        gate_c._arm_roles({}, task_selection_policy="explicit_dev_canary")
    with pytest.raises(ValueError, match="arm roles"):
        gate_c._arm_roles(
            {"arm_roles": ["target_patch", "generic_security_reminder"]},
            task_selection_policy="explicit_dev_canary",
        )


def test_gate_c_direct_adapter_authenticates_append_suffix_envelope() -> None:
    source = PromptRecord.model_validate(
        {
            "prompt_id": "prompt-1",
            "task_id": "task-1",
            "split": "discover",
            "language": "python",
            "task_family": "sql_query",
            "cwe": "CWE-89",
            "prompt": "Write a query function.",
            "prompt_role": "neutral_baseline",
        }
    )
    assert (
        gate_c._direct_candidate_text(
            source=source,
            variant={"intervention_output_mode": "append_suffix_v1"},
            request={"intervention_output_mode": "append_suffix_v1"},
            response={"append_suffix": " Use parameterized queries."},
        )
        == "Write a query function. Use parameterized queries."
    )


def test_gate_c_rebuilds_and_authenticates_python_comment_boundary() -> None:
    source = PromptRecord.model_validate(
        {
            "prompt_id": "prompt-1",
            "task_id": "task-1",
            "split": "discover",
            "language": "python",
            "task_family": "sql_query",
            "cwe": "CWE-89",
            "prompt": "def remove_user(username):\n    '''Remove the named user.'''",
            "prompt_role": "neutral_baseline",
        }
    )
    suffix = " Use parameterized queries."
    rendered = render_append_boundary(
        source.prompt,
        suffix,
        policy=PYTHON_COMMENT_BOUNDARY_POLICY,
    )
    parse_check = python_parse_preservation(source.prompt, rendered.candidate_text)
    variant = {
        "intervention_output_mode": "append_suffix_v1",
        **rendered.metadata(),
        **parse_check.metadata(),
    }

    assert (
        gate_c._direct_candidate_text(
            source=source,
            variant=variant,
            request={"intervention_output_mode": "append_suffix_v1"},
            response={"append_suffix": suffix},
        )
        == rendered.candidate_text
    )
    assert (
        gate_c._direct_candidate_text(
            source=source,
            variant={**variant, "rendered_append_sha256": "0" * 64},
            request={"intervention_output_mode": "append_suffix_v1"},
            response={"append_suffix": suffix},
        )
        is None
    )


def test_gate_c_fresh_graph_binding_rejects_an_old_prompt_interpretation() -> None:
    prompt = PromptRecord.model_validate(
        {
            "prompt_id": "variant-prompt-1",
            "task_id": "task-1",
            "split": "confirm",
            "language": "python",
            "task_family": "sql_query",
            "cwe": "CWE-89",
            "prompt": "value = 1\n\n# Use parameters.",
            "prompt_role": "neutral_baseline",
        }
    )
    variant = {
        "proposal_id": "proposal-1",
        "graph_sha256": "a" * 64,
        "extractor_policy_sha256": "b" * 64,
    }
    proposal = {
        "proposal_id": "proposal-1",
        "prompt_id": prompt.prompt_id,
        "prompt_sha256": prompt.prompt_sha256,
        "task_id": "blind-task-1",
        "policy_sha256": "b" * 64,
    }
    graph = {
        "graph_sha256": "a" * 64,
        "prompt_id": prompt.prompt_id,
        "task_id": "blind-task-1",
        "proposal_id": "proposal-1",
        "extractor_policy_sha256": "b" * 64,
    }

    assert gate_c._prompt_graph_binding_is_authenticated(
        variant=variant,
        prompt=prompt,
        proposal=proposal,
        graph=graph,
    )
    assert not gate_c._prompt_graph_binding_is_authenticated(
        variant=variant,
        prompt=prompt,
        proposal={**proposal, "prompt_sha256": "c" * 64},
        graph=graph,
    )


def test_gate_c_fresh_graph_index_allows_equal_semantic_hashes_for_distinct_proposals() -> None:
    shared_graph_sha256 = "a" * 64
    graphs = (
        {
            "proposal_id": "proposal-1",
            "prompt_id": "prompt-1",
            "graph_sha256": shared_graph_sha256,
        },
        {
            "proposal_id": "proposal-2",
            "prompt_id": "prompt-2",
            "graph_sha256": shared_graph_sha256,
        },
    )

    indexed = gate_c._fresh_graphs_by_proposal_id(graphs)

    assert indexed == {
        "proposal-1": graphs[0],
        "proposal-2": graphs[1],
    }
    with pytest.raises(ValueError, match="fresh graph coverage"):
        gate_c._fresh_graphs_by_proposal_id((graphs[0], {**graphs[1], "proposal_id": "proposal-1"}))


def test_gate_c_authenticates_source_reuse_only_when_every_variant_was_fresh() -> None:
    variant_ids = frozenset({"gate-a-1", "gate-a-2"})
    reuse = {
        "extractor_reuse_policy": "source_exact_reuse_variant_fresh_v1",
        "excluded_extractor_labels": ["variant-gate-a-1", "variant-gate-a-2"],
        "observed_extractor_exclusion_labels": [
            "variant-gate-a-1",
            "variant-gate-a-2",
        ],
    }
    counts = {
        "source_extractions": 1,
        "reused_extractor_calls": 1,
        "provider_extractor_calls": 2,
    }

    assert gate_c._fresh_variant_extractor_reuse_is_authenticated(
        reuse=reuse,
        counts=counts,
        variant_ids=variant_ids,
    )
    assert not gate_c._fresh_variant_extractor_reuse_is_authenticated(
        reuse={
            **reuse,
            "observed_extractor_exclusion_labels": ["variant-gate-a-1"],
        },
        counts=counts,
        variant_ids=variant_ids,
    )
    assert not gate_c._fresh_variant_extractor_reuse_is_authenticated(
        reuse={"extractor_reuse_policy": "exact_request_response_reuse_v1"},
        counts=counts,
        variant_ids=variant_ids,
    )
    assert gate_c._fresh_variant_extractor_reuse_is_authenticated(
        reuse={"extractor_reuse_policy": "fresh_only_v1"},
        counts={
            "source_extractions": 1,
            "reused_extractor_calls": 0,
            "provider_extractor_calls": 3,
        },
        variant_ids=variant_ids,
    )


@pytest.mark.parametrize(
    ("request_payload", "response_payload"),
    (
        ({}, {"append_suffix": " Use parameters."}),
        (
            {"intervention_output_mode": "append_suffix_v1"},
            {"append_suffix": " Use parameters.", "candidate_text": "unexpected"},
        ),
        (
            {"intervention_output_mode": "append_suffix_v1"},
            {"append_suffix": "Write a query function. Use parameters."},
        ),
    ),
)
def test_gate_c_direct_adapter_rejects_unbound_append_suffix_envelopes(
    request_payload: dict[str, object],
    response_payload: dict[str, object],
) -> None:
    source = PromptRecord.model_validate(
        {
            "prompt_id": "prompt-1",
            "task_id": "task-1",
            "split": "discover",
            "language": "python",
            "task_family": "sql_query",
            "cwe": "CWE-89",
            "prompt": "Write a query function.",
            "prompt_role": "neutral_baseline",
        }
    )
    assert (
        gate_c._direct_candidate_text(
            source=source,
            variant={"intervention_output_mode": "append_suffix_v1"},
            request=request_payload,
            response=response_payload,
        )
        is None
    )


def test_gate_c_direct_upstream_manifest_requires_closed_file_set(tmp_path: Path) -> None:
    upstream = tmp_path / "gate-b"
    upstream.mkdir()
    payload = b'{"status":"GATE_B_PASSED"}\n'
    (upstream / "report.json").write_bytes(payload)
    (upstream / "artifact-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "files": [
                    {
                        "path": "report.json",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    gate_c._verify_closed_manifest(upstream)
    (upstream / "unlisted.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="closure"):
        gate_c._verify_closed_manifest(upstream)


def test_gate_c_functional_contracts_are_frozen_before_generation() -> None:
    bundle = _ROOT / "data/e2e-pilot/gate-c-cwe78-cwe89-v1"
    contracts = tuple(
        read_jsonl(
            bundle / "task-functional-contracts.jsonl",
            TaskFunctionalContractRecord,
            required=True,
            allow_empty=False,
        )
    )
    assert {item.task_id for item in contracts} == {
        "cluster-22d97b466b5d2c737129",
        "cluster-b80c034159e718b8bbc9",
    }
    assert all(item.audit_pass_ids == ("A", "B") for item in contracts)
    assert all(item.audit_status.value == "consistent" for item in contracts)
    assert all(item.requirements for item in contracts)


def test_gate_c_config_freezes_exact_single_attempt_provider_budgets() -> None:
    config = load_config(_ROOT / "configs/e2e-pilot/gate-c-qwen25-coder-32b-bailian-v1.yaml")
    assert config.generation.models == ["qwen2.5-coder-32b-instruct"]
    assert config.generation.confirmation_seeds == [
        2026081511,
        2026081512,
        2026081513,
        2026081514,
    ]
    assert config.generation.confirmation_max_requests == 8
    assert config.generation.confirmation_max_total_provider_attempts == 8
    assert config.generation.openai_compatible is not None
    assert config.generation.openai_compatible.max_attempts == 1
    assert config.functional_judge.enabled is True
    assert config.functional_judge.mode == "single_pass"
    assert config.functional_judge.llm is not None
    assert config.functional_judge.llm.max_attempts == 1


def test_gate_c_five_cwe_plan_freezes_twenty_single_attempt_units() -> None:
    config = load_config(
        _ROOT / "configs/e2e-pilot/gate-c-five-cwe-qwen25-coder-7b-bailian-v1.yaml"
    )
    gate = json.loads(
        (_ROOT / "configs/e2e-pilot/gate-c-five-cwe-qwen25-coder-7b-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert gate["gate_b_artifact_schema"] == "direct_exploratory_v1"
    assert len(gate["selected_task_ids"]) == 5
    assert gate["expected_assignments"] == 20
    assert config.generation.models == ["qwen2.5-coder-7b-instruct"]
    assert config.generation.confirmation_max_requests == 20
    assert config.generation.confirmation_max_total_provider_attempts == 20
    assert config.functional_judge.mode == "single_pass"
    assert config.functional_judge.llm is not None
    assert config.functional_judge.llm.max_attempts == 1


@pytest.mark.parametrize(
    ("config_name", "gate_name", "model_id"),
    (
        (
            "gate-c-main-prompt-canary-qwen25-coder-7b-bailian-v1.yaml",
            "gate-c-main-prompt-canary-qwen25-coder-7b-v1.json",
            "qwen2.5-coder-7b-instruct",
        ),
        (
            "gate-c-main-prompt-canary-phi4-14b-bailian-v1.yaml",
            "gate-c-main-prompt-canary-phi4-14b-v1.json",
            "phi-4-14b",
        ),
    ),
)
def test_gate_c_main_prompt_canaries_freeze_separate_twenty_unit_strata(
    config_name: str,
    gate_name: str,
    model_id: str,
) -> None:
    config = load_config(_ROOT / "configs/e2e-pilot" / config_name)
    gate = json.loads((_ROOT / "configs/e2e-pilot" / gate_name).read_text(encoding="utf-8"))
    assert gate["gate_b_artifact_schema"] == "direct_exploratory_v1"
    assert gate["expected_assignments"] == 20
    assert gate["scientific_claim_allowed"] is False
    assert gate["scale_up_allowed"] is False
    assert config.generation.models == [model_id]
    assert config.generation.confirmation_seeds == [
        2026081831,
        2026081832,
        2026081833,
        2026081834,
    ]
    assert config.generation.confirmation_max_requests == 20
    assert config.generation.confirmation_max_total_provider_attempts == 20
    assert config.functional_judge.llm is not None
    assert config.functional_judge.llm.max_attempts == 1


@pytest.mark.parametrize(
    ("config_name", "model_id"),
    (
        ("gate-c-qwen25-coder-7b-bailian-v1.yaml", "qwen2.5-coder-7b-instruct"),
        ("gate-c-phi4-14b-bailian-v1.yaml", "phi-4-14b"),
    ),
)
def test_gate_c_scale_canaries_freeze_separate_model_strata(
    config_name: str,
    model_id: str,
) -> None:
    config = load_config(_ROOT / "configs/e2e-pilot" / config_name)
    assert config.generation.models == [model_id]
    assert config.generation.openai_compatible is not None
    assert config.generation.openai_compatible.base_url == "http://127.0.0.1:18101/v1"
    assert config.generation.openai_compatible.max_attempts == 1
    assert config.generation.confirmation_max_requests == 8
    assert config.generation.confirmation_max_total_provider_attempts == 8
    assert config.functional_judge.llm is not None
    assert config.functional_judge.llm.max_attempts == 1


@pytest.mark.parametrize(
    ("model_suffix", "model_id"),
    (
        ("qwen7b", "qwen2.5-coder-7b-instruct"),
        ("phi14b", "phi-4-14b"),
    ),
)
def test_randomized_discovery_main_gate_c_freezes_full_separate_model_strata(
    model_suffix: str,
    model_id: str,
) -> None:
    gate = json.loads(
        (
            _ROOT / "configs/e2e-pilot" / f"randomized-discovery-gate-c-main-{model_suffix}-v1.json"
        ).read_text(encoding="utf-8")
    )
    config = load_config(
        _ROOT
        / "configs/e2e-pilot"
        / f"randomized-discovery-gate-c-main-{model_suffix}-bailian-v1.yaml"
    )
    live = json.loads(
        (
            _ROOT
            / "configs/e2e-pilot"
            / f"randomized-discovery-gate-c-main-live-{model_suffix}-v1.json"
        ).read_text(encoding="utf-8")
    )
    remaining = json.loads(
        (
            _ROOT
            / "configs/e2e-pilot"
            / f"randomized-discovery-gate-c-main-live-{model_suffix}-remaining-v1.json"
        ).read_text(encoding="utf-8")
    )

    assert gate["task_selection_policy"] == "all_gate_b_tasks"
    assert len(gate["selected_task_ids"]) == 51
    assert gate["expected_assignments"] == 204
    assert config.generation.models == [model_id]
    assert config.generation.confirmation_seeds == [
        2026081841,
        2026081842,
        2026081843,
        2026081844,
    ]
    assert config.generation.confirmation_max_requests == 204
    assert config.generation.confirmation_max_total_provider_attempts == 204
    assert config.randomization.max_blocks == 51
    assert live["task_selection_policy"] == "all_gate_b_tasks"
    assert live["scale_up_allowed"] is False
    assert remaining["scale_up_allowed"] is True
    assert remaining["scale_up_authorization_scope"] == "remaining_assignments_only"
    assert config.functional_judge.llm is not None
    assert config.functional_judge.llm.max_attempts == 1


def test_gate_c_scale_canaries_reuse_frozen_texts_but_not_model_assignments() -> None:
    configs = []
    for name in (
        "gate-c-canary-qwen25-coder-7b-v1.json",
        "gate-c-canary-phi4-14b-v1.json",
    ):
        configs.append(json.loads((_ROOT / "configs/e2e-pilot" / name).read_text(encoding="utf-8")))
    assert {item["gate_b_dir"] for item in configs} == {
        "runs/e2e-pilot/gate-b-extractor-revalidation-v1-live-20260815-01"
    }
    assert len({item["gate_a_dir"] for item in configs}) == 2
    assert all(item["expected_assignments"] == 8 for item in configs)
    assert all(item["scientific_claim_allowed"] is False for item in configs)
    assert all(item["scale_up_allowed"] is False for item in configs)
