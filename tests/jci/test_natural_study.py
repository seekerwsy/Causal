"""End-to-end natural-task paired counterfactual study, unit test Oracle, and verifier tests."""

from copy import deepcopy
from pathlib import Path
import shutil

import pytest

from prompt_mechanism_study.artifact_io import read_json, write_bundle, write_json_new
from prompt_mechanism_study.cli import main as cli_main
from prompt_mechanism_study.experiment import natural_study
from prompt_mechanism_study.llm import ProviderError
from prompt_mechanism_study.measurement.security_profiles import evaluate_security_profile
from prompt_mechanism_study.measurement.unit_test_oracle import evaluate_python_unit_tests
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.verification.natural_study import verify_natural_study


def test_target_function_scoped_security_profile():
    scoped_safe_code = (
        "import random, secrets, string\n\n"
        "def issue_invite_code(opts):\n"
        "    alpha = string.ascii_letters + string.digits\n"
        "    return ''.join(secrets.choice(alpha) for _ in range(opts['length']))\n\n"
        "def deterministic_tiebreak_order(candidates, opts):\n"
        "    random.seed(opts['seed'])\n"
        "    return random.sample(candidates, len(candidates))\n"
    )
    scoped_res = evaluate_security_profile(
        scoped_safe_code,
        "python.cwe338.security_randomness.v1",
        target_function="issue_invite_code",
    )
    assert scoped_res["security_label"] == "secure"
    assert scoped_res["decision"]["trace"]["target_function"] == "issue_invite_code"

    helper_tainted_code = (
        "import random, string\n\n"
        "def _weak_pick(alpha):\n"
        "    return random.choice(alpha)\n\n"
        "def issue_invite_code(opts):\n"
        "    alpha = string.ascii_letters + string.digits\n"
        "    return ''.join(_weak_pick(alpha) for _ in range(opts['length']))\n"
    )
    helper_res = evaluate_security_profile(
        helper_tainted_code,
        "python.cwe338.security_randomness.v1",
        target_function="issue_invite_code",
    )
    assert helper_res["security_label"] == "insecure"

    missing_res = evaluate_security_profile(
        scoped_safe_code,
        "python.cwe338.security_randomness.v1",
        target_function="missing_fn",
    )
    assert missing_res["security_label"] == "unknown"


def test_unit_test_oracle_pass_fail_and_timeout():
    p_res = evaluate_python_unit_tests("def add(a, b): return a + b\n", "assert add(2, 3) == 5\n")
    f_res = evaluate_python_unit_tests("def add(a, b): return a - b\n", "assert add(2, 3) == 5\n")
    t_res = evaluate_python_unit_tests("import time\ndef spin(): time.sleep(2)\n", "spin()\n", timeout_seconds=0.3)

    assert p_res["functional_label"] == "pass" and p_res["passed"] is True
    assert f_res["functional_label"] == "fail" and f_res["passed"] is False
    assert t_res["functional_label"] == "fail" and "timeout" in str(t_res["failure_reason"])


def test_natural_task_multiop_smoke_and_independent_verification(tmp_path):
    out_dir = tmp_path / "natural-smoke"
    assert cli_main(["study", "natural-smoke", str(out_dir)]) == 0
    assert cli_main(["study", "verify", str(out_dir)]) == 0

    summary = read_json(out_dir / "summary" / "result.json")
    assert summary["study_mode"] == "natural_task"
    assert summary["formal_claim_allowed"] is False
    assert summary["new_provider_calls"] == 0
    assert summary["n_eval_tasks"] == 24
    assert summary["n_total_measurements"] == 96
    assert summary["reliability_gate_passed"] is True
    assert summary["jci_selected_mechanisms"] == ["Z_cau"]
    assert summary["corr_selected_mechanisms"] == ["Z_lat"]
    assert summary["arm_rates"]["baseline"]["joint_success_rate"] == 0.0
    assert summary["arm_rates"]["corr_tsg"]["joint_success_rate"] == 0.0
    assert summary["arm_rates"]["jci_flat"]["joint_success_rate"] == 0.0
    assert summary["arm_rates"]["jci_tsg"]["joint_success_rate"] == 1.0

    # Tampering with summary/result.json (even re-hashed) must be rejected by independent replay.
    forged = deepcopy(summary)
    forged["arm_rates"]["corr_tsg"]["joint_success_rate"] = 1.0
    shutil.rmtree(out_dir / "summary")
    write_bundle(out_dir / "summary", {"result.json": forged})
    manifest = read_json(out_dir / "manifest.json")
    manifest["summary_sha256"] = content_hash(forged)
    (out_dir / "manifest.json").unlink()
    write_json_new(out_dir / "manifest.json", manifest)
    with pytest.raises(ValueError, match="mismatch"):
        verify_natural_study(out_dir)


def test_mocked_local_vllm_retains_provider_errors_in_full_itt(tmp_path, monkeypatch):
    # Subset benchmark of 2 tasks (x 4 arms = 8 calls) exercising ProviderError ITT accounting + verification.
    bm = read_json(Path("src/fixtures/natural-multiop-benchmark.json"))
    mini_bm = {
        **bm,
        "calibration_records": bm["calibration_records"][:2],
        "evaluation_cohort": bm["evaluation_cohort"][:2],
    }
    bm_path = tmp_path / "mini-bm.json"
    bm_path.write_text(__import__("json").dumps(mini_bm), encoding="utf-8")

    plan = read_json(Path("configs/jci-local-vllm-pilot.json"))
    plan["fixture_path"] = str(bm_path)
    plan_path = tmp_path / "vllm-plan.json"
    plan_path.write_text(__import__("json").dumps(plan), encoding="utf-8")

    def fake_complete_chat(req_payload, evaluator, prompt, **kwargs):
        tid = req_payload["task_unit_id"]
        arm = req_payload["arm"]
        if kwargs.get("trace") is not None:
            kwargs["trace"]("request", b"{}")
            kwargs["trace"]("response", b"{}")
        if tid == mini_bm["evaluation_cohort"][0]["task_unit_id"] and arm == "corr_tsg":
            raise ProviderError("simulated vLLM timeout")
        task = next(t for t in mini_bm["evaluation_cohort"] if t["task_unit_id"] == tid)
        return task["offline_responses"][arm].encode("utf-8")

    monkeypatch.setattr(natural_study, "complete_chat", fake_complete_chat)
    out_dir = tmp_path / "vllm-out"
    summary = natural_study.run_natural_study(plan_path, out_dir)
    assert summary["new_provider_calls"] == 8
    assert summary["n_total_measurements"] == 8
    # Failed corr_tsg call stays in the full paired ITT denominator (code_valid_rate == 0.5).
    assert summary["arm_rates"]["corr_tsg"]["code_valid_rate"] == pytest.approx(0.5)
    assert summary["arm_rates"]["jci_tsg"]["joint_success_rate"] == pytest.approx(1.0)
    verified = verify_natural_study(out_dir)
    assert verified["status"] == "VERIFIED" and verified["n_measurements_verified"] == 8
