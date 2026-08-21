from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from scripts import run_executable_functional_sensitivity as cli

from secaware.canonical import canonical_sha256
from secaware.exploratory.executable_functional_sensitivity import (
    IsolatedSubprocessExecutorV1,
    run_executable_functional_sensitivity,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TRACKED_SPEC = (
    _REPO_ROOT / "data" / "functional-judge" / "executable-sensitivity-v1" / "source-spec.json"
)
_LIVE_ROOT = Path(
    os.environ.get(
        "SECAWARE_EXEC_SENSITIVITY_LIVE_ROOT",
        "/home/ubuntu/secaware-experiments/runs/"
        "minimal-validation-protocol-v2-full-live-a335fb2-20260821-attempt-001",
    )
)
_BWRAP = Path(os.environ.get("SECAWARE_TEST_BWRAP", "/usr/bin/bwrap"))
_PYTHON_RUNTIME = Path(
    os.environ.get(
        "SECAWARE_TEST_PYTHON_RUNTIME",
        "/home/ubuntu/.local/share/uv/python/cpython-3.12.12-linux-x86_64-gnu",
    )
)


def _tracked_spec() -> dict[str, object]:
    value = json.loads(_TRACKED_SPEC.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _readdress(spec: dict[str, object]) -> dict[str, object]:
    content = dict(spec)
    content.pop("spec_id", None)
    return {
        **content,
        "spec_id": "executable_sensitivity_source_spec_" + canonical_sha256(content),
    }


def test_tracked_rich_source_spec_is_self_addressed_and_exact() -> None:
    spec = _tracked_spec()
    source_sha, cases = cli._spec_cases(spec)

    assert source_sha == "c2e750f0b422e9b87030931438d9bf4784092c6f51a4612733083ebb59a53687"
    assert len(cases) == 4
    assert {str(case["family"]) for case in cases} == set(cli._ADAPTERS)
    assert sum(len(case["arms"]) for case in cases) == 8
    assert all(
        set(case) == {"task_id", "family", "adapter_id", "contract", "arms"} for case in cases
    )
    assert all(
        set(case["contract"]) == {"contract_id", "artifact_sha256", "requirements"}
        for case in cases
    )
    assert {str(arm["arm_role"]) for case in cases for arm in case["arms"]} == {
        "target_patch",
        "noop_rewrite",
    }


def test_tracked_spec_rejects_self_address_and_requirement_tampering() -> None:
    wrong_id = _tracked_spec()
    wrong_id["source_live_root_manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="spec failed validation"):
        cli._spec_cases(wrong_id)

    wrong_requirement = _tracked_spec()
    cases = wrong_requirement["cases"]
    assert type(cases) is list and type(cases[0]) is dict
    contract = cases[0]["contract"]
    assert type(contract) is dict and type(contract["requirements"]) is list
    contract["requirements"][0]["requirement_id"] = "req_unfrozen"
    with pytest.raises(ValueError, match="requirement coverage"):
        cli._spec_cases(_readdress(wrong_requirement))


@pytest.mark.skipif(
    os.name != "posix"
    or not (_LIVE_ROOT / "artifact-manifest.json").is_file()
    or not _BWRAP.is_file()
    or not _PYTHON_RUNTIME.is_dir(),
    reason="requires the authoritative read-only Linux root and frozen executor paths",
)
def test_tracked_spec_builds_zero_execution_preflight_and_contract_bindings(
    tmp_path: Path,
) -> None:
    output = tmp_path / "must-not-exist"
    plan, cases = cli.build_preflight(
        source_live_root=_LIVE_ROOT,
        frozen_spec_path=_TRACKED_SPEC,
        bwrap_path=_BWRAP,
        python_runtime_root=_PYTHON_RUNTIME,
        python_relative_executable="bin/python3.12",
        output_dir=output,
        execute_requested=False,
    )

    assert plan["status"] == "EXECUTABLE_FUNCTIONAL_SENSITIVITY_PREFLIGHT_COMPLETE"
    assert plan["execution_performed"] is False
    assert plan["zero_execution_counts"] == {
        "subprocess_calls": 0,
        "generated_code_executions": 0,
        "provider_calls": 0,
        "functional_judge_calls": 0,
        "security_oracle_calls": 0,
    }
    assert plan["counts"] == {"tasks": 4, "assignments": 8}
    assert len(plan["functional_contracts"]) == 4
    assert len(cases) == 4
    assert all(case.functional_contract is not None for case in cases)
    assert all(case.functional_contract.requirement_ids for case in cases)
    assert not output.exists()

    for coordinate in ("contract", "generated_code"):
        tampered = _tracked_spec()
        raw_cases = tampered["cases"]
        assert type(raw_cases) is list and type(raw_cases[0]) is dict
        if coordinate == "contract":
            contract = raw_cases[0]["contract"]
            assert type(contract) is dict
            contract["artifact_sha256"] = "0" * 64
        else:
            arms = raw_cases[0]["arms"]
            assert type(arms) is list and type(arms[0]) is dict
            arms[0]["generated_code_artifact_sha256"] = "0" * 64
        tampered_path = tmp_path / f"tampered-{coordinate}.json"
        tampered_path.write_text(
            json.dumps(_readdress(tampered), sort_keys=True),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="differs from the tracked frozen spec"):
            cli.build_preflight(
                source_live_root=_LIVE_ROOT,
                frozen_spec_path=tampered_path,
                bwrap_path=_BWRAP,
                python_runtime_root=_PYTHON_RUNTIME,
                python_relative_executable="bin/python3.12",
                output_dir=output,
                execute_requested=False,
            )


@pytest.mark.skipif(
    os.environ.get("SECAWARE_RUN_REAL_EXEC_SENSITIVITY") != "1"
    or os.name != "posix"
    or not (_LIVE_ROOT / "artifact-manifest.json").is_file()
    or not _BWRAP.is_file()
    or not _PYTHON_RUNTIME.is_dir(),
    reason="requires explicit authorization for the frozen real-eight Linux execution",
)
def test_frozen_real_eight_execute_with_expected_pdf_and_slurm_failures(
    tmp_path: Path,
) -> None:
    output = tmp_path / "real-eight-sidecar"
    plan, cases = cli.build_preflight(
        source_live_root=_LIVE_ROOT,
        frozen_spec_path=_TRACKED_SPEC,
        bwrap_path=_BWRAP,
        python_runtime_root=_PYTHON_RUNTIME,
        python_relative_executable="bin/python3.12",
        output_dir=output,
        execute_requested=True,
    )
    report = run_executable_functional_sensitivity(
        source_manifest_path=_LIVE_ROOT / "artifact-manifest.json",
        output_dir=output,
        cases=cases,
        executor=IsolatedSubprocessExecutorV1(
            bwrap_executable=_BWRAP,
            python_runtime_root=_PYTHON_RUNTIME,
        ),
        command_argv=("pytest", "frozen-real-eight"),
        frozen_input_plan=plan,
    )

    assert report["counts"]["assignments"] == 8
    assert report["counts"]["y_f_e_pass"] == 0
    assert report["counts"]["y_f_e_fail"] == 8
    by_family = {row["family"]: row for row in report["paired_results"]}
    for family in ("pdf_bag_of_words", "slurm_exit_code"):
        assert by_family[family]["target_y_f_e"] == 0
        assert by_family[family]["noop_y_f_e"] == 0
        assert by_family[family]["paired_target_minus_noop"] == 0
