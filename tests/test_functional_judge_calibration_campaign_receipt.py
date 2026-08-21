from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from secaware.exploratory.artifact_integrity import (
    verify_closed_manifest,
    write_closed_manifest_atomic,
)
from secaware.pipeline.artifact import canonical_sha256

ROOT = Path(__file__).parents[1]
CALIBRATION_DATA = ROOT / "data" / "functional-judge" / "blind-calibration-v3"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_deployment(
    root: Path,
    spec_path: Path,
    execution_sources: list[Path],
) -> dict[str, object]:
    root.mkdir()
    shutil.copytree(
        ROOT / "src" / "secaware",
        root / "src" / "secaware",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    copied_execution_paths: list[Path] = []
    for source in execution_sources:
        destination = root / source.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(source, destination)
        copied_execution_paths.append(destination)
    deployed_spec = root / "data" / "functional-judge" / "blind-calibration-v3" / "spec.json"
    deployed_spec.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(spec_path, deployed_spec)
    deployed_baseline = deployed_spec.parent / "evaluator-qwen35flash-v1.json"
    deployed_new = deployed_spec.parent / "evaluator-qwen35flash-v2.json"
    shutil.copy2(CALIBRATION_DATA / deployed_baseline.name, deployed_baseline)
    shutil.copy2(CALIBRATION_DATA / deployed_new.name, deployed_new)

    listed_paths = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    ledger = root / "DEPLOYMENT_FILES.sha256"
    ledger.write_text(
        "".join(
            f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}\n" for path in listed_paths
        ),
        encoding="utf-8",
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    manifest = root / "DEPLOYMENT_MANIFEST.json"
    _write_json(
        manifest,
        {
            "schema_version": "1.0",
            "deployment_id": "functional-judge-calibration-test-deployment",
            "deployed_commit": commit,
            "deployment_method": "test_fixture",
            "scientific_claim_allowed": False,
            "deployment_files": {
                "exclusions": ["DEPLOYMENT_FILES.sha256", "DEPLOYMENT_MANIFEST.json"],
                "listed_files": len(listed_paths),
                "path": "DEPLOYMENT_FILES.sha256",
                "sha256": _sha256_file(ledger),
            },
        },
    )
    return {
        "root": root,
        "manifest": manifest,
        "commit": commit,
        "execution_paths": copied_execution_paths,
        "spec": deployed_spec,
        "baseline_config": deployed_baseline,
        "new_config": deployed_new,
    }


def _run_preflight(
    canary,
    *,
    output_dir: Path,
    cases_path: Path,
    contracts_path: Path,
    evaluator_config: Path,
) -> None:
    payload = json.loads(evaluator_config.read_text(encoding="utf-8"))
    with pytest.MonkeyPatch.context() as patch:
        patch.delenv(payload["api_key_env"], raising=False)
        patch.setattr(
            canary,
            "OpenAICompatibleStructuredTransport",
            lambda **_kwargs: (_ for _ in ()).throw(AssertionError("provider constructed")),
        )
        patch.setattr(
            sys,
            "argv",
            [
                str(Path(canary.__file__).resolve()),
                "--output-dir",
                str(output_dir),
                "--cases-path",
                str(cases_path),
                "--contracts-path",
                str(contracts_path),
                "--evaluator-config",
                str(evaluator_config),
                "--preflight",
            ],
        )
        assert canary.main() == 0


@pytest.fixture(scope="module")
def campaign_fixture(tmp_path_factory):
    root = tmp_path_factory.mktemp("functional-judge-campaign-receipt")
    helpers = _load_module(
        "campaign_receipt_calibration_helpers",
        ROOT / "tests" / "test_functional_judge_calibration.py",
    )
    with pytest.MonkeyPatch.context() as patch:
        plan_dir, canary, spec_path = helpers._build_plan(root, patch)
    freezer = _load_module(
        "freeze_functional_judge_calibration_campaign_tested",
        ROOT / "scripts" / "freeze_functional_judge_calibration_campaign.py",
    )
    deployment = _build_deployment(
        root / "deployment",
        spec_path,
        freezer._execution_code_paths(),
    )
    baseline_config = Path(deployment["baseline_config"])
    new_config = Path(deployment["new_config"])
    preflights: dict[str, Path] = {}
    for candidate, config in (("baseline", baseline_config), ("new_candidate", new_config)):
        for phase, cases_name in (
            ("pilot", "pilot-cases.jsonl"),
            ("remaining", "remaining-cases.jsonl"),
        ):
            stage = f"{candidate}_{phase}"
            output = root / "preflights" / stage
            _run_preflight(
                canary,
                output_dir=output,
                cases_path=plan_dir / cases_name,
                contracts_path=plan_dir / "contracts.jsonl",
                evaluator_config=config,
            )
            preflights[stage] = output
    return {
        "root": root,
        "module": freezer,
        "plan": plan_dir,
        "sidecar": root / "overlay",
        "spec": deployment["spec"],
        "delivery": root / "final-delivery.json",
        "baseline_config": baseline_config,
        "new_config": new_config,
        "preflights": preflights,
        "deployment_root": deployment["root"],
        "deployment_execution_paths": deployment["execution_paths"],
        "deployment_manifest": deployment["manifest"],
        "deployed_commit": deployment["commit"],
    }


def _bind_test_execution_to_deployment(fixture: dict[str, object], monkeypatch) -> None:
    module = fixture["module"]
    deployment_root = Path(fixture["deployment_root"])
    execution_paths = [Path(path) for path in fixture["deployment_execution_paths"]]
    monkeypatch.setattr(module, "_REPOSITORY_ROOT", deployment_root)
    monkeypatch.setattr(module, "_execution_code_paths", lambda: execution_paths)


def _campaign_argv(
    fixture: dict[str, object],
    *,
    tag: str,
    receipt_dir: Path,
    overrides: dict[str, object] | None = None,
) -> tuple[list[str], dict[str, Path]]:
    root = Path(fixture["root"])
    preflights = fixture["preflights"]
    assert isinstance(preflights, dict)
    values: dict[str, Path | str] = {
        "deployment-manifest": Path(fixture["deployment_manifest"]),
        "deployed-commit": str(fixture["deployed_commit"]),
        "source-final-delivery": Path(fixture["delivery"]),
        "sidecar-dir": Path(fixture["sidecar"]),
        "plan-dir": Path(fixture["plan"]),
        "calibration-spec": Path(fixture["spec"]),
        "baseline-evaluator-config": Path(fixture["baseline_config"]),
        "new-candidate-evaluator-config": Path(fixture["new_config"]),
        "baseline-pilot-preflight-dir": Path(preflights["baseline_pilot"]),
        "baseline-remaining-preflight-dir": Path(preflights["baseline_remaining"]),
        "new-candidate-pilot-preflight-dir": Path(preflights["new_candidate_pilot"]),
        "new-candidate-remaining-preflight-dir": Path(preflights["new_candidate_remaining"]),
        "baseline-pilot-output-dir": root / "future" / tag / "baseline" / "pilot",
        "baseline-remaining-output-dir": root / "future" / tag / "baseline" / "remaining",
        "new-candidate-pilot-output-dir": root / "future" / tag / "new-candidate" / "pilot",
        "new-candidate-remaining-output-dir": root / "future" / tag / "new-candidate" / "remaining",
        "analysis-output-dir": root / "future" / tag / "analysis",
        "output-dir": receipt_dir,
    }
    values.update(overrides or {})
    argv: list[str] = []
    for name, value in values.items():
        argv.extend((f"--{name}", str(value)))
    future = {
        name: Path(value)
        for name, value in values.items()
        if name.endswith("-output-dir") and name != "output-dir"
    }
    return argv, future


def _copy_reclosed(source: Path, destination: Path, mutate) -> Path:
    shutil.copytree(source, destination)
    (destination / "artifact-manifest.json").unlink()
    mutate(destination)
    write_closed_manifest_atomic(destination, label="attacked campaign fixture")
    return destination


def _rewrite_plan_id(root: Path) -> None:
    plan_path = root / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    core = {key: value for key, value in plan.items() if key != "plan_id"}
    plan["plan_id"] = "functional_judge_calibration_plan_" + canonical_sha256(core)
    _write_json(plan_path, plan)


def test_campaign_receipt_is_content_addressed_closed_and_zero_call(
    campaign_fixture,
    monkeypatch,
    tmp_path: Path,
) -> None:
    module = campaign_fixture["module"]
    _bind_test_execution_to_deployment(campaign_fixture, monkeypatch)
    receipt_dir = tmp_path / "receipt"
    argv, future = _campaign_argv(
        campaign_fixture,
        tag="positive",
        receipt_dir=receipt_dir,
    )
    invocation = [
        sys.executable,
        "-I",
        "-B",
        str(Path(module.__file__).resolve()),
        *argv,
    ]
    monkeypatch.setattr(sys, "argv", [str(Path(module.__file__).resolve()), *argv])
    monkeypatch.setattr(sys, "orig_argv", invocation)

    assert module.main() == 0
    manifest = verify_closed_manifest(
        receipt_dir / "artifact-manifest.json", label="campaign receipt test"
    )
    assert {row["path"] for row in manifest["files"]} == {
        "campaign-receipt.json",
        "command.json",
        "environment.json",
    }
    receipt = json.loads((receipt_dir / "campaign-receipt.json").read_text(encoding="utf-8"))
    core = {key: value for key, value in receipt.items() if key != "receipt_id"}
    assert receipt["receipt_id"] == (
        "functional_judge_calibration_campaign_receipt_" + canonical_sha256(core)
    )
    assert receipt["claim"] is False
    assert receipt["scientific_claim_allowed"] is False
    assert receipt["expected_calls"] == {
        "functional_judge_provider_trace_attempts_by_stage": {
            "baseline_pilot": 2,
            "baseline_remaining": 22,
            "new_candidate_pilot": 2,
            "new_candidate_remaining": 22,
        },
        "functional_judge_provider_trace_attempts_total": 48,
        "provider_attempt_scope": "included_closed_run_trace_records",
        "generation_provider_attempts": 0,
        "security_oracle_executions": 0,
        "freezer_provider_attempts": 0,
        "analyzer_provider_attempts": 0,
    }
    assert [stage["case_count"] for stage in receipt["stages"]] == [2, 22, 2, 22]
    assert receipt["limitations"][0]["limitation_id"] == (
        "recording_transport_post_return_trace_gap"
    )
    assert receipt["credential"]["value_read_by_freezer"] is False
    assert all(not path.exists() for path in future.values())
    command = json.loads((receipt_dir / "command.json").read_text(encoding="utf-8"))
    assert command["argv"] == invocation
    assert command["argv_source"] == "sys.orig_argv"
    assert command["sys_dont_write_bytecode"] is True

    with pytest.raises(SystemExit, match="FileExistsError"):
        module.main()


def test_campaign_receipt_archive_script_starts_without_editable_source_path(
    campaign_fixture,
) -> None:
    deployment_root = Path(campaign_fixture["deployment_root"])
    bytecode_before = {
        path.relative_to(deployment_root).as_posix()
        for path in deployment_root.rglob("*")
        if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
    }
    assert bytecode_before == set()
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(deployment_root / "scripts" / "freeze_functional_judge_calibration_campaign.py"),
            "--help",
        ],
        cwd=deployment_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--deployment-manifest" in completed.stdout
    bytecode_after = {
        path.relative_to(deployment_root).as_posix()
        for path in deployment_root.rglob("*")
        if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
    }
    assert bytecode_after == set()


@pytest.mark.parametrize(
    "attack",
    (
        "cross_plan",
        "config",
        "cases",
        "contracts",
        "preflight",
        "outputs_existing",
        "budget",
        "sidecar",
        "preflight_command",
        "receipt_authority_overlap",
        "future_authority_overlap",
        "deployment_commit",
        "unrelated_deployment",
        "deployment_excluded_module",
        "preflight_relative_cwd",
        "preflight_secret_field",
    ),
)
def test_campaign_receipt_rejects_cross_campaign_and_tampered_inputs(
    campaign_fixture,
    monkeypatch,
    tmp_path: Path,
    attack: str,
) -> None:
    module = campaign_fixture["module"]
    _bind_test_execution_to_deployment(campaign_fixture, monkeypatch)
    overrides: dict[str, object] = {}
    tag = f"attack-{attack}"
    receipt_dir = tmp_path / f"receipt-{attack}"

    if attack == "cross_plan":

        def mutate_cross_plan(root: Path) -> None:
            pilot = [
                json.loads(line)
                for line in (root / "pilot-cases.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            remaining = [
                json.loads(line)
                for line in (root / "remaining-cases.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            pilot[0], remaining[0] = remaining[0], pilot[0]
            _write_jsonl(root / "pilot-cases.jsonl", pilot)
            _write_jsonl(root / "remaining-cases.jsonl", remaining)
            plan = json.loads((root / "plan.json").read_text(encoding="utf-8"))
            plan["pilot_case_ids"] = sorted(row["case_id"] for row in pilot)
            _write_json(root / "plan.json", plan)
            _rewrite_plan_id(root)

        overrides["plan-dir"] = _copy_reclosed(
            Path(campaign_fixture["plan"]),
            tmp_path / "cross-plan",
            mutate_cross_plan,
        )
    elif attack == "config":
        overrides["baseline-evaluator-config"] = Path(campaign_fixture["new_config"])
    elif attack == "cases":
        preflights = campaign_fixture["preflights"]
        assert isinstance(preflights, dict)
        overrides["baseline-pilot-preflight-dir"] = Path(preflights["baseline_remaining"])
    elif attack == "contracts":

        def mutate_contract(root: Path) -> None:
            contracts = [
                json.loads(line)
                for line in (root / "contracts.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            contracts[0]["requirements"][0]["criterion"] += " tampered"
            _write_jsonl(root / "contracts.jsonl", contracts)
            plan = json.loads((root / "plan.json").read_text(encoding="utf-8"))
            plan["contracts_sha256"] = canonical_sha256(contracts)
            _write_json(root / "plan.json", plan)
            _rewrite_plan_id(root)

        overrides["plan-dir"] = _copy_reclosed(
            Path(campaign_fixture["plan"]),
            tmp_path / "contract-plan",
            mutate_contract,
        )
    elif attack == "preflight":

        def mutate_preflight(root: Path) -> None:
            report = json.loads((root / "report.json").read_text(encoding="utf-8"))
            report["provider_attempts"] = 1
            report["new_calls"]["functional_judge_provider_attempts"] = 1
            _write_json(root / "report.json", report)

        preflights = campaign_fixture["preflights"]
        assert isinstance(preflights, dict)
        overrides["new-candidate-pilot-preflight-dir"] = _copy_reclosed(
            Path(preflights["new_candidate_pilot"]),
            tmp_path / "provider-preflight",
            mutate_preflight,
        )
    elif attack == "budget":

        def mutate_budget(root: Path) -> None:
            plan = json.loads((root / "plan.json").read_text(encoding="utf-8"))
            plan["comparison_design"]["expected_total_functional_judge_provider_attempts"] = 49
            _write_json(root / "plan.json", plan)
            _rewrite_plan_id(root)

        overrides["plan-dir"] = _copy_reclosed(
            Path(campaign_fixture["plan"]),
            tmp_path / "budget-plan",
            mutate_budget,
        )
    elif attack == "sidecar":

        def mutate_sidecar(root: Path) -> None:
            report = json.loads((root / "report.json").read_text(encoding="utf-8"))
            report["sandbox_limitations"] = ["tampered limitation"]
            content = {key: value for key, value in report.items() if key != "report_id"}
            report["report_id"] = "executable_sensitivity_report_" + canonical_sha256(content)
            _write_json(root / "report.json", report)

        overrides["sidecar-dir"] = _copy_reclosed(
            Path(campaign_fixture["sidecar"]),
            tmp_path / "sidecar",
            mutate_sidecar,
        )
    elif attack == "preflight_command":

        def mutate_preflight_command(root: Path) -> None:
            commands = [
                json.loads(line)
                for line in (root / "commands.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            commands[0]["argv"].remove("--preflight")
            _write_jsonl(root / "commands.jsonl", commands)

        preflights = campaign_fixture["preflights"]
        assert isinstance(preflights, dict)
        overrides["baseline-pilot-preflight-dir"] = _copy_reclosed(
            Path(preflights["baseline_pilot"]),
            tmp_path / "live-command-preflight",
            mutate_preflight_command,
        )
    elif attack == "receipt_authority_overlap":
        receipt_dir = Path(campaign_fixture["plan"]) / "receipt-attack"
    elif attack == "future_authority_overlap":
        overrides["baseline-pilot-output-dir"] = (
            Path(campaign_fixture["sidecar"]) / "future-run-attack"
        )
    elif attack == "deployment_commit":
        overrides["deployed-commit"] = "f" * 40
    elif attack == "unrelated_deployment":
        unrelated = tmp_path / "unrelated-deployment"
        shutil.copytree(Path(campaign_fixture["deployment_root"]), unrelated)
        overrides["deployment-manifest"] = unrelated / "DEPLOYMENT_MANIFEST.json"
    elif attack == "deployment_excluded_module":
        source_deployment = Path(campaign_fixture["deployment_root"])
        attacked = tmp_path / "excluded-module-deployment"
        shutil.copytree(source_deployment, attacked)
        relative = "src/secaware/schema/experiments.py"
        target = attacked / relative
        assert target.is_file()
        target.write_text(target.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
        ledger = attacked / "DEPLOYMENT_FILES.sha256"
        retained = [
            line
            for line in ledger.read_text(encoding="utf-8").splitlines()
            if not line.endswith(f"  {relative}")
        ]
        ledger.write_text("\n".join(retained) + "\n", encoding="utf-8")
        manifest_path = attacked / "DEPLOYMENT_MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["deployment_files"]["exclusions"] = sorted(
            [*manifest["deployment_files"]["exclusions"], relative]
        )
        manifest["deployment_files"]["listed_files"] = len(retained)
        manifest["deployment_files"]["sha256"] = _sha256_file(ledger)
        _write_json(manifest_path, manifest)
        monkeypatch.setattr(module, "_REPOSITORY_ROOT", attacked)
        monkeypatch.setattr(
            module,
            "_execution_code_paths",
            lambda: [
                attacked / Path(path).relative_to(source_deployment)
                for path in campaign_fixture["deployment_execution_paths"]
            ],
        )
        overrides["deployment-manifest"] = manifest_path
    elif attack == "preflight_relative_cwd":

        def mutate_relative_cwd(root: Path) -> None:
            commands = [
                json.loads(line)
                for line in (root / "commands.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            environment = json.loads((root / "environment.json").read_text(encoding="utf-8"))
            argv = commands[0]["argv"]
            resolution_cwd = Path(campaign_fixture["root"]).resolve()
            monkeypatch.chdir(resolution_cwd)
            for flag in (
                "--output-dir",
                "--cases-path",
                "--contracts-path",
                "--evaluator-config",
            ):
                index = argv.index(flag) + 1
                argv[index] = os.path.relpath(argv[index], resolution_cwd)
            forged_cwd = (tmp_path / "forged-recorded-cwd").resolve()
            forged_cwd.mkdir()
            commands[0]["working_directory"] = str(forged_cwd)
            environment["working_directory"] = str(forged_cwd)
            _write_jsonl(root / "commands.jsonl", commands)
            _write_json(root / "environment.json", environment)

        preflights = campaign_fixture["preflights"]
        assert isinstance(preflights, dict)
        overrides["new-candidate-remaining-preflight-dir"] = _copy_reclosed(
            Path(preflights["new_candidate_remaining"]),
            tmp_path / "relative-cwd-preflight",
            mutate_relative_cwd,
        )
    elif attack == "preflight_secret_field":

        def mutate_secret_field(root: Path) -> None:
            environment = json.loads((root / "environment.json").read_text(encoding="utf-8"))
            environment["api_key"] = "must-never-be-accepted"
            _write_json(root / "environment.json", environment)

        preflights = campaign_fixture["preflights"]
        assert isinstance(preflights, dict)
        overrides["baseline-remaining-preflight-dir"] = _copy_reclosed(
            Path(preflights["baseline_remaining"]),
            tmp_path / "secret-field-preflight",
            mutate_secret_field,
        )

    argv, future = _campaign_argv(
        campaign_fixture,
        tag=tag,
        receipt_dir=receipt_dir,
        overrides=overrides,
    )
    if attack == "outputs_existing":
        next(iter(future.values())).mkdir(parents=True)
    args = module._parse_args(argv)
    with pytest.raises((ValueError, FileExistsError)):
        module._freeze_campaign(args, raw_argv=argv)
    assert not receipt_dir.exists()
