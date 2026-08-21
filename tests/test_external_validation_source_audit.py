from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from secaware.dataset_audit.fingerprints import (
    exact_prompt_sha256,
    normalized_prompt_sha256,
)
from secaware.exploratory.external_validation_source_audit import (
    audit_external_validation_sources,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def test_external_source_audit_separates_asset_and_method_overlap(tmp_path: Path) -> None:
    selection = tmp_path / "selection.json"
    _write_json(
        selection,
        {
            "tasks": [
                {"source_prompt_sha256": hashlib.sha256(f"used-{index}".encode()).hexdigest()}
                for index in range(93)
            ]
        },
    )

    codeguard = tmp_path / "codeguard"
    scenario = codeguard / "data" / "base" / "cwe-078" / "0-py"
    _write_json(
        scenario / "info.json",
        {"language": "py", "cwe": "CWE-078", "scenario": "0-py"},
    )
    (codeguard / "README.md").write_text("fixture", encoding="utf-8")
    (scenario / "file_context.py").write_text("import subprocess\n", encoding="utf-8")
    (scenario / "func_context.py").write_text("# run a command\n", encoding="utf-8")
    functional = codeguard / "unit_test" / "cwe-078" / "0-py" / "functional.py"
    functional.parent.mkdir(parents=True)
    functional.write_text("def test_it(): pass\n", encoding="utf-8")

    llmseceval = tmp_path / "llmseceval"
    llm_rows = [
        {
            "Prompt ID": f"prompt-{index}",
            "CWE Name": (
                "Deserialization of Untrusted Data" if index == 0 else "Unrelated"
            ),
            "Language": "Python",
            "LLM-generated NL Prompt": f"Generate program {index}",
        }
        for index in range(150)
    ]
    _write_json(llmseceval / "Dataset" / "LLMSecEval-Prompts_dataset.json", llm_rows)

    seccode = tmp_path / "seccode"
    _git(tmp_path, "init", str(seccode))
    _git(seccode, "config", "user.email", "fixture@example.test")
    _git(seccode, "config", "user.name", "Fixture")
    manifests = {
        "cpp": ("datasets/benchmark/cpp/c.json", "OtherCpp"),
        "go": ("datasets/benchmark/go/go.json", "OtherGo"),
        "java": ("datasets/benchmark/java/java.json", "WeakHashMD5SHA1"),
        "nodejs": ("datasets/benchmark/nodejs/nodejs.json", "OtherNode"),
        "python": (
            "datasets/benchmark/python/python.json",
            "CommandInjectionSubprocessRun",
        ),
    }
    seccode_python_prompt = "Generate a login history query."
    for language, (manifest_path, task_name) in manifests.items():
        prompt_base = f"2_1_0/{task_name}"
        _write_json(
            seccode / manifest_path,
            {
                task_name: {
                    "prompt": prompt_base,
                    "locale": "en-US",
                    "FuncTester": "UnitTester",
                }
            },
        )
        prompt_dir = "cpp" if language == "cpp" else language
        prompt = (
            seccode_python_prompt
            if language == "python"
            else f"Generate {task_name}."
        )
        prompt_path = (
            seccode
            / "datasets"
            / "benchmark"
            / prompt_dir
            / "prompts"
            / f"{prompt_base}.en-US"
        )
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")
    _git(seccode, "add", ".")
    _git(seccode, "commit", "-m", "fixture")
    _git(seccode, "tag", "v2.2.0")
    revision = _git(seccode, "rev-parse", "HEAD")

    record_audit = tmp_path / "record-audit.jsonl"
    _write_jsonl(
        record_audit,
        [
            {
                "coordinate": {"source_id": "seccodebench_python"},
                "exact_prompt_sha256": exact_prompt_sha256(seccode_python_prompt),
                "normalized_prompt_sha256": normalized_prompt_sha256(seccode_python_prompt),
            }
        ],
    )
    codeguard_archive = tmp_path / "codeguard.zip"
    llm_archive = tmp_path / "llm.zip"
    codeguard_archive.write_bytes(b"codeguard archive")
    llm_archive.write_bytes(b"llm archive")
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "audit_id": "five_cwe_external_validation_source_audit_v1",
            "target_cwes": ["CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338"],
            "minimum_validation_tasks": 50,
            "repository_inputs": {
                "method_development_selection": {
                    "path": selection.relative_to(tmp_path).as_posix(),
                    "sha256": _sha(selection),
                },
                "repository_record_audit": {
                    "path": record_audit.relative_to(tmp_path).as_posix(),
                    "sha256": _sha(record_audit),
                },
            },
            "sources": {
                "codeguard_plus": {"archive_sha256": _sha(codeguard_archive)},
                "llmseceval": {"archive_sha256": _sha(llm_archive)},
                "seccodebench_v2_2_0": {"revision": revision},
            },
            "provider_calls_allowed": False,
            "outcomes_allowed": False,
        },
    )

    report = audit_external_validation_sources(
        repo_root=tmp_path,
        config_path=config,
        run_dir=tmp_path / "run",
        codeguard_root=codeguard,
        codeguard_archive=codeguard_archive,
        llmseceval_root=llmseceval,
        llmseceval_archive=llm_archive,
        seccode_root=seccode,
        command_argv=("audit",),
    )

    assert report["status"] == "EXTERNAL_SOURCE_BLINDED_REVIEW_REQUIRED"
    assert report["provider_calls"] == 0
    assert report["outcomes_consumed"] == 0
    assert report["sources"]["codeguard_plus"]["five_cwe_tasks"] == 1
    assert report["sources"]["llmseceval"]["five_cwe_tasks"] == 1
    assert report["sources"]["seccodebench_v2_2_0"]["repository_asset_exact_overlap"] == 1
    assert (tmp_path / "run" / "artifact-manifest.json").is_file()
