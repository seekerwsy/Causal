import os
import re
import shutil
import subprocess
import sys
from importlib.metadata import entry_points, metadata, requires
from pathlib import Path
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"


def _run_module(module: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    pythonpath = [str(SRC_ROOT)]
    if existing_pythonpath := env.get("PYTHONPATH"):
        pythonpath.append(existing_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)
    return subprocess.run(
        [sys.executable, "-m", module, "--help"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def test_project_registers_cli_entry_points() -> None:
    expected_scripts = {
        "secaware": "secaware.cli:app",
        "secaware-oracle": "secaware.oracle.cli:app",
    }
    installed_scripts = {
        entry_point.name: entry_point.value
        for entry_point in entry_points(group="console_scripts")
        if entry_point.name in expected_scripts
    }

    assert installed_scripts == expected_scripts


def test_project_declares_exact_oracle_extra_and_test_marker() -> None:
    project = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    package_metadata = metadata("secaware")
    package_requirements = requires("secaware") or []

    assert "oracle" in (package_metadata.get_all("Provides-Extra") or [])
    assert 'semgrep==1.168.0; extra == "oracle"' in package_requirements
    assert 'bandit==1.9.4; extra == "oracle"' in package_requirements
    assert '"oracle_tools: requires the exact locked Semgrep and Bandit executables"' in project


def test_python_m_secaware_shows_pipeline_help() -> None:
    result = _run_module("secaware")

    assert result.returncode == 0, result.stderr
    assert "prompt-side security mechanism pipeline" in result.stdout
    assert "extract-prompt-tsg" in result.stdout
    forbidden_commands = ("extractor-benchmark", "rank-backends", "select-best-backend")
    assert all(command not in result.stdout for command in forbidden_commands)


def test_python_m_secaware_oracle_cli_shows_oracle_help() -> None:
    result = _run_module("secaware.oracle.cli")

    assert result.returncode == 0, result.stderr
    assert "standalone security oracle" in result.stdout


def test_built_wheel_contains_both_versioned_prompt_templates(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None, "the development packaging gate requires uv"
    result = subprocess.run(
        [
            uv,
            "build",
            "--wheel",
            "--out-dir",
            str(tmp_path),
            "--no-build-logs",
            "--no-create-gitignore",
            str(PROJECT_ROOT),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )

    assert result.returncode == 0, result.stderr
    wheels = tuple(tmp_path.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        packaged = set(archive.namelist())
    assert {
        "secaware/extractors/prompts/llm_facts_v1.txt",
        "secaware/extractors/prompts/llm_direct_graph_v1.txt",
    } <= packaged


def test_package_and_config_examples_contain_no_embedded_secrets() -> None:
    candidates = (
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "pyproject.toml",
        *(PROJECT_ROOT / "configs").glob("*.yaml"),
        *(PROJECT_ROOT / "src" / "secaware" / "extractors" / "prompts").glob("*.txt"),
    )
    secret_value = re.compile(
        r"(?im)^\s*(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*[^<$\s][^\r\n]*$"
    )
    provider_token = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")

    violations = {
        path.relative_to(PROJECT_ROOT): pattern.pattern
        for path in candidates
        for pattern in (secret_value, provider_token)
        if pattern.search(path.read_text(encoding="utf-8"))
    }
    assert violations == {}
