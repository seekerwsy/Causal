import os
import subprocess
import sys
import tomllib
from pathlib import Path


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
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    assert pyproject["project"]["scripts"] == {
        "secaware": "secaware.cli:app",
        "secaware-oracle": "secaware.oracle.cli:app",
    }


def test_python_m_secaware_shows_pipeline_help() -> None:
    result = _run_module("secaware")

    assert result.returncode == 0, result.stderr
    assert "prompt-side security mechanism pipeline" in result.stdout


def test_python_m_secaware_oracle_cli_shows_oracle_help() -> None:
    result = _run_module("secaware.oracle.cli")

    assert result.returncode == 0, result.stderr
    assert "standalone security oracle" in result.stdout
