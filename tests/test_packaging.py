import os
import re
import subprocess
import sys
import hashlib
import json
from importlib.metadata import entry_points, metadata, requires
from pathlib import Path
import shutil
import zipfile

import pytest

from secaware.extractors.llm_direct_graph import (
    LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE,
    LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256,
)
from secaware.extractors.llm_facts import (
    LLM_FACTS_SYSTEM_TEMPLATE,
    LLM_FACTS_SYSTEM_TEMPLATE_SHA256,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"


def _clean_source_ignore(_directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        path = Path(name)
        if (
            name in {".git", ".venv", "build", "dist", "__pycache__"}
            or name.endswith(".egg-info")
            or path.suffix in {".pyc", ".pyo"}
        ):
            ignored.add(name)
    return ignored


def _copy_clean_build_source(source: Path, destination: Path) -> None:
    if destination.exists():
        raise ValueError("clean build destination must not exist")
    destination.mkdir(parents=True)
    for filename in ("pyproject.toml", "README.md"):
        shutil.copy2(source / filename, destination / filename)
    shutil.copytree(
        source / "src",
        destination / "src",
        copy_function=shutil.copy2,
        ignore=_clean_source_ignore,
    )


def _project_generated_fingerprint() -> tuple[tuple[object, ...], ...]:
    generated_roots = (
        PROJECT_ROOT / "build",
        PROJECT_ROOT / "dist",
        *PROJECT_ROOT.glob("*.egg-info"),
        *(PROJECT_ROOT / "src").glob("*.egg-info"),
    )
    entries: list[tuple[object, ...]] = []
    for root in sorted(set(generated_roots)):
        if not root.exists():
            continue
        for path in (root, *sorted(root.rglob("*"))):
            stat_result = path.stat()
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
            entries.append(
                (
                    path.relative_to(PROJECT_ROOT).as_posix(),
                    path.is_dir(),
                    stat_result.st_size,
                    stat_result.st_mtime_ns,
                    digest,
                )
            )
    return tuple(entries)


def _offline_build_environment() -> dict[str, str]:
    env = os.environ.copy()
    for key in tuple(env):
        normalized = key.casefold()
        if normalized.endswith("_proxy") or normalized in {
            "pip_index_url",
            "pip_extra_index_url",
            "pip_find_links",
            "pythonpath",
        }:
            env.pop(key, None)
    env.update(
        {
            "NO_PROXY": "*",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return env


def _assert_wheel_resources_load_in_isolation(wheel: Path, isolated_cwd: Path) -> None:
    isolated_cwd.mkdir()
    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONPATH"] = str(wheel.resolve())
    script = """
import hashlib
import importlib.resources
import json

from secaware.extractors import llm_direct_graph, llm_facts

package = importlib.resources.files("secaware.extractors")
facts = package.joinpath("prompts/llm_facts_v1.txt").read_bytes()
direct = package.joinpath("prompts/llm_direct_graph_v1.txt").read_bytes()
print(json.dumps({
    "facts_digest": hashlib.sha256(facts).hexdigest(),
    "facts_constant": llm_facts.LLM_FACTS_SYSTEM_TEMPLATE_SHA256,
    "facts_loader_digest": hashlib.sha256(
        llm_facts.LLM_FACTS_SYSTEM_TEMPLATE.encode("utf-8")
    ).hexdigest(),
    "facts_module": llm_facts.__file__,
    "direct_digest": hashlib.sha256(direct).hexdigest(),
    "direct_constant": llm_direct_graph.LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256,
    "direct_loader_digest": hashlib.sha256(
        llm_direct_graph.LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE.encode("utf-8")
    ).hexdigest(),
    "direct_module": llm_direct_graph.__file__,
}, sort_keys=True))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=isolated_cwd,
        env=env,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert ".whl" in payload["facts_module"]
    assert ".whl" in payload["direct_module"]
    assert {
        payload["facts_digest"],
        payload["facts_constant"],
        payload["facts_loader_digest"],
    } == {LLM_FACTS_SYSTEM_TEMPLATE_SHA256}
    assert {
        payload["direct_digest"],
        payload["direct_constant"],
        payload["direct_loader_digest"],
    } == {LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256}


_SECRET_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?P<key>(?:[a-z0-9]+[_-])?api[_-]?key|access[_-]?token|"
    r"client[_-]?secret|secret|password)"
    r"(?P<env>[_-]env)?\s*[:=]\s*(?P<value>[^#\r\n]*)"
)
_AUTHORIZATION_BEARER = re.compile(
    r"(?im)authorization\s*[:=]\s*['\"]?\s*bearer\s+(?P<value>[^'\"\s]+)"
)
_URL_USERINFO = re.compile(r"(?i)https?://(?P<username>[^/@\s:]+):(?P<password>[^/@\s]+)@[^/\s]+")
_PROVIDER_TOKEN = re.compile(
    r"(?:\bsk-[A-Za-z0-9_-]{20,}\b|\bghp_[A-Za-z0-9]{20,}\b|\bAIza[A-Za-z0-9_-]{20,}\b)"
)
_ENVIRONMENT_REFERENCE = re.compile(
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|"
    r"<[A-Za-z0-9 _-]*(?:env|environment)[A-Za-z0-9 _-]*>|[A-Z][A-Z0-9_]{2,})"
)
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _nonsecret_reference(value: str) -> bool:
    candidate = value.strip().strip("'\"")
    return _ENVIRONMENT_REFERENCE.fullmatch(candidate) is not None


def _embedded_secret_violations(text: str) -> list[str]:
    violations: list[str] = []
    for match in _SECRET_ASSIGNMENT.finditer(text):
        if match.group("env") is not None:
            environment_name = match.group("value").strip().strip("'\"")
            if _ENVIRONMENT_NAME.fullmatch(environment_name) is None:
                violations.append(f"invalid-{match.group('key').casefold()}-env")
            continue
        if _nonsecret_reference(match.group("value")):
            continue
        violations.append(f"literal-{match.group('key').casefold()}")
    for match in _AUTHORIZATION_BEARER.finditer(text):
        if not _nonsecret_reference(match.group("value")):
            violations.append("literal-authorization-bearer")
    for match in _URL_USERINFO.finditer(text):
        if not (
            _nonsecret_reference(match.group("username"))
            and _nonsecret_reference(match.group("password"))
        ):
            violations.append("url-userinfo")
    if _PROVIDER_TOKEN.search(text):
        violations.append("provider-token")
    return violations


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


def test_project_pins_offline_wheel_build_toolchain() -> None:
    project = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    for requirement in ("pip==25.0.1", "setuptools==83.0.0", "wheel==0.47.0"):
        assert f'"{requirement}"' in project


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
    assert not any(tmp_path.iterdir())
    original_generated = _project_generated_fingerprint()
    clean_source = tmp_path / "clean-source"
    _copy_clean_build_source(PROJECT_ROOT, clean_source)
    assert {path.name for path in clean_source.iterdir()} == {"README.md", "pyproject.toml", "src"}
    assert not any(
        path.name in {".git", ".venv", "build", "dist", "__pycache__"}
        or path.name.endswith(".egg-info")
        or path.suffix in {".pyc", ".pyo"}
        for path in clean_source.rglob("*")
    )
    wheel_dir = tmp_path / "wheelhouse"
    wheel_dir.mkdir()
    env = _offline_build_environment()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            ".",
        ],
        cwd=clean_source,
        env=env,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert _project_generated_fingerprint() == original_generated
    wheels = tuple(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        packaged = {
            member: archive.read(member)
            for member in (
                "secaware/extractors/prompts/llm_facts_v1.txt",
                "secaware/extractors/prompts/llm_direct_graph_v1.txt",
            )
        }

    expected = {
        "secaware/extractors/prompts/llm_facts_v1.txt": (
            LLM_FACTS_SYSTEM_TEMPLATE.encode("utf-8"),
            LLM_FACTS_SYSTEM_TEMPLATE_SHA256,
        ),
        "secaware/extractors/prompts/llm_direct_graph_v1.txt": (
            LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE.encode("utf-8"),
            LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256,
        ),
    }
    for member, payload in packaged.items():
        source_payload, expected_sha256 = expected[member]
        assert payload
        assert payload == source_payload
        assert hashlib.sha256(payload).hexdigest() == expected_sha256

    _assert_wheel_resources_load_in_isolation(wheels[0], tmp_path / "isolated")


def test_package_and_config_examples_contain_no_embedded_secrets() -> None:
    candidates = (
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "pyproject.toml",
        PROJECT_ROOT / "docs" / "migrations" / "prompt-tsg-v2.md",
        *(PROJECT_ROOT / "configs").glob("*.yaml"),
        *(PROJECT_ROOT / "src" / "secaware" / "extractors" / "prompts").glob("*.txt"),
    )
    violations = {
        path.relative_to(PROJECT_ROOT): tuple(_embedded_secret_violations(text))
        for path in candidates
        if (text := path.read_text(encoding="utf-8"))
        if _embedded_secret_violations(text)
    }
    assert violations == {}


@pytest.mark.parametrize(
    "snippet",
    (
        "api_key: sk-" + "exampleliteral0123456789",
        "openai_api_key: literal-api-key-value",
        "client_secret = 'literal-client-secret-value'",
        "Authorization: Bearer literal-access-token-value",
        "base_url: https://embedded-user:embedded-password@example.test/v1",
        "api_key_env: literal-client-secret-value",
        "api_key_env: ${OPENAI_API_KEY}",
        "api_key_env: 9OPENAI_API_KEY",
        "api_key_env: OPENAI API KEY",
    ),
)
def test_secret_gate_rejects_literal_credentials(snippet: str) -> None:
    assert _embedded_secret_violations(snippet)


@pytest.mark.parametrize(
    "snippet",
    (
        "api_key_env: OPENAI_API_KEY",
        "api_key: ${OPENAI_API_KEY}",
        "client_secret: <set-via-environment>",
        "Authorization: Bearer ${ACCESS_TOKEN}",
        "base_url: https://${API_USER}:${API_PASSWORD}@example.test/v1",
        "api_key_env: A",
        "api_key_env: _A",
        "api_key_env: openai_key_1",
    ),
)
def test_secret_gate_allows_nonsecret_environment_references(snippet: str) -> None:
    assert _embedded_secret_violations(snippet) == []
