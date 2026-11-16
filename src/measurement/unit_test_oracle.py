"""Deterministic subprocess Python unit-test Oracle for functional evaluation."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from prompt_mechanism_study.records import content_hash


_HARNESS_CODE = """\
from pathlib import Path
import traceback
import sys

try:
    ns = {"__name__": "candidate_module"}
    cand_src = Path("candidate_module.py").read_text(encoding="utf-8")
    exec(compile(cand_src, "candidate_module.py", "exec"), ns)
    test_src = Path("test_script.py").read_text(encoding="utf-8")
    exec(compile(test_src, "test_script.py", "exec"), ns)
except BaseException:
    traceback.print_exc()
    sys.exit(1)
"""


def evaluate_python_unit_tests(
    code: str,
    test_script: str,
    *,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Execute deterministic Python unit tests against candidate code in a temp dir."""
    if not isinstance(code, str) or not code.strip():
        digest = content_hash({"code_sha256": content_hash(code or ""), "test_sha256": content_hash(test_script), "functional_label": "fail", "exit_code": 1})
        return {
            "functional_label": "fail",
            "passed": False,
            "exit_code": 1,
            "failure_reason": "empty_code",
            "evidence_sha256": digest,
        }
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    code_sha = content_hash(code)
    test_sha = content_hash(test_script)
    venv_bin = str(Path(sys.executable).parent)
    base_path = os.environ.get("PATH", "")
    env = {
        "PATH": f"{venv_bin}{os.pathsep}{base_path}" if base_path else venv_bin,
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
    }

    with tempfile.TemporaryDirectory(prefix="pms_ut_") as tmp_dir:
        work = Path(tmp_dir)
        (work / "candidate_module.py").write_text(code, encoding="utf-8", newline="\n")
        (work / "test_script.py").write_text(test_script, encoding="utf-8", newline="\n")
        (work / "harness.py").write_text(_HARNESS_CODE, encoding="utf-8", newline="\n")
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "harness.py"],
                cwd=work,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=float(timeout_seconds),
                check=False,
            )
            exit_code = int(proc.returncode)
            passed = exit_code == 0
            label = "pass" if passed else "fail"
            if passed:
                reason = None
            else:
                tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-4:]
                reason = " | ".join(tail) if tail else f"exit_code={exit_code}"
        except subprocess.TimeoutExpired:
            exit_code = -1
            passed = False
            label = "fail"
            reason = f"timeout_after_{timeout_seconds}s"

    evidence_sha = content_hash(
        {
            "code_sha256": code_sha,
            "test_sha256": test_sha,
            "functional_label": label,
            "exit_code": exit_code,
        }
    )
    return {
        "functional_label": label,
        "passed": passed,
        "exit_code": exit_code,
        "failure_reason": reason,
        "evidence_sha256": evidence_sha,
    }
