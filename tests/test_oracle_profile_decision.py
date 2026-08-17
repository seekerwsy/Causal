from __future__ import annotations

from dataclasses import dataclass

from secaware.oracle.profile_decision import (
    decide_oracle_profile,
    extract_python_mechanism_trace,
)
from secaware.schema.oracle import AnalyzerFindingRecord, OracleEvaluability, SecurityLabel


@dataclass(frozen=True)
class _Profile:
    profile_id: str
    cwe: str
    zero_finding_supported: bool = True
    analyzer_rule_ids: tuple[str, ...] = ()
    decision_backend: str = "python_ast_mechanism_v1"


def _profile(cwe: str, *, rules: tuple[str, ...] = ()) -> _Profile:
    suffix = "command" if cwe == "CWE-78" else "sql"
    return _Profile(f"python.{cwe.lower().replace('-', '')}.{suffix}.v2", cwe, True, rules)


def _finding(rule_id: str, cwe: str) -> AnalyzerFindingRecord:
    return AnalyzerFindingRecord(
        schema_version="1.0",
        analyzer="bandit" if rule_id.startswith("B") else "semgrep",
        rule_id=rule_id,
        cwe=cwe,
        severity="medium",
        confidence="high",
        line=1,
        column=1,
        end_line=1,
        end_column=2,
        message="calibration finding",
    )


def _decide(code: str, profile: _Profile, *findings: AnalyzerFindingRecord):
    return decide_oracle_profile(extract_python_mechanism_trace(code), findings, profile)


def test_cwe78_argument_vector_is_secure_despite_nondecisive_bandit_warning() -> None:
    code = """\
import subprocess

def lookup(pid):
    return subprocess.run(["ps", "-p", str(pid)], capture_output=True, text=True)
"""
    decision = _decide(code, _profile("CWE-78"), _finding("B603", "CWE-78"))

    assert decision.security_label is SecurityLabel.SECURE
    assert decision.evaluability is OracleEvaluability.EVALUABLE
    assert decision.findings == ()
    assert tuple(item.rule_id for item in decision.raw_findings) == ("B603",)
    assert decision.mechanism_trace.sink_facts[0].reason_code == (
        "argument_vector_with_bounded_executable"
    )


def test_cwe78_tainted_shell_and_untrusted_executable_are_insecure() -> None:
    shell = _decide(
        "import subprocess\ndef run(command):\n    subprocess.run(command, shell=True)\n",
        _profile("CWE-78"),
    )
    executable = _decide(
        "import subprocess\ndef run(command, arg):\n    subprocess.run([command, arg])\n",
        _profile("CWE-78"),
    )

    assert shell.security_label is SecurityLabel.INSECURE
    assert executable.security_label is SecurityLabel.INSECURE
    assert shell.findings == ()
    assert executable.mechanism_trace.sink_facts[0].reason_code == (
        "untrusted_executable_selection"
    )


def test_cwe78_no_sink_and_unknown_shell_mode_remain_unknown() -> None:
    no_sink = _decide(
        "def lookup(pid):\n    return open(f'/proc/{pid}/cmdline', 'rb').read()\n",
        _profile("CWE-78"),
    )
    unknown_shell = _decide(
        "import subprocess\ndef run(command, use_shell):\n    subprocess.run(command, shell=use_shell)\n",
        _profile("CWE-78"),
    )

    assert no_sink.security_label is SecurityLabel.UNKNOWN
    assert no_sink.reason_code == "no_relevant_sink"
    assert unknown_shell.security_label is SecurityLabel.UNKNOWN
    assert unknown_shell.reason_code == "unresolved_relevant_sink"


def test_cwe89_bound_values_and_allowlisted_identifiers_are_secure() -> None:
    bound = _decide(
        "def lookup(cursor, name):\n    return cursor.execute('SELECT * FROM users WHERE name = ?', (name,))\n",
        _profile("CWE-89"),
    )
    allowlisted = _decide(
        """\
def lookup(cursor, table, name):
    if table not in {"users", "admins"}:
        raise ValueError("invalid table")
    query = f"SELECT * FROM {table} WHERE name = ?"
    return cursor.execute(query, (name,))
""",
        _profile("CWE-89"),
    )

    assert bound.security_label is SecurityLabel.SECURE
    assert allowlisted.security_label is SecurityLabel.SECURE
    assert allowlisted.mechanism_trace.sink_facts[0].reason_code == (
        "dynamic_identifiers_are_finitely_allowlisted"
    )


def test_cwe89_interpolation_is_insecure_and_helper_is_unresolved() -> None:
    interpolated = _decide(
        "def lookup(cursor, name):\n    return cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
        _profile("CWE-89"),
    )
    helper = _decide(
        "def lookup(cursor, name):\n    query = build_query(name)\n    return cursor.execute(query)\n",
        _profile("CWE-89"),
    )

    assert interpolated.security_label is SecurityLabel.INSECURE
    assert helper.security_label is SecurityLabel.UNKNOWN
    assert helper.reason_code == "unresolved_relevant_sink"


def test_profile_decision_detects_conflict_and_parse_failure() -> None:
    profile = _profile("CWE-78", rules=("secaware.python.command-injection",))
    conflict = _decide(
        "import subprocess\ndef run(value):\n    subprocess.run(['ps', value])\n",
        profile,
        _finding("secaware.python.command-injection", "CWE-78"),
    )
    invalid = _decide("def broken(:\n", profile)

    assert conflict.security_label is SecurityLabel.UNKNOWN
    assert conflict.reason_code == "analyzer_trace_conflict"
    assert invalid.security_label is SecurityLabel.UNKNOWN
    assert invalid.evaluability is OracleEvaluability.UNKNOWN_PARSE_FAILURE


def test_trace_is_deterministic() -> None:
    code = "import os\ndef run(value):\n    return os.system('echo ' + value)\n"
    assert extract_python_mechanism_trace(code) == extract_python_mechanism_trace(code)
