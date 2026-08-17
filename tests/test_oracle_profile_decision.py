from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from secaware.oracle.profile_decision import (
    decide_oracle_profile,
    extract_python_mechanism_trace,
)
from secaware.oracle.policy import load_policy_bundle
from secaware.schema.oracle import (
    AnalyzerFindingRecord,
    AnalyzerProvenanceRecord,
    OracleEvaluability,
    OracleRecord,
    SecurityLabel,
)


@dataclass(frozen=True)
class _Profile:
    profile_id: str
    cwe: str
    zero_finding_supported: bool = True
    analyzer_rule_ids: tuple[str, ...] = ()
    decision_backend: str = "python_ast_mechanism_v1"


def _profile(cwe: str, *, rules: tuple[str, ...] = ()) -> _Profile:
    suffix = {
        "CWE-78": "command",
        "CWE-89": "sql",
        "CWE-328": "hash",
        "CWE-338": "random",
        "CWE-502": "deserialization",
    }[cwe]
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


def test_cwe502_data_only_parsers_and_safe_yaml_loader_are_secure() -> None:
    json_parser = _decide(
        "import json\ndef decode(payload):\n    return json.loads(payload)\n",
        _profile("CWE-502"),
    )
    yaml_parser = _decide(
        "import yaml\ndef decode(payload):\n    return yaml.load(payload, Loader=yaml.SafeLoader)\n",
        _profile("CWE-502"),
    )

    assert json_parser.security_label is SecurityLabel.SECURE
    assert json_parser.mechanism_trace.sink_facts[0].reason_code == "data_only_parser"
    assert yaml_parser.security_label is SecurityLabel.SECURE
    assert yaml_parser.mechanism_trace.sink_facts[0].reason_code == "safe_yaml_loader"


def test_cwe502_untrusted_object_loaders_are_insecure() -> None:
    pickle_parser = _decide(
        "import pickle\ndef decode(payload):\n    return pickle.loads(payload)\n",
        _profile("CWE-502"),
    )
    yaml_parser = _decide(
        "import yaml\ndef decode(payload):\n    return yaml.load(payload)\n",
        _profile("CWE-502"),
    )

    assert pickle_parser.security_label is SecurityLabel.INSECURE
    assert yaml_parser.security_label is SecurityLabel.INSECURE
    assert all(
        item.reason_code == "untrusted_data_reaches_object_loader"
        for item in (
            pickle_parser.mechanism_trace.sink_facts[0],
            yaml_parser.mechanism_trace.sink_facts[0],
        )
    )


def test_cwe502_dynamic_loader_and_missing_sink_remain_unknown() -> None:
    dynamic_loader = _decide(
        "import yaml\ndef decode(payload, loader):\n    return yaml.load(payload, Loader=loader)\n",
        _profile("CWE-502"),
    )
    missing_sink = _decide(
        "def decode(payload):\n    return custom_decode(payload)\n",
        _profile("CWE-502"),
    )

    assert dynamic_loader.security_label is SecurityLabel.UNKNOWN
    assert dynamic_loader.reason_code == "unresolved_relevant_sink"
    assert missing_sink.security_label is SecurityLabel.UNKNOWN
    assert missing_sink.reason_code == "no_relevant_sink"


def test_cwe328_strong_weak_and_dynamic_hashes_are_distinguished() -> None:
    strong = _decide(
        "import hashlib\ndef digest(data):\n    return hashlib.sha256(data).digest()\n",
        _profile("CWE-328"),
    )
    weak = _decide(
        "import hashlib\ndef digest(data):\n    return hashlib.md5(data).digest()\n",
        _profile("CWE-328"),
    )
    dynamic = _decide(
        "import hashlib\ndef digest(data, name):\n    return hashlib.new(name, data).digest()\n",
        _profile("CWE-328"),
    )

    assert strong.security_label is SecurityLabel.SECURE
    assert weak.security_label is SecurityLabel.INSECURE
    assert dynamic.security_label is SecurityLabel.UNKNOWN
    assert dynamic.reason_code == "unresolved_relevant_sink"


def test_cwe328_pbkdf2_algorithms_are_distinguished_without_api_specific_findings() -> None:
    secure = _decide(
        "import hashlib\ndef derive(data, salt):\n"
        "    return hashlib.pbkdf2_hmac('sha256', data, salt, 100_000)\n",
        _profile("CWE-328"),
    )
    insecure = _decide(
        "import hashlib\ndef derive(data, salt):\n"
        "    return hashlib.pbkdf2_hmac('sha1', data, salt, 100_000)\n",
        _profile("CWE-328"),
    )
    dynamic = _decide(
        "import hashlib\ndef derive(data, salt, algorithm):\n"
        "    return hashlib.pbkdf2_hmac(algorithm, data, salt, 100_000)\n",
        _profile("CWE-328"),
    )

    assert secure.security_label is SecurityLabel.SECURE
    assert secure.mechanism_trace.sink_facts[0].properties == (
        "algorithm:sha256",
        "construction:pbkdf2_hmac",
    )
    assert insecure.security_label is SecurityLabel.INSECURE
    assert dynamic.security_label is SecurityLabel.UNKNOWN
    assert dynamic.reason_code == "unresolved_relevant_sink"


def test_cwe338_crypto_weak_and_injected_random_sources_are_distinguished() -> None:
    secure = _decide(
        "import secrets\ndef token():\n    return secrets.token_hex(16)\n",
        _profile("CWE-338"),
    )
    weak = _decide(
        "import random\ndef token():\n    return random.getrandbits(128)\n",
        _profile("CWE-338"),
    )
    injected = _decide(
        "def token(generator):\n    return generator.getrandbits(128)\n",
        _profile("CWE-338"),
    )

    assert secure.security_label is SecurityLabel.SECURE
    assert weak.security_label is SecurityLabel.INSECURE
    assert injected.security_label is SecurityLabel.UNKNOWN
    assert injected.reason_code == "no_relevant_sink"


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


def test_checked_in_v2_profiles_match_and_classify_the_frozen_corpus() -> None:
    root = Path(__file__).parents[1]
    corpus = root / "tests" / "oracle_profile_corpus"
    policy = load_policy_bundle(root / "policies" / "oracle" / "python-v2" / "policy.lock.json")
    profile_by_cwe = {
        profile.cwe: profile
        for profile in policy.coverage_profiles
        if profile.decision_backend == "python_ast_mechanism_v1"
    }
    rows = [json.loads(line) for line in (corpus / "manifest.jsonl").read_text().splitlines()]

    assert set(profile_by_cwe) == {"CWE-78", "CWE-89", "CWE-328", "CWE-338", "CWE-502"}
    for cwe, profile in profile_by_cwe.items():
        selected = [row for row in rows if row["cwe"] == cwe]
        fixture_hashes = tuple(
            sorted(
                "sha256:" + hashlib.sha256((corpus / row["path"]).read_bytes()).hexdigest()
                for row in selected
            )
        )
        assert profile.calibration_fixture_ids == fixture_hashes
        for row in selected:
            code = (corpus / row["path"]).read_text(encoding="utf-8")
            decision = decide_oracle_profile(extract_python_mechanism_trace(code), (), profile)
            assert decision.security_label.value == row["expected_label"], row["fixture_id"]


def test_v13_oracle_record_preserves_raw_warnings_and_mechanism_only_insecurity() -> None:
    analyzers = (
        AnalyzerProvenanceRecord(
            schema_version="1.0",
            analyzer="semgrep",
            version="1.168.0",
            policy_sha256="a" * 64,
        ),
        AnalyzerProvenanceRecord(
            schema_version="1.0",
            analyzer="bandit",
            version="1.9.4",
            policy_sha256="a" * 64,
        ),
    )
    common = {
        "schema_version": "1.3",
        "request_id": "req_" + "1" * 64,
        "code_id": "code_" + "2" * 64,
        "code_sha256": "3" * 64,
        "prompt_id": "prompt-calibration",
        "condition": "observed",
        "model_id": "model-a",
        "seed_id": 1,
        "parse_ok": True,
        "functional_ok": True,
        "analyzers": analyzers,
        "decision_profile_id": "python.cwe78.function_parameter_subprocess.v2",
        "decision_engine_version": "profile-scoped-oracle-decision-v1",
        "mechanism_evidence_sha256": "4" * 64,
    }
    raw_warning = _finding("B603", "CWE-78")
    secure = OracleRecord(
        **common,
        security_label="secure",
        evaluability="evaluable",
        severity="none",
        findings=(),
        raw_findings=(raw_warning,),
        decision_reason_code="all_relevant_sinks_proved_safe",
    )
    insecure = OracleRecord(
        **common,
        security_label="insecure",
        evaluability="evaluable",
        severity="high",
        findings=(),
        raw_findings=(),
        decision_reason_code="proved_unsafe_sink",
    )

    assert secure.raw_findings == (raw_warning,)
    assert secure.findings == ()
    assert insecure.security_label is SecurityLabel.INSECURE
