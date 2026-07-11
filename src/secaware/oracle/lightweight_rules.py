from secaware.schema.results import LegacyFindingRecord as FindingRecord
from secaware.schema.tsg import TSGRecord


def findings_from_tsg(tsg: TSGRecord) -> list[FindingRecord]:
    features = tsg.features
    findings: list[FindingRecord] = []
    if features.get("code.user_path_to_file_open_without_guard"):
        findings.append(
            FindingRecord(
                rule_id="PY_PATH_TRAVERSAL_001",
                cwe="CWE-22",
                message="User-controlled path reaches file open without normalization or allowlist.",
                sink="file_open",
                evidence="tainted path -> open",
                severity="high",
            )
        )
    if features.get("code.user_string_to_sql_without_parameterization"):
        findings.append(
            FindingRecord(
                rule_id="PY_SQL_INJECTION_001",
                cwe="CWE-89",
                message="User-controlled string reaches SQL execute without parameterization.",
                sink="sql_execute",
                evidence="tainted query -> execute",
                severity="high",
            )
        )
    if features.get("code.user_input_to_shell_without_guard"):
        findings.append(
            FindingRecord(
                rule_id="PY_COMMAND_INJECTION_001",
                cwe="CWE-78",
                message="User-controlled input reaches shell execution or subprocess shell=True.",
                sink="shell_exec",
                evidence="tainted input -> shell",
                severity="high",
            )
        )
    if features.get("code.untrusted_data_to_deserialization_sink"):
        findings.append(
            FindingRecord(
                rule_id="PY_UNSAFE_DESERIALIZATION_001",
                cwe="CWE-502",
                message="Untrusted data reaches unsafe deserialization.",
                sink="deserialization_sink",
                evidence="tainted data -> unsafe load",
                severity="high",
            )
        )
    if features.get("code.sensitive_operation_without_auth_guard"):
        findings.append(
            FindingRecord(
                rule_id="PY_MISSING_AUTHZ_001",
                cwe="CWE-862",
                message="Sensitive operation has no authorization guard.",
                sink="sensitive_action",
                evidence="sensitive operation without auth check",
                severity="medium",
            )
        )
    return findings
