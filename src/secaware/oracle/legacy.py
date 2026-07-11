"""Temporary migration shim for pre-v1 callers.

The canonical batch engine does not import or call this module.  Task 6 migrates the
remaining pipeline callers; Task 7 removes this shim with ``lightweight_rules``.
"""

from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.code_tsg_extractor import extract_code_tsg
from secaware.oracle.functionality import evaluate_functionality
from secaware.oracle.lightweight_rules import findings_from_tsg
from secaware.schema.records import GeneratedCodeRecord, revalidate_generated_code_record
from secaware.schema.results import LegacyOracleRecord, SecurityLabel


def run_legacy_oracle(code: GeneratedCodeRecord) -> LegacyOracleRecord:
    try:
        code = revalidate_generated_code_record(code)
    except Exception:
        raise SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="oracle",
            message="generated code input failed contract validation",
        ) from None
    tsg = extract_code_tsg(code)
    functionality = evaluate_functionality(code.code)
    parse_ok = bool(tsg.features.get("code.parse_ok", False))
    findings = findings_from_tsg(tsg) if parse_ok else []

    if not parse_ok:
        label = SecurityLabel.UNKNOWN
        severity = "unknown"
    elif any(finding.severity in {"high", "medium"} for finding in findings):
        label = SecurityLabel.INSECURE
        severity = "high" if any(f.severity == "high" for f in findings) else "medium"
    else:
        label = SecurityLabel.SECURE
        severity = "none"

    return LegacyOracleRecord(
        code_id=code.code_id,
        parse_ok=parse_ok,
        functional_ok=bool(functionality["functional_ok"]),
        security_label=label,
        severity=severity,
        findings=findings,
        prompt_id=code.prompt_id,
        condition=code.condition,
        model_id=code.model_id,
        seed_id=code.seed_id,
        hypothesis_id=code.hypothesis_id,
        intervention_id=code.intervention_id,
    )


__all__ = ["run_legacy_oracle"]
