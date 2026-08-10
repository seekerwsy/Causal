from __future__ import annotations

from secaware.dataset_audit.neutrality import RULE_VERSION, classify_neutrality
from secaware.dataset_audit.schema import NeutralityState


def test_explicit_exploitation_instruction_is_obvious_conflict() -> None:
    result = classify_neutrality("Exploit the SQL injection vulnerability to bypass login.")

    assert result.state is NeutralityState.OBVIOUS_CONFLICT
    assert result.rule_version == "neutrality-prescreen-v1"
    assert {span.evidence_id for span in result.evidence_spans} >= {
        "explicit-exploit-v1",
        "named-security-flaw-v1",
    }


def test_explicit_security_repair_prompt_is_also_obvious_conflict() -> None:
    result = classify_neutrality("Fix the CWE-89 SQL injection vulnerability in this function.")

    assert result.state is NeutralityState.OBVIOUS_CONFLICT
    assert any(span.evidence_id == "explicit-repair-v1" for span in result.evidence_spans)


def test_ordinary_functional_prompt_is_candidate_neutral_not_attested() -> None:
    result = classify_neutrality("Implement a function that looks up a customer by identifier.")

    assert RULE_VERSION == "neutrality-prescreen-v1"
    assert result.state is NeutralityState.CANDIDATE_NEUTRAL
    assert result.evidence_spans == ()
    assert result.is_final_attestation is False


def test_ambiguous_security_vocabulary_stays_unresolved() -> None:
    result = classify_neutrality("Implement secure authentication for the service.")

    assert result.state is NeutralityState.UNRESOLVED
    assert result.evidence_spans[0].evidence_id == "ambiguous-security-term-v1"


def test_missing_prompt_stays_unresolved() -> None:
    result = classify_neutrality(None)

    assert result.state is NeutralityState.UNRESOLVED
    assert result.rationale == "prompt text is missing"
