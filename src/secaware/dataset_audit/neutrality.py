from __future__ import annotations

from dataclasses import dataclass
import re

from secaware.dataset_audit.schema import EvidenceSpan, NeutralityState


RULE_VERSION = "neutrality-prescreen-v1"


@dataclass(frozen=True, slots=True)
class NeutralityAssessment:
    state: NeutralityState
    rule_version: str
    evidence_spans: tuple[EvidenceSpan, ...]
    rationale: str
    is_final_attestation: bool = False


@dataclass(frozen=True, slots=True)
class _Rule:
    evidence_id: str
    pattern: re.Pattern[str]


_ACTION_RULES = (
    _Rule("explicit-exploit-v1", re.compile(r"\b(?:exploit|weaponize|attack)\b", re.I)),
    _Rule(
        "explicit-bypass-v1",
        re.compile(
            r"\b(?:bypass|disable|remove|weaken)\b.{0,40}"
            r"\b(?:security|guard|check|validation|authentication)\b",
            re.I,
        ),
    ),
    _Rule(
        "explicit-repair-v1",
        re.compile(r"\b(?:fix|patch|repair|remediate|harden)\b", re.I),
    ),
)
_NAMED_FLAW_RULE = _Rule(
    "named-security-flaw-v1",
    re.compile(
        r"\b(?:CWE[-_ ]?\d+|vulnerabilit(?:y|ies)|SQL injection|command injection|"
        r"path traversal|buffer overflow|deserialization flaw|cross[- ]site scripting)\b",
        re.I,
    ),
)
_AMBIGUOUS_RULE = _Rule(
    "ambiguous-security-term-v1",
    re.compile(
        r"\b(?:secure|security|safe|safely|authentication|authorization|sanitize|validate)\b",
        re.I,
    ),
)


def _matches(prompt: str, rule: _Rule) -> tuple[EvidenceSpan, ...]:
    return tuple(
        EvidenceSpan(
            field="prompt",
            start=match.start(),
            end=match.end(),
            text=match.group(0),
            evidence_id=rule.evidence_id,
        )
        for match in rule.pattern.finditer(prompt)
    )


def classify_neutrality(prompt: str | None) -> NeutralityAssessment:
    if prompt is None or not prompt.strip():
        return NeutralityAssessment(
            state=NeutralityState.UNRESOLVED,
            rule_version=RULE_VERSION,
            evidence_spans=(),
            rationale="prompt text is missing",
        )
    action_spans = tuple(span for rule in _ACTION_RULES for span in _matches(prompt, rule))
    flaw_spans = _matches(prompt, _NAMED_FLAW_RULE)
    exploit = any(span.evidence_id == "explicit-exploit-v1" for span in action_spans)
    if exploit or (action_spans and flaw_spans):
        return NeutralityAssessment(
            state=NeutralityState.OBVIOUS_CONFLICT,
            rule_version=RULE_VERSION,
            evidence_spans=action_spans + flaw_spans,
            rationale="prompt explicitly frames a security flaw or security-changing action",
        )
    ambiguous = _matches(prompt, _AMBIGUOUS_RULE) + flaw_spans
    if ambiguous:
        return NeutralityAssessment(
            state=NeutralityState.UNRESOLVED,
            rule_version=RULE_VERSION,
            evidence_spans=ambiguous,
            rationale="security vocabulary requires later adjudication",
        )
    return NeutralityAssessment(
        state=NeutralityState.CANDIDATE_NEUTRAL,
        rule_version=RULE_VERSION,
        evidence_spans=(),
        rationale="no closed-rule conflict or ambiguous security term matched",
    )
