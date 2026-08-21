from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import re
from typing import Any

from secaware.dataset_audit.fingerprints import exact_prompt_sha256, normalized_prompt_sha256
from secaware.dataset_audit.schema import (
    AdaptedRecord,
    CweEvidence,
    EvidenceSpan,
    FunctionalState,
    SourceCoordinate,
)


_PROMPT_FIELDS = (
    "prompt",
    "Prompt",
    "test_case_prompt",
    "instruction",
    "question",
    "text",
    "description",
    "task_description",
)
_ID_FIELDS = ("prompt_id", "task_id", "sample_id", "ID", "id")
_LANGUAGE_FIELDS = ("language", "lang", "programming_language")
_CWE_FIELDS = (
    "cwe",
    "CWE",
    "cwe_id",
    "cwe_ids",
    "cwe_identifier",
    "weakness",
)
_FUNCTIONAL_EXECUTABLE_FIELDS = (
    "test",
    "tests",
    "test_list",
    "challenge_test_list",
    "input_output",
    "unit_tests",
    "test_cases",
    "entry_point",
    "functional_eval",
)
_LANGUAGE_ALIASES = {
    "py": "python",
    "python": "python",
    "js": "javascript",
    "javascript": "javascript",
}
_FUNCTIONAL_REFERENCE_FIELDS = (
    "test_path",
    "test_case_path",
    "functional_eval_harness",
    "canonical_solution",
    "reference_solution",
)
_CWE_PATTERN = re.compile(r"(?i)(?<![A-Z0-9])CWE[-_ ]?0*([0-9]+)(?![0-9])")
_CWE_FILE_PATTERN = re.compile(r"(?i)(?:^|[/\\])cwe_0*([0-9]+)_")


def _first_nonempty(raw: Mapping[str, Any], fields: tuple[str, ...]) -> tuple[str, str] | None:
    for field in fields:
        value = raw.get(field)
        if isinstance(value, str) and value.strip():
            return field, value.strip()
        if field in _ID_FIELDS and isinstance(value, int) and not isinstance(value, bool):
            return field, str(value)
    return None


def _cwe_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        values = _CWE_PATTERN.findall(value)
    elif isinstance(value, (list, tuple)):
        values = [
            match
            for item in value
            if isinstance(item, str)
            for match in _CWE_PATTERN.findall(item)
        ]
    else:
        values = []
    return tuple(sorted({f"CWE-{int(number)}" for number in values}))


def _span(field: str, text: str, evidence_id: str) -> EvidenceSpan:
    return EvidenceSpan(
        field=field,
        start=0,
        end=len(text),
        text=text,
        evidence_id=evidence_id,
    )


def _cwe_evidence(raw: Mapping[str, Any], source_id: str) -> tuple[
    tuple[str, ...], CweEvidence, tuple[EvidenceSpan, ...]
]:
    explicit: set[str] = set()
    spans: list[EvidenceSpan] = []
    for field in _CWE_FIELDS:
        if field not in raw:
            continue
        values = _cwe_values(raw[field])
        if values:
            explicit.update(values)
            text = str(raw[field])
            spans.append(_span(field, text, "explicit-cwe-field-v1"))

    identifier: set[str] = set()
    for field in _ID_FIELDS:
        value = raw.get(field)
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            continue
        text = str(value)
        values = _cwe_values(text)
        if values:
            identifier.update(values)
            spans.append(_span(field, text, "source-id-cwe-v1"))

    mapping: set[str] = set()
    if source_id in {"cweval", "cweval_python"}:
        file_path = raw.get("file_path")
        if isinstance(file_path, str):
            matched = _CWE_FILE_PATTERN.search(file_path)
            if matched:
                mapping.add(f"CWE-{int(matched.group(1))}")
                spans.append(_span("file_path", file_path, "cweval-file-path-v1"))

    all_sets = [values for values in (explicit, identifier, mapping) if values]
    all_values = tuple(
        sorted(explicit | identifier | mapping, key=lambda value: int(value[4:]))
    )
    if len(all_sets) > 1 and any(values != all_sets[0] for values in all_sets[1:]):
        return all_values, CweEvidence.CONFLICTING, tuple(spans)
    if explicit:
        return all_values, CweEvidence.EXPLICIT_FIELD, tuple(spans)
    if identifier:
        return all_values, CweEvidence.SOURCE_ID_PARSE, tuple(spans)
    if mapping:
        return all_values, CweEvidence.SOURCE_MAPPING, tuple(spans)
    return (), CweEvidence.UNRESOLVED, ()


def _functional_evidence(
    raw: Mapping[str, Any],
) -> tuple[FunctionalState, tuple[EvidenceSpan, ...]]:
    executable: list[EvidenceSpan] = []
    references: list[EvidenceSpan] = []
    for field in _FUNCTIONAL_EXECUTABLE_FIELDS:
        value = raw.get(field)
        if value not in (None, "", [], {}):
            executable.append(_span(field, str(value), "functional-contract-field-v1"))
    for field in _FUNCTIONAL_REFERENCE_FIELDS:
        value = raw.get(field)
        if value not in (None, "", [], {}):
            references.append(_span(field, str(value), "functional-reference-field-v1"))
    if executable:
        return FunctionalState.PRESENT_UNVALIDATED, tuple(executable + references)
    if references:
        return FunctionalState.REFERENCE_ONLY, tuple(references)
    return FunctionalState.ABSENT, ()


def adapt_record(
    *,
    source_id: str,
    source_path: Path,
    line_number: int,
    raw: Mapping[str, Any],
) -> AdaptedRecord:
    identity = _first_nonempty(raw, _ID_FIELDS)
    record_id = identity[1] if identity is not None else None
    prompt_value = _first_nonempty(raw, _PROMPT_FIELDS)
    prompt = prompt_value[1] if prompt_value is not None else None
    language_value = _first_nonempty(raw, _LANGUAGE_FIELDS)
    language_token = language_value[1].casefold() if language_value is not None else None
    language = _LANGUAGE_ALIASES.get(language_token, language_token)
    cwe_ids, cwe_evidence, cwe_spans = _cwe_evidence(raw, source_id)
    functional_state, functional_spans = _functional_evidence(raw)
    return AdaptedRecord(
        coordinate=SourceCoordinate(
            source_id=source_id,
            relative_path=Path(source_path).as_posix(),
            line_number=line_number,
            record_id=record_id,
        ),
        prompt=prompt,
        language=language,
        cwe_ids=cwe_ids,
        cwe_evidence=cwe_evidence,
        cwe_evidence_spans=cwe_spans,
        exact_prompt_sha256=exact_prompt_sha256(prompt) if prompt is not None else None,
        normalized_prompt_sha256=(
            normalized_prompt_sha256(prompt) if prompt is not None else None
        ),
        functional_state=functional_state,
        functional_evidence_spans=functional_spans,
    )
