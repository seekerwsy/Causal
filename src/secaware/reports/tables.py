"""Deterministic, side-effect-free rendering for Prompt-only reports."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import html
from io import StringIO
import json
from typing import Iterable, Mapping, Sequence

from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BootstrapFailureRecord,
    DiscoveryFailureRecord,
    FrozenHypothesisRecord,
)
from secaware.schema.experiments import (
    AssignmentRecord,
    GraphDeltaRecord,
    PreRandomizationExclusionRecord,
    PromptVariantRecord,
)
from secaware.schema.outcomes import (
    AnalysisFailureRecord,
    AssignmentOutcomeRecord,
    ITTEffectRecord,
    JCIOrientationDeltaRecord,
    RFCICapabilityRecord,
)


EFFECT_FIELDS = (
    "schema_version",
    "effect_id",
    "hypothesis_id",
    "target_spec_id",
    "arm_protocol_id",
    "model_id",
    "contrast_id",
    "outcome_id",
    "treatment_n",
    "control_n",
    "independent_task_n",
    "risk_difference",
    "ci_low",
    "ci_high",
    "sensitivity_low",
    "sensitivity_high",
    "status",
    "assignment_universe_sha256",
    "target_instance_universe_sha256",
    "bootstrap_manifest_sha256",
)

JCI_ORIENTATION_FIELDS = (
    "schema_version",
    "delta_id",
    "raw_pag_id",
    "constrained_pag_id",
    "assumption_ids",
    "assumption_set_sha256",
    "per_assumption_attribution",
    "changes",
)

FAILURE_FIELDS = (
    "source_stage",
    "record_id",
    "subject_id",
    "reason_code",
    "config_sha256",
    "input_bundle_sha256",
    "detail_sha256",
)

RFCI_CAPABILITY_PREFIX = "- RFCI capability record: "
_MARKDOWN_CODE_ESCAPES = frozenset("\\`[]()\r\n")


@dataclass(frozen=True, slots=True)
class ReportDocuments:
    discovery_pags: bytes
    hypotheses: bytes
    interventions: bytes
    assignments: bytes
    effects: bytes
    jci_orientations: bytes
    failures: bytes
    hypothesis_cards: bytes
    summary: bytes

    def ordered(self) -> tuple[bytes, ...]:
        return (
            self.discovery_pags,
            self.hypotheses,
            self.interventions,
            self.assignments,
            self.effects,
            self.jci_orientations,
            self.failures,
            self.hypothesis_cards,
            self.summary,
        )


def canonical_jsonl_bytes(records: Iterable[Mapping[str, object]]) -> bytes:
    lines = tuple(
        json.dumps(
            dict(record),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        for record in records
    )
    return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")


def canonical_markdown_code(value: str) -> str:
    escaped = html.escape(value, quote=True)
    encoded = "".join(
        f"&#{ord(character)};"
        if character in _MARKDOWN_CODE_ESCAPES or ord(character) < 0x20
        else character
        for character in escaped
    )
    return f"`{encoded}`"


def decode_canonical_markdown_code(value: str) -> str:
    if len(value) < 2 or value[0] != "`" or value[-1] != "`" or "\n" in value or "\r" in value:
        raise ValueError("report Markdown scalar failed validation")
    decoded = html.unescape(value[1:-1])
    if canonical_markdown_code(decoded) != value:
        raise ValueError("report Markdown scalar failed validation")
    return decoded


def _csv_value(value: object) -> object:
    if value is None:
        return ""
    if type(value) is bool:
        return "true" if value else "false"
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    return value


def canonical_csv_bytes(
    fields: Sequence[str],
    rows: Iterable[Mapping[str, object]],
) -> bytes:
    handle = StringIO(newline="")
    writer = csv.DictWriter(
        handle,
        fieldnames=list(fields),
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({field: _csv_value(row.get(field)) for field in fields})
    return handle.getvalue().encode("utf-8")


def build_intervention_rows(
    variants: Sequence[PromptVariantRecord],
    deltas: Sequence[GraphDeltaRecord],
) -> tuple[dict[str, object], ...]:
    delta_by_id = {item.delta_id: item for item in deltas}
    if len(delta_by_id) != len(deltas) or {item.delta_id for item in variants} != set(delta_by_id):
        raise ValueError("report intervention provenance failed validation")
    rows: list[dict[str, object]] = []
    for variant in sorted(variants, key=lambda item: item.variant_id):
        delta = delta_by_id[variant.delta_id]
        payload = variant.model_dump(mode="json", exclude={"prompt_text"})
        payload["graph_delta"] = delta.model_dump(mode="json")
        digest = canonical_sha256(payload)
        rows.append(
            {
                **payload,
                "report_record_id": f"reported_intervention_{digest}",
                "report_record_sha256": digest,
            }
        )
    return tuple(rows)


def build_assignment_rows(
    assignments: Sequence[AssignmentRecord],
    outcomes: Sequence[AssignmentOutcomeRecord],
) -> tuple[dict[str, object], ...]:
    outcome_by_assignment = {item.assignment_id: item for item in outcomes}
    if len(outcome_by_assignment) != len(outcomes) or {
        item.assignment_id for item in assignments
    } != set(outcome_by_assignment):
        raise ValueError("report assignment provenance failed validation")
    rows: list[dict[str, object]] = []
    for assignment in sorted(assignments, key=lambda item: item.assignment_id):
        payload = assignment.model_dump(mode="json")
        payload["assignment_outcome"] = outcome_by_assignment[assignment.assignment_id].model_dump(
            mode="json"
        )
        digest = canonical_sha256(payload)
        rows.append(
            {
                **payload,
                "report_record_id": f"reported_assignment_{digest}",
                "report_record_sha256": digest,
            }
        )
    return tuple(rows)


def build_effect_rows(effects: Sequence[ITTEffectRecord]) -> tuple[dict[str, object], ...]:
    return tuple(
        item.model_dump(mode="json") for item in sorted(effects, key=lambda item: item.effect_id)
    )


def build_jci_orientation_rows(
    deltas: Sequence[JCIOrientationDeltaRecord],
) -> tuple[dict[str, object], ...]:
    return tuple(
        item.model_dump(mode="json") for item in sorted(deltas, key=lambda item: item.delta_id)
    )


def _analysis_failure_row(record: AnalysisFailureRecord) -> dict[str, object]:
    return {
        "source_stage": record.stage.value,
        "record_id": record.failure_id,
        "subject_id": record.subject_id,
        "reason_code": record.reason_code.value,
        "config_sha256": record.config_sha256,
        "input_bundle_sha256": record.input_bundle_sha256,
        "detail_sha256": "",
    }


def build_failure_rows(
    bootstrap_failures: Sequence[BootstrapFailureRecord],
    discovery_failures: Sequence[DiscoveryFailureRecord],
    exclusions: Sequence[PreRandomizationExclusionRecord],
    effect_failures: Sequence[AnalysisFailureRecord],
    jci_failures: Sequence[AnalysisFailureRecord],
    rfci_failures: Sequence[AnalysisFailureRecord],
) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    for record in bootstrap_failures:
        rows.append(
            {
                "source_stage": "fci-discovery-bootstrap",
                "record_id": record.failure_id,
                "subject_id": record.draw_id,
                "reason_code": record.reason_code.value,
                "config_sha256": record.fci_config_sha256,
                "input_bundle_sha256": "",
                "detail_sha256": record.detail_sha256,
            }
        )
    for record in discovery_failures:
        rows.append(
            {
                "source_stage": "fci-discovery",
                "record_id": record.failure_id,
                "subject_id": record.table_id,
                "reason_code": record.reason_code.value,
                "config_sha256": record.fci_config_sha256,
                "input_bundle_sha256": record.table_sha256,
                "detail_sha256": record.detail_sha256,
            }
        )
    for record in exclusions:
        rows.append(
            {
                "source_stage": "build-confirmation-variants",
                "record_id": record.exclusion_id,
                "subject_id": record.task_id,
                "reason_code": ";".join(item.value for item in record.failure_codes),
                "config_sha256": "",
                "input_bundle_sha256": "",
                "detail_sha256": record.detail_sha256,
            }
        )
    rows.extend(
        _analysis_failure_row(record)
        for group in (effect_failures, jci_failures, rfci_failures)
        for record in group
    )
    return tuple(sorted(rows, key=lambda row: (str(row["source_stage"]), str(row["record_id"]))))


def render_summary(
    *,
    hypotheses: Sequence[FrozenHypothesisRecord],
    variants: Sequence[PromptVariantRecord],
    assignments: Sequence[AssignmentRecord],
    effects: Sequence[ITTEffectRecord],
    jci_deltas: Sequence[JCIOrientationDeltaRecord],
    failure_count: int,
    capability: RFCICapabilityRecord,
    pag_counts: Mapping[str, int],
) -> bytes:
    status_counts: dict[str, int] = {}
    for effect in effects:
        status_counts[effect.status] = status_counts.get(effect.status, 0) + 1
    capability_json = json.dumps(
        capability.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    lines = [
        "# SecAware Prompt-Only Run Summary",
        "",
        "Endpoint marks are preserved without causal reinterpretation.",
        "",
        "## Discovery",
        "",
        f"- Frozen hypotheses: {len(hypotheses)}",
        f"- Observational reference PAGs: {pag_counts.get('observational_reference', 0)}",
        f"- JCI raw PAGs: {pag_counts.get('jci_raw', 0)}",
        f"- JCI constrained PAGs: {pag_counts.get('jci_constrained', 0)}",
        f"- RFCI sensitivity PAGs: {pag_counts.get('rfci_sensitivity', 0)}",
        "",
        "## Randomized confirmation",
        "",
        f"- Frozen Prompt variants: {len(variants)}",
        f"- Committed assignments: {len(assignments)}",
        f"- Published ITT effects: {len(effects)}",
        f"- JCI orientation deltas: {len(jci_deltas)}",
        "",
        "## Effect statuses",
        "",
    ]
    if status_counts:
        lines.extend(f"- {status}: {status_counts[status]}" for status in sorted(status_counts))
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Optional RFCI capability",
            "",
            f"- RFCI status: {capability.status}",
            f"- RFCI reason: {canonical_markdown_code(capability.reason_code or 'none')}",
            f"{RFCI_CAPABILITY_PREFIX}{canonical_markdown_code(capability_json)}",
            "",
            "## Typed failures",
            "",
            f"- Total: {failure_count}",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def write_reports(*args: object, **kwargs: object) -> object:
    """Compatibility import surface; the transactional implementation lives in the stage."""

    from secaware.pipeline.stages.reporting import write_reports as stage_write_reports

    return stage_write_reports(*args, **kwargs)


__all__ = [
    "EFFECT_FIELDS",
    "FAILURE_FIELDS",
    "JCI_ORIENTATION_FIELDS",
    "RFCI_CAPABILITY_PREFIX",
    "ReportDocuments",
    "build_assignment_rows",
    "build_effect_rows",
    "build_failure_rows",
    "build_intervention_rows",
    "build_jci_orientation_rows",
    "canonical_csv_bytes",
    "canonical_jsonl_bytes",
    "canonical_markdown_code",
    "decode_canonical_markdown_code",
    "render_summary",
    "write_reports",
]
