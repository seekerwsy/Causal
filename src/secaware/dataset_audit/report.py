from __future__ import annotations

import hashlib
import json
from typing import Any


_ROLE_LABELS = {
    "PAPER_PRIMARY_CANDIDATE": "Paper primary candidate",
    "SECURITY_ONLY_SECONDARY_CANDIDATE": "Security-only secondary candidate",
    "FUNCTIONAL_CALIBRATION": "Functional calibration",
    "ORACLE_CALIBRATION": "Oracle calibration",
    "EXTRACTOR_OR_TSG_EVALUATION": "Extractor/TSG evaluation",
    "EXTERNAL_REPLICATION_CANDIDATE": "External replication candidate",
    "PENDING_CONTRACT_OR_ADJUDICATION": "Pending contract or adjudication",
    "UNUSABLE_UNDER_CURRENT_SCOPE": "Unusable under current scope",
}

_OVERLAP_LABELS = {
    "discover_adv_unique": "Legacy discover-adv unique prompts",
    "secure_code_unique": "Legacy secure-code unique prompts",
    "legacy_exact_overlap": "Legacy 150/260 exact overlap",
    "v2_unique": "v2 unique prompts",
    "v2_secure_code_overlap": "v2 overlap with legacy secure-code",
    "v2_discover_adv_overlap": "v2 overlap with legacy discover-adv",
    "v2_legacy_union_overlap": "v2 overlap with legacy union",
}


def _stable_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _sentence(value: object) -> str:
    text = _cell(value).strip()
    if not text:
        return "—"
    return text[0].upper() + text[1:]


def _role_value(role: object) -> str:
    value = getattr(role, "value", role)
    text = str(value)
    return text.removeprefix("DatasetRole.")


def _evidence_rows(counts: dict[str, dict[str, int]]) -> str:
    rows: list[str] = []
    for dimension in ("language", "neutrality", "functional"):
        for state, count in sorted(counts.get(dimension, {}).items()):
            rows.append(f"| {dimension.title()} | {_cell(state)} | {count} |")
    cwe = counts.get("cwe", {})
    if cwe:
        rows.append(
            "| CWE evidence | Resolved CWE assignments | "
            f"{sum(count for name, count in cwe.items() if name != 'UNRESOLVED')} |"
        )
        rows.append(f"| CWE evidence | Unresolved records | {cwe.get('UNRESOLVED', 0)} |")
    return "\n".join(rows) or "| — | — | 0 |"


def _split_rows(split_summaries: tuple[dict[str, Any], ...]) -> str:
    rows: list[str] = []
    for item in sorted(split_summaries, key=lambda value: float(value["discover_ratio"])):
        summary = item.get("summary", {})
        ratio = float(item["discover_ratio"])
        ratio_label = f"{round(ratio * 100)}/{round((1 - ratio) * 100)}"
        floor_met = "yes" if summary.get("pipeline_floor_met") else "no"
        rows.append(
            f"| {ratio_label} | {summary.get('independent_clusters', 0)} | "
            f"{summary.get('discover_clusters', 0)} | "
            f"{summary.get('confirm_clusters', 0)} | "
            f"{summary.get('unresolved_clusters', 0)} | "
            f"{summary.get('pipeline_floor', 0)} | {floor_met} |"
        )
    return "\n".join(rows) or "| — | 0 | 0 | 0 | 0 | 0 | no |"


def _role_rows(dataset_roles: tuple[dict[str, Any], ...]) -> str:
    rows: list[str] = []
    for item in sorted(dataset_roles, key=lambda value: str(value["dataset_id"])):
        roles = ", ".join(
            _ROLE_LABELS.get(_role_value(role), _role_value(role).replace("_", " ").title())
            for role in item.get("roles", [])
        ) or "—"
        blockers = "; ".join(
            _sentence(reason) for reason in item.get("blocking_reasons", [])
        ) or "None recorded"
        rows.append(f"| {_cell(item['dataset_id'])} | {_cell(roles)} | {_cell(blockers)} |")
    return "\n".join(rows) or "| — | — | No role decision was supplied |"


def _overlap_rows(overlap: dict[str, Any]) -> str:
    rows = [
        f"| {label} | {overlap[key]} |"
        for key, label in _OVERLAP_LABELS.items()
        if key in overlap
    ]
    return "\n".join(rows) or "| No overlap metric evaluated | — |"


def build_gap_report(
    *,
    run_id: str,
    status: str,
    progress: dict[str, int | float | None],
    counts: dict[str, dict[str, int]],
    overlap: dict[str, Any],
    split_summaries: tuple[dict[str, Any], ...] = (),
    dataset_roles: tuple[dict[str, Any], ...] = (),
    gaps: tuple[str, ...],
) -> tuple[dict[str, Any], str]:
    stable_progress = {
        key: value
        for key, value in progress.items()
        if key not in {"records_per_second", "eta_seconds"}
    }
    stable = {
        "schema_version": "1.0",
        "status": status,
        "progress": stable_progress,
        "counts": counts,
        "overlap": overlap,
        "split_summaries": list(split_summaries),
        "dataset_roles": list(dataset_roles),
        "gaps": list(gaps),
    }
    report = {
        "run_id": run_id,
        **stable,
        "progress": progress,
        "stable_digest": _stable_digest(stable),
    }
    dataset_rows = "\n".join(
        f"| {name} | {count} |" for name, count in sorted(counts.get("dataset", {}).items())
    ) or "| — | 0 |"
    gap_rows = (
        "\n".join(f"- {gap}" for gap in gaps)
        or "- No additional automated gap was recorded."
    )
    evidence_rows = _evidence_rows(counts)
    split_rows = _split_rows(split_summaries)
    role_rows = _role_rows(dataset_roles)
    overlap_rows = _overlap_rows(overlap)
    relationship = overlap.get("relationship", "not_evaluated")
    relationship_statement = {
        "legacy_and_v2_evaluated": (
            "The legacy 150/260 collections and pinned v2 source were evaluated "
            "together using exact normalized-prompt identity."
        ),
        "not_evaluated": "No combined legacy/v2 overlap analysis was supplied.",
    }.get(str(relationship), f"Recorded relationship: `{_cell(relationship)}`.")
    power_statement = (
        "The cluster floor is a pipeline-operability threshold. Meeting it does not "
        "establish statistical power or freeze the eventual sample size."
    )
    split_header = (
        "| Discover/confirm | Independent clusters | Discover | Confirm | "
        "Unresolved | Pipeline floor | Floor met |"
    )
    markdown = f"""# Dataset availability audit: {run_id}

Status: `{status}`

## Verified inventory facts

| Dataset | Parsed records |
|---|---:|
{dataset_rows}

Completed `{progress.get('completed', 0)}` of `{progress.get('total', 0)}` records;
`{progress.get('failed', 0)}` failed and `{progress.get('unresolved', 0)}` remain unresolved.

## Evidence coverage

| Dimension | State | Count |
|---|---|---:|
{evidence_rows}

## Deterministic pre-screen

Neutrality and CWE values in this report are deterministic evidence screens. A
`CANDIDATE_NEUTRAL` result is not a final human attestation.

## Split feasibility

{power_statement}

{split_header}
|---|---:|---:|---:|---:|---:|---|
{split_rows}

## Evidence-based dataset roles

These are audit recommendations, not final paper assignments.

| Dataset | Suggested roles | Explicit blockers |
|---|---|---|
{role_rows}

## CyberSecEval relationship

{relationship_statement}

| Exact normalized-prompt metric | Count |
|---|---:|
{overlap_rows}

## Unresolved evidence and gaps

{gap_rows}

These outputs do not freeze the CWE scope, sample size, model choice, RQ claims,
or ITT conclusions. Primary-paper eligibility remains pending human adjudication
and power analysis.
"""
    return report, markdown


__all__ = ["build_gap_report"]
