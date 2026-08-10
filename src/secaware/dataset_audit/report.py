from __future__ import annotations

import hashlib
import json
from typing import Any


def _stable_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_gap_report(
    *,
    run_id: str,
    status: str,
    progress: dict[str, int | float | None],
    counts: dict[str, dict[str, int]],
    overlap: dict[str, Any],
    gaps: tuple[str, ...],
) -> tuple[dict[str, Any], str]:
    stable = {
        "schema_version": "1.0",
        "status": status,
        "progress": progress,
        "counts": counts,
        "overlap": overlap,
        "gaps": list(gaps),
    }
    report = {"run_id": run_id, **stable, "stable_digest": _stable_digest(stable)}
    dataset_rows = "\n".join(
        f"| {name} | {count} |" for name, count in sorted(counts.get("dataset", {}).items())
    ) or "| — | 0 |"
    gap_rows = (
        "\n".join(f"- {gap}" for gap in gaps)
        or "- No additional automated gap was recorded."
    )
    power_statement = (
        "The cluster floor is a pipeline-operability threshold. Meeting it does not "
        "establish statistical power or freeze the eventual sample size."
    )
    markdown = f"""# Dataset availability audit: {run_id}

Status: `{status}`

## Verified inventory facts

| Dataset | Parsed records |
|---|---:|
{dataset_rows}

Completed `{progress.get('completed', 0)}` of `{progress.get('total', 0)}` records;
`{progress.get('failed', 0)}` failed and `{progress.get('unresolved', 0)}` remain unresolved.

## Deterministic pre-screen

Neutrality and CWE values in this report are deterministic evidence screens. A
`CANDIDATE_NEUTRAL` result is not a final human attestation.

## Split feasibility

{power_statement}

## CyberSecEval relationship

`{overlap.get('relationship', 'not_evaluated')}`

## Unresolved evidence and gaps

{gap_rows}
"""
    return report, markdown


__all__ = ["build_gap_report"]
