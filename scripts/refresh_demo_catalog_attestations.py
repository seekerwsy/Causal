"""Preserve and refresh the checked-in demo attestations after a catalog revision."""

from __future__ import annotations

import json
from pathlib import Path

from secaware.intervention.attestation import PromptRoleAttestationRecord
from secaware.schema.features import FeatureOperation
from secaware.schema.experiments import PromptRole
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "data" / "examples" / "prompt_attestations_demo.jsonl"
    history = root / "data" / "examples" / "history"
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]
    if not rows or len({row["catalog_sha256"] for row in rows}) != 1:
        raise ValueError("demo attestation source failed validation")
    old_catalog = rows[0]["catalog_sha256"]
    archive = history / f"prompt_attestations_demo-{old_catalog}.jsonl"
    if archive.exists():
        raise FileExistsError(archive)
    history.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(source.read_bytes())

    refreshed = []
    for row in rows:
        refreshed.append(
            PromptRoleAttestationRecord.from_content(
                prompt_id=row["prompt_id"],
                task_id=row["task_id"],
                prompt_sha256=row["prompt_sha256"],
                prompt_role=PromptRole(row["prompt_role"]),
                counterpart_prompt_id=row["counterpart_prompt_id"],
                counterpart_prompt_sha256=row["counterpart_prompt_sha256"],
                variant_clause_start=row["variant_clause_start"],
                variant_clause_end=row["variant_clause_end"],
                variant_clause_sha256=row["variant_clause_sha256"],
                contrast_owner_operation=FeatureOperation(row["contrast_owner_operation"]),
                catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            )
        )
    payload = b"".join(
        json.dumps(
            item.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
        for item in refreshed
    )
    temporary = source.with_suffix(".jsonl.tmp")
    temporary.write_bytes(payload)
    temporary.replace(source)


if __name__ == "__main__":
    main()
