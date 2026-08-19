from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.dataset_audit.fingerprints import exact_prompt_sha256
from secaware.exploratory.codesec_eval_plus_audit import audit_codesec_eval_plus_source


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_codesec_eval_audit_keeps_reference_fields_restricted(tmp_path: Path) -> None:
    selection = tmp_path / "selection.json"
    _write_json(
        selection,
        {
            "tasks": [
                {"source_prompt_sha256": hashlib.sha256(f"used-{index}".encode()).hexdigest()}
                for index in range(93)
            ]
        },
    )
    prior = tmp_path / "prior.jsonl"
    _write_jsonl(
        prior,
        [
            {
                "source_prompt_sha256": hashlib.sha256(f"prior-{index}".encode()).hexdigest(),
                "prompt": f"Prior task {index}",
            }
            for index in range(40)
        ],
    )
    assets = tmp_path / "assets.jsonl"
    _write_jsonl(
        assets,
        [
            {
                "exact_prompt_sha256": hashlib.sha256(b"asset").hexdigest(),
                "normalized_prompt_sha256": hashlib.sha256(b"normalized-asset").hexdigest(),
            }
        ],
    )
    source = tmp_path / "source.jsonl"
    rows = []
    for index in range(140):
        identifier = "CWE-78_01" if index == 0 else f"CWE-20_{index:03d}"
        prompt = "Run a fixed utility with the supplied path." if index == 0 else f"Task {index}"
        rows.append(
            {
                "ID": identifier,
                "Problem": prompt,
                "Insecure Code": "DO_NOT_PUBLISH_INSECURE",
                "Secure Code": "DO_NOT_PUBLISH_SECURE",
                "Test": "DO_NOT_PUBLISH_TEST",
                "Test-FP": "def check(candidate): pass",
                "Test-SP": "DO_NOT_PUBLISH_SECURITY_TEST",
                "Entry_Point": f"entry_{index}",
            }
        )
    _write_jsonl(source, rows)
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "audit_id": "five_cwe_codesec_eval_plus_source_audit_v1",
            "target_cwes": ["CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338"],
            "repository_inputs": {
                "method_development_selection": {
                    "path": selection.relative_to(tmp_path).as_posix(),
                    "sha256": _sha(selection),
                },
                "prior_independent_candidates": {
                    "path": prior.relative_to(tmp_path).as_posix(),
                    "sha256": _sha(prior),
                },
                "repository_record_audit": {
                    "path": assets.relative_to(tmp_path).as_posix(),
                    "sha256": _sha(assets),
                },
            },
            "source": {
                "subset": "SecEvalPlus",
                "expected_rows": 140,
                "revision": "fixture",
                "file_sha256": _sha(source),
                "license_status": "under_review",
                "raw_redistribution_allowed": False,
            },
            "provider_calls_allowed": False,
            "outcomes_allowed": False,
            "raw_reference_fields_allowed": False,
        },
    )

    report = audit_codesec_eval_plus_source(
        repo_root=tmp_path,
        config_path=config,
        source_path=source,
        public_run_dir=tmp_path / "public",
        restricted_run_dir=tmp_path / "restricted",
        command_argv=("audit",),
    )

    assert report["counts"]["five_cwe_tasks"] == 1
    assert report["reference_fields_consumed"] == 0
    public = "".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "public").iterdir()
        if path.is_file()
    )
    assert "DO_NOT_PUBLISH" not in public
    queue = (tmp_path / "restricted" / "five-cwe-review-queue.jsonl").read_text(
        encoding="utf-8"
    )
    assert "Run a fixed utility" in queue
    assert exact_prompt_sha256("Run a fixed utility with the supplied path.") in queue
    assert "DO_NOT_PUBLISH" not in queue
