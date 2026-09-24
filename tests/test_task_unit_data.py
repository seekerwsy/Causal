"""Fixed synthetic source bundles protect provenance independently of producers."""
import hashlib
import json
from pathlib import Path

import pytest

from prompt_mechanism_study.cli import main
from prompt_mechanism_study.data.contract_cleaning import ContractCleaningError, verify_contract_content_data
from prompt_mechanism_study.data.task_unit_data import TaskUnitDataError, verify_task_unit_data
from prompt_mechanism_study.records import canonical_json, content_hash


@pytest.mark.parametrize("version", ["4", "5"])
def test_fixed_input_identity_evidence_and_task_partition(version, tmp_path, capsys):
    fixture = json.loads((Path(__file__).parent / "fixtures/task-unit-bundles.json").read_text(encoding="utf-8"))[version]
    for name, payload in fixture.items():
        (tmp_path / name).write_bytes(payload.encode("utf-8"))
    verify = verify_task_unit_data if version == "4" else verify_contract_content_data
    error = TaskUnitDataError if version == "4" else ContractCleaningError
    result = verify(tmp_path)
    assert result["task_units"] == result["functional_contracts"] == 3
    assert not result["formal_execution_authorized"]
    assert main(["data", "verify-inputs", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == result

    def rewrite(name, rows):
        payload = "".join(canonical_json(row) + "\n" for row in rows).encode("utf-8")
        (tmp_path / name).write_bytes(payload)
        manifest = json.loads(fixture["manifest.json"])
        manifest["files"][name].update(record_count=len(rows), sha256=hashlib.sha256(payload).hexdigest())
        (tmp_path / "manifest.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8", newline="\n")

    # Even with a recomputed file hash, every independent task must be in exactly
    # one duplicate group. More rows may not manufacture more task support.
    groups = [json.loads(line) for line in fixture["near-duplicate-groups.jsonl"].splitlines()]
    groups[0]["task_unit_ids"].append(groups[0]["task_unit_ids"][0])
    rewrite("near-duplicate-groups.jsonl", groups)
    with pytest.raises(error):
        verify(tmp_path)
    (tmp_path / "near-duplicate-groups.jsonl").write_bytes(fixture["near-duplicate-groups.jsonl"].encode())

    # Rehashing a contract cannot make its unsupported quote into source evidence.
    contracts = [json.loads(line) for line in fixture["functional-contracts.jsonl"].splitlines()]
    if version == "4":
        contracts[0]["requirement_evidence"] = [dict(
            evidence_start=0, evidence_end=5, evidence_text="unsupported source quote",
            evidence_sha256=content_hash("unsupported source quote"))]
    else:
        contracts[0]["content_evidence"]["requirements"][0][0]["quoted_text"] = "unsupported source quote"
    contracts[0]["functional_contract_record_sha256"] = content_hash({
        k: v for k, v in contracts[0].items() if k != "functional_contract_record_sha256"})
    rewrite("functional-contracts.jsonl", contracts)
    with pytest.raises(error):
        verify(tmp_path)
