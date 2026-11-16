import json
from pathlib import Path
import shutil
import subprocess

from jsonschema import Draft202012Validator, ValidationError
import pytest

from prompt_mechanism_study.artifact_io import file_sha256, read_json
from prompt_mechanism_study.experiment.code_generation import (
    PATCH_OUTPUT_CONTRACT,
    apply_candidate_patch,
    parse_candidate_patch,
)


PROJECT = Path(__file__).resolve().parents[2]
DEVELOPMENT = PROJECT / "data/method/graph-remediation-development-20261105"
OLD_GENERATION = (
    DEVELOPMENT
    / "runtime/old-result/graph-representation-fixed-240-final/results/generation"
)
PREPARED = DEVELOPMENT / "runtime/prepared-representations"
REQUESTS_SOURCE = (
    DEVELOPMENT
    / "runtime/sources/requests/requests-302225334678490ec66b3614a9dddb8a02c5f4fe"
)
REQUESTS_REFERENCE = (
    DEVELOPMENT
    / "runtime/sources/requests-archive/data/method/requests-proxy-contract-20261103/reference_sessions.py"
)
REQUESTS_TARGET = "requests/sessions.py"
REQUESTS_SHA256 = "294a8971144ba2f35e7d4b3b49c39749454271f49ac93156b5b889ee03929532"


def _real_requests_patch(work):
    target = work / REQUESTS_TARGET
    target.parent.mkdir(parents=True)
    shutil.copy2(REQUESTS_SOURCE / REQUESTS_TARGET, target)
    initialized = subprocess.run(
        ["git", "init", "--quiet"], cwd=work, capture_output=True, text=True, check=False)
    assert initialized.returncode == 0
    added = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "add", REQUESTS_TARGET],
        cwd=work, capture_output=True, text=True, check=False)
    assert added.returncode == 0
    shutil.copy2(REQUESTS_REFERENCE, target)
    completed = subprocess.run(
        [
            "git", "-c", "core.autocrlf=false", "diff", "--no-ext-diff", "--binary",
            "--", REQUESTS_TARGET,
        ],
        cwd=work,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout.startswith("diff --git a/requests/sessions.py b/requests/sessions.py")
    return completed.stdout


def _response(patch, target=REQUESTS_TARGET, source_sha256=REQUESTS_SHA256):
    return json.dumps(
        {
            "contract": PATCH_OUTPUT_CONTRACT,
            "target_path": target,
            "source_sha256": source_sha256,
            "unified_diff": patch,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def test_semantic_fact_inventories_match_schema_and_prepared_representations():
    schema = read_json(DEVELOPMENT / "semantic-facts.schema.json")
    manifest = read_json(PREPARED / "manifest.json")
    rows = {row["representation_id"]: row for row in manifest["rows"]}
    fact_paths = sorted((DEVELOPMENT / "facts").glob("*.json"))
    assert len(fact_paths) == 6
    for path in fact_paths:
        record = read_json(path)
        Draft202012Validator(schema).validate(record)
        prepared = PREPARED / rows[record["representation_id"]]["path"]
        assert file_sha256(prepared) == record["representation_sha256"]
        representation = prepared.read_text(encoding="utf-8")
        fact_ids = [fact["fact_id"] for fact in record["facts"]]
        assert len(fact_ids) == len(set(fact_ids))
        assert {fact["reference_dimension"] for fact in record["facts"]} == {
            "target_input_object_state",
            "security_operations_and_consumers",
            "applicable_entrypoints_and_branches",
            "complete_policy_and_allowed_cases",
            "preserved_behaviors_and_interfaces",
            "unknowns_and_source_vs_normative",
        }
        assert all(fact["representation_evidence"] in representation for fact in record["facts"])


def test_real_token_budget_fits_and_actual_semantic_entry_is_blocked():
    budget_path = DEVELOPMENT / "actual-token-budget.json"
    budget = read_json(budget_path)
    status = read_json(DEVELOPMENT / "development-execution-status.json")
    reviews = list((DEVELOPMENT / "reviews").glob("*.json"))
    assert file_sha256(budget_path) == status["token_budget"]["sha256"]
    assert budget["request_count"] == 6
    assert len(budget["rows"]) == 6
    assert all(row["fits"] for row in budget["rows"])
    assert all(
        row["input_tokens"] + row["max_output_tokens"]
        <= row["service_context_tokens"]
        for row in budget["rows"]
    )
    assert reviews == []
    assert status["semantic_entry"]["independent_semantic_review_count"] == 0
    assert status["semantic_entry"]["status"] == "BLOCKED_MISSING_INDEPENDENT_SEMANTIC_REVIEWS"
    assert status["subject_requests"] == {
        "assigned": 6,
        "sent": 0,
        "completed": 0,
        "request_failures": 0,
        "not_started_semantic_gate_blocked": 6,
        "retry_count": 0,
    }


@pytest.mark.parametrize("slug", ["requests", "brotli"])
@pytest.mark.parametrize("method", ["raw", "flat", "graph"])
def test_old_failed_responses_remain_invalid_under_new_contract(slug, method):
    response = (
        OLD_GENERATION / f"{slug}-{method}-2026113101/candidate-response.txt"
    ).read_text(encoding="utf-8")
    target = REQUESTS_TARGET if slug == "requests" else "python/_brotli.c"
    digest = (
        REQUESTS_SHA256
        if slug == "requests"
        else "156dfcb86a2db2ccb5b88e4d26899532cc85b7bcf76375aac69ea7fe43f3e944"
    )
    with pytest.raises((json.JSONDecodeError, ValueError)):
        parse_candidate_patch(response, target, digest)


def test_real_source_patch_has_exact_target_and_passes_python_syntax(tmp_path):
    source = tmp_path / "source"
    shutil.copytree(REQUESTS_SOURCE, source)
    patch = _real_requests_patch(tmp_path / "diff")
    result = apply_candidate_patch(
        _response(patch), source, REQUESTS_TARGET, REQUESTS_SHA256,
        tmp_path / "application", {"kind": "python_ast"})
    assert result["status"] == "CANDIDATE_APPLIED_AND_SYNTAX_CHECKED"
    assert result["modified_paths"] == [REQUESTS_TARGET]
    assert result["candidate_sha256"] == file_sha256(REQUESTS_REFERENCE)


def test_contract_rejects_wrong_source_path_ambiguity_truncation_and_no_patch(tmp_path):
    patch = _real_requests_patch(tmp_path / "diff")
    valid = _response(patch)
    with pytest.raises(ValidationError):
        parse_candidate_patch(
            valid.replace(
                '"source_sha256":"' + REQUESTS_SHA256 + '"',
                '"source_sha256":"' + "0" * 64 + '"'),
            REQUESTS_TARGET,
            REQUESTS_SHA256,
        )
    with pytest.raises(ValidationError):
        parse_candidate_patch(_response(patch, "requests/adapters.py"), REQUESTS_TARGET, REQUESTS_SHA256)
    duplicate = valid.replace(
        '"target_path":"requests/sessions.py"',
        '"target_path":"requests/sessions.py","target_path":"requests/sessions.py"',
    )
    with pytest.raises(ValueError):
        parse_candidate_patch(duplicate, REQUESTS_TARGET, REQUESTS_SHA256)
    with pytest.raises(json.JSONDecodeError):
        parse_candidate_patch(valid[:-1], REQUESTS_TARGET, REQUESTS_SHA256)
    source = tmp_path / "source"
    shutil.copytree(REQUESTS_SOURCE, source)
    with pytest.raises(RuntimeError):
        apply_candidate_patch(
            _response("not a patch"), source, REQUESTS_TARGET, REQUESTS_SHA256,
            tmp_path / "application", {"kind": "python_ast"})
