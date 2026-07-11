from importlib import metadata
from pathlib import Path
import shutil

import pytest

from secaware.config import OracleConfig
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.oracle.aggregator import run_oracle_batch
from secaware.pipeline.preflight import run_oracle_preflight
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationParameters,
    GenerationProvenance,
    GenerationRequestRecord,
    build_generation_request_id,
    sha256_text,
)
from secaware.schema.oracle import SecurityLabel
from secaware.schema.records import CanonicalGeneratedCodeRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = Path(__file__).with_name("oracle_corpus")
POLICY_LOCK = PROJECT_ROOT / "policies" / "oracle" / "python" / "policy.lock.json"
EXACT_TOOLS = {"semgrep": "1.168.0", "bandit": "1.9.4"}


def _exact_tools_unavailable_reason() -> str | None:
    unavailable: list[str] = []
    for tool, expected_distribution in EXACT_TOOLS.items():
        try:
            distribution_version = metadata.version(tool)
        except metadata.PackageNotFoundError:
            distribution_version = None
        executable = shutil.which(tool)
        if distribution_version != expected_distribution or executable is None:
            unavailable.append(
                f"{tool} distribution={distribution_version!r} executable={executable!r}"
            )
    if unavailable:
        return "exact Oracle tools unavailable: " + "; ".join(unavailable)
    return None


EXACT_TOOLS_UNAVAILABLE = _exact_tools_unavailable_reason()
pytestmark = [
    pytest.mark.oracle_tools,
    pytest.mark.skipif(
        EXACT_TOOLS_UNAVAILABLE is not None,
        reason=EXACT_TOOLS_UNAVAILABLE or "exact Oracle tools unavailable",
    ),
]


def _request(prompt_id: str, seed_id: int) -> GenerationRequestRecord:
    prompt = f"Return the checked-in {prompt_id} Python corpus sample."
    parameters = GenerationParameters(values={"temperature": 0.0})
    prompt_sha256 = sha256_text(prompt)
    endpoint_sha256 = sha256_text("checked-in-oracle-corpus")
    template_sha256 = sha256_text("Return only Python code.")
    request_id = build_generation_request_id(
        schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
        condition="observed",
        prompt_id=prompt_id,
        prompt_sha256=prompt_sha256,
        language="python",
        model_id="checked-in-corpus",
        seed_id=seed_id,
        hypothesis_id=None,
        intervention_id=None,
        endpoint_type="offline",
        endpoint_sha256=endpoint_sha256,
        system_template_version="oracle-corpus-v1",
        system_template_sha256=template_sha256,
        parameters=parameters,
    )
    return GenerationRequestRecord(
        schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
        request_id=request_id,
        condition="observed",
        prompt_id=prompt_id,
        prompt=prompt,
        prompt_sha256=prompt_sha256,
        language="python",
        model_id="checked-in-corpus",
        seed_id=seed_id,
        hypothesis_id=None,
        intervention_id=None,
        endpoint_type="offline",
        endpoint_sha256=endpoint_sha256,
        system_template_version="oracle-corpus-v1",
        system_template_sha256=template_sha256,
        parameters=parameters,
    )


def _corpus_records() -> list[CanonicalGeneratedCodeRecord]:
    provenance = GenerationProvenance(
        producer="checked-in-oracle-corpus",
        producer_version="1",
        source_batch_id="oracle-real-tools-v1",
    )
    records: list[CanonicalGeneratedCodeRecord] = []
    for seed_id, sample in enumerate(("secure", "insecure"), start=1):
        request = _request(f"oracle-corpus-{sample}", seed_id)
        records.append(
            canonical_generated_code_from_request(
                request,
                CORPUS_ROOT.joinpath(f"{sample}.py").read_text(encoding="utf-8"),
                provenance,
            )
        )
    return records


def test_locked_real_tools_classify_checked_in_corpus() -> None:
    policy = run_oracle_preflight(OracleConfig(policy_lock_path=str(POLICY_LOCK)))
    secure, insecure = run_oracle_batch(_corpus_records(), policy)

    assert [secure.security_label, insecure.security_label] == [
        SecurityLabel.SECURE,
        SecurityLabel.INSECURE,
    ]
    expected_provenance = {
        (tool, version, policy.combined_sha256) for tool, version in EXACT_TOOLS.items()
    }
    for record in (secure, insecure):
        assert {
            (item.analyzer, item.version, item.policy_sha256) for item in record.analyzers
        } == expected_provenance
    assert {finding.analyzer for finding in insecure.findings} == {"semgrep", "bandit"}
