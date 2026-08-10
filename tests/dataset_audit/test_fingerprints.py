from __future__ import annotations

import hashlib

from secaware.dataset_audit.fingerprints import (
    NORMALIZATION_VERSION,
    exact_prompt_sha256,
    file_sha256,
    normalize_prompt,
    normalized_prompt_sha256,
)


def test_file_sha256_hashes_exact_bytes(tmp_path) -> None:
    path = tmp_path / "source.jsonl"
    payload = b'{"prompt":"caf\xc3\xa9"}\r\n'
    path.write_bytes(payload)

    assert file_sha256(path) == hashlib.sha256(payload).hexdigest()


def test_exact_prompt_sha256_preserves_layout() -> None:
    assert exact_prompt_sha256("Build  API") != exact_prompt_sha256("Build API")


def test_normalized_prompt_digest_collapses_only_layout() -> None:
    assert NORMALIZATION_VERSION == "prompt-normalization-v1"
    assert normalized_prompt_sha256("Build  an API\r\nnow  ") == normalized_prompt_sha256(
        "Build an API\nnow"
    )
    assert normalized_prompt_sha256("Build safe API") != normalized_prompt_sha256(
        "Build unsafe API"
    )


def test_normalization_preserves_case_punctuation_and_token_order() -> None:
    assert normalize_prompt("API, build!") == "API, build!"
    assert normalize_prompt("api, build!") != normalize_prompt("API, build!")
    assert normalize_prompt("build API") != normalize_prompt("API build")
