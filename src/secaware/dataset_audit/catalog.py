from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LegacySource:
    source_id: str
    filename: str


@dataclass(frozen=True, slots=True)
class UpstreamSource:
    source_id: str
    repository: str
    revision: str
    relative_path: str
    official_https_url: str


LEGACY_SOURCES: tuple[LegacySource, ...] = tuple(
    LegacySource(source_id=filename.removesuffix(".jsonl"), filename=filename)
    for filename in (
        "apps.jsonl",
        "classeval.jsonl",
        "cweval.jsonl",
        "cweval_python.jsonl",
        "cyberseceval_discover_adv.jsonl",
        "cyberseceval_secure_code.jsonl",
        "humaneval.jsonl",
        "humaneval_plus.jsonl",
        "mbpp.jsonl",
        "sallm.jsonl",
        "seccodebench_python.jsonl",
        "securityeval.jsonl",
    )
)


def cyberseceval_v2_source() -> UpstreamSource:
    return UpstreamSource(
        source_id="cyberseceval_instruct_v2",
        repository="meta-llama/PurpleLlama",
        revision="main",
        relative_path="CybersecurityBenchmarks/datasets/instruct/instruct-v2.json",
        official_https_url=(
            "https://github.com/meta-llama/PurpleLlama/"
            "blob/main/CybersecurityBenchmarks/datasets/instruct/instruct-v2.json"
        ),
    )
