"""Stable extraction backend protocol and run-locked policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from secaware.schema.features import PromptExtractorBackend
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord


@dataclass(frozen=True, slots=True)
class ExtractionPolicy:
    backend: PromptExtractorBackend
    policy_sha256: str
    catalog_sha256: str
    max_response_chars: int


class PromptExtractor(Protocol):
    def extract(
        self,
        prompt: PromptRecord,
        policy: ExtractionPolicy,
    ) -> PromptExtractionProposalRecord:
        raise NotImplementedError


__all__ = ["ExtractionPolicy", "PromptExtractor"]
