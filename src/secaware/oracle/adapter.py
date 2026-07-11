from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from secaware.schema.oracle import AnalyzerFindingRecord, AnalyzerProvenanceRecord


AnalyzerName = Literal["semgrep", "bandit"]


@dataclass(frozen=True, slots=True, repr=False)
class LocatedAnalyzerFinding:
    opaque_file: str
    record: AnalyzerFindingRecord
    start_offset: int | None = None
    end_offset: int | None = None

    @property
    def analyzer(self) -> Literal["semgrep", "bandit"]:
        return self.record.analyzer

    @property
    def rule_id(self) -> str:
        return self.record.rule_id

    @property
    def cwe(self) -> str:
        return self.record.cwe

    @property
    def severity(self) -> Literal["low", "medium", "high"]:
        return self.record.severity

    @property
    def confidence(self) -> Literal["low", "medium", "high", "not_provided"]:
        return self.record.confidence

    @property
    def line(self) -> int:
        return self.record.line

    @property
    def column(self) -> int:
        return self.record.column

    @property
    def end_line(self) -> int:
        return self.record.end_line

    @property
    def end_column(self) -> int:
        return self.record.end_column

    @property
    def message(self) -> str:
        return self.record.message

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.analyzer,
            self.opaque_file,
            self.line,
            self.column,
            self.end_line,
            self.end_column,
            self.rule_id,
            self.cwe,
            self.severity,
            self.confidence,
            self.message,
            self.start_offset,
            self.end_offset,
        )

    def identity_key(self) -> tuple[object, ...]:
        return (
            self.analyzer,
            self.opaque_file,
            self.line,
            self.column,
            self.end_line,
            self.end_column,
            self.rule_id,
        )

    def __repr__(self) -> str:
        return "LocatedAnalyzerFinding()"


@dataclass(frozen=True, slots=True, repr=False)
class AnalyzerReport:
    analyzer: AnalyzerName
    provenance: AnalyzerProvenanceRecord
    covered_files: tuple[str, ...]
    findings: tuple[LocatedAnalyzerFinding, ...]

    @property
    def canonical_findings(self) -> tuple[AnalyzerFindingRecord, ...]:
        return tuple(item.record for item in self.findings)

    def __repr__(self) -> str:
        return "AnalyzerReport()"


__all__ = ["AnalyzerReport", "LocatedAnalyzerFinding"]
