from __future__ import annotations

from dataclasses import fields
import inspect
import json

import pytest

from secaware.analysis.contrasts import materialize_contrasts
from secaware.analysis.itt import estimate_itt
from secaware.config import AnalysisConfig

from test_jci_fci_analysis import _CapturingRunner, _config, _jci_table_and_rows
from test_jci_table_builder import fixture_for


def _analysis_config() -> AnalysisConfig:
    return AnalysisConfig(
        bootstrap_samples=4,
        percentile_method="linear-v1",
        max_failed_bootstrap_fraction=0.10,
        ci_level=0.95,
        multiplicity_method="bonferroni",
        min_independent_tasks=2,
        min_eligible_pairs=2,
        min_flip_rate=0.05,
        max_side_effect_rate_confirmed=0.10,
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def test_jci_analysis_cannot_modify_frozen_primary_artifacts_or_report_fields() -> None:
    from secaware.causal.jci import analyze_jci_stratum

    fixture = fixture_for(task_count=2)
    contrasts = materialize_contrasts(fixture.protocols)
    effects = estimate_itt(
        fixture.outcomes,
        _analysis_config(),
        protocols=fixture.protocols,
        contrasts=contrasts,
    )
    primary_report_fields = tuple(
        (
            effect.effect_id,
            effect.risk_difference,
            effect.ci_low,
            effect.ci_high,
            effect.status,
        )
        for effect in effects
    )
    protected_before = {
        "hypotheses": tuple(item.model_dump(mode="json") for item in fixture.hypotheses),
        "assignments": tuple(item.model_dump(mode="json") for item in fixture.assignments),
        "contrasts": tuple(item.model_dump(mode="json") for item in contrasts),
        "effects": tuple(item.model_dump(mode="json") for item in effects),
        "report_primary": primary_report_fields,
    }
    protected_bytes_before = _canonical_bytes(protected_before)
    table, rows = _jci_table_and_rows()

    result = analyze_jci_stratum(table, rows, _config(), runner=_CapturingRunner())

    protected_after = {
        "hypotheses": tuple(item.model_dump(mode="json") for item in fixture.hypotheses),
        "assignments": tuple(item.model_dump(mode="json") for item in fixture.assignments),
        "contrasts": tuple(item.model_dump(mode="json") for item in contrasts),
        "effects": tuple(item.model_dump(mode="json") for item in effects),
        "report_primary": tuple(
            (
                effect.effect_id,
                effect.risk_difference,
                effect.ci_low,
                effect.ci_high,
                effect.status,
            )
            for effect in effects
        ),
    }
    assert protected_before == protected_after
    assert protected_bytes_before == _canonical_bytes(protected_after)
    assert result.delta.per_assumption_attribution is False


def test_jci_result_and_analysis_api_have_no_primary_effect_mutation_surface() -> None:
    from secaware.causal.jci import JCIAnalysisResult, analyze_jci_stratum

    assert tuple(inspect.signature(analyze_jci_stratum).parameters) == (
        "table",
        "rows",
        "config",
        "runner",
    )
    assert tuple(field.name for field in fields(JCIAnalysisResult)) == (
        "raw_pag",
        "constrained_pag",
        "delta",
    )
    forbidden = {
        "hypotheses",
        "assignments",
        "contrasts",
        "effects",
        "risk_difference",
        "ci_low",
        "ci_high",
        "status",
        "report_primary_fields",
    }
    assert not forbidden & set(JCIAnalysisResult.__annotations__)

    table, rows = _jci_table_and_rows()
    result = analyze_jci_stratum(table, rows, _config(), runner=_CapturingRunner())
    with pytest.raises((AttributeError, TypeError)):
        result.risk_difference = 1.0  # type: ignore[attr-defined]
