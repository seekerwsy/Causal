from __future__ import annotations

from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

import pytest

from secaware.errors import SecAwareError
from secaware.causal.background import build_background_knowledge
from secaware.config import RFCIConfig
from secaware.io.jsonl import read_jsonl
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import PAGRecord, PAGRunKind
from secaware.schema.outcomes import (
    AnalysisFailureRecord,
    RFCICapabilityRecord,
)
from test_rfci_adapter import _capability, _rows, _table
from test_stage_orchestration import _store


pytest_plugins = ("test_jci_stage",)


EXPECTED_RFCI_OUTPUTS = (
    "analysis/rfci_capability.jsonl",
    "analysis/rfci_pags.jsonl",
    "analysis/rfci_failures.jsonl",
)


def _disabled_capability() -> RFCICapabilityRecord:
    return RFCICapabilityRecord(
        schema_version="1.0",
        available=False,
        status="disabled",
        requires_java=True,
        python_version="0.0",
        java_major=None,
        jpype_version=None,
        py_tetrad_commit=None,
        tetrad_jar_sha256=None,
        reason_code="disabled",
    )


def _unavailable_capability() -> RFCICapabilityRecord:
    return RFCICapabilityRecord(
        schema_version="1.0",
        available=False,
        status="unavailable",
        requires_java=True,
        python_version="3.12.9",
        java_major=None,
        jpype_version=None,
        py_tetrad_commit=None,
        tetrad_jar_sha256=None,
        reason_code="jpype_missing",
    )


def test_rfci_stage_declares_exact_ordered_outputs() -> None:
    module = import_module("secaware.pipeline.stages.rfci")

    assert tuple(path.as_posix() for path, _model in module.RFCI_STAGE_OUTPUTS) == (
        EXPECTED_RFCI_OUTPUTS
    )
    assert tuple(model for _path, model in module.RFCI_STAGE_OUTPUTS) == (
        RFCICapabilityRecord,
        PAGRecord,
        AnalysisFailureRecord,
    )


def test_run_store_enforces_exact_rfci_output_contract(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store._validate_stage_output_contract("rfci-confirmation", EXPECTED_RFCI_OUTPUTS)

    with pytest.raises(SecAwareError, match="output contract"):
        store._validate_stage_output_contract(
            "rfci-confirmation", tuple(reversed(EXPECTED_RFCI_OUTPUTS))
        )


def test_rfci_stage_publishes_disabled_capability_without_pag_or_failure(
    committed_jci_base,
) -> None:
    config, store, _jci_result, _runner, _effect_bytes = committed_jci_base
    module = import_module("secaware.pipeline.stages.rfci")
    probes = 0

    def probe(_config):
        nonlocal probes
        probes += 1
        return _disabled_capability()

    def forbidden_runner(*_args, **_kwargs):
        raise AssertionError("disabled RFCI invoked its runner")

    result = module.rfci_stage(
        config,
        store,
        capability_probe=probe,
        runner=forbidden_runner,
        force=True,
    )
    capability = read_jsonl(
        store.root / EXPECTED_RFCI_OUTPUTS[0],
        RFCICapabilityRecord,
        required=True,
        allow_empty=False,
    )
    pags = read_jsonl(
        store.root / EXPECTED_RFCI_OUTPUTS[1],
        PAGRecord,
        required=True,
        allow_empty=True,
    )
    failures = read_jsonl(
        store.root / EXPECTED_RFCI_OUTPUTS[2],
        AnalysisFailureRecord,
        required=True,
        allow_empty=True,
    )

    assert capability == [_disabled_capability()]
    assert not pags and not failures
    assert probes == 1
    assert result.capability_count == 1
    assert result.pag_count == result.failure_count == 0


def test_rfci_backend_uses_supplied_frozen_capability_without_reprobe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery import rfci_backend

    table = _table()
    rows = _rows(table)
    knowledge = build_background_knowledge(table)
    config = RFCIConfig(enabled=True)
    capability = _capability()
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind.RFCI_SENSITIVITY,
        table_id=table.table_id,
        backend="py_tetrad_rfci_v1",
        backend_version=config.py_tetrad_commit,
        ci_test="gsq",
        config_sha256=canonical_sha256(config.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=(),
    )
    monkeypatch.setattr(
        rfci_backend,
        "detect_rfci_capability",
        lambda _config: pytest.fail("supplied capability was re-probed"),
    )
    monkeypatch.setattr(
        rfci_backend,
        "_collect_runtime_evidence",
        lambda _config: SimpleNamespace(capability=capability),
    )
    monkeypatch.setattr(rfci_backend, "_run_subprocess_rfci", lambda *_args: pag)

    result = rfci_backend._run_rfci_sensitivity_with_capability(
        table,
        rows,
        knowledge,
        config,
        capability=capability,
    )

    assert result.capability == capability
    assert result.pag == pag


@pytest.mark.parametrize(
    ("config", "capability"),
    (
        (RFCIConfig(enabled=True), _disabled_capability()),
        (RFCIConfig(enabled=False), _capability()),
        (RFCIConfig(enabled=False), _unavailable_capability()),
    ),
)
def test_rfci_backend_rejects_supplied_capability_config_mismatch(
    config: RFCIConfig,
    capability: RFCICapabilityRecord,
) -> None:
    from secaware.discovery import rfci_backend

    table = _table()
    with pytest.raises(SecAwareError):
        rfci_backend._run_rfci_sensitivity_with_capability(
            table,
            _rows(table),
            build_background_knowledge(table),
            config,
            capability=capability,
        )
