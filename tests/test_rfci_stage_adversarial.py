from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import sys
from types import MappingProxyType

import pytest

from m5_executor_fixtures import hypothesis
import secaware.pipeline.stages.rfci as rfci_module
from secaware.causal.background import build_background_knowledge, validate_pag_against_background
from secaware.discovery.rfci_backend import RFCI_BACKEND
from secaware.errors import SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.manifest import read_stage_manifest
from secaware.pipeline.stages.effects import effects_stage
from secaware.pipeline.stages.jci import JCI_STAGE_OUTPUTS, jci_stage
from secaware.pipeline.stages.rfci import RFCI_STAGE_INPUTS, RFCI_STAGE_OUTPUTS, rfci_stage
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    PAGRecord,
    PAGRunKind,
)
from secaware.schema.outcomes import (
    AnalysisFailureReason,
    AnalysisFailureRecord,
    AnalysisStage,
    RFCICapabilityRecord,
    RFCISensitivityResult,
)
from test_effect_stage import _base_store
from test_jci_stage import _EmptyFCIRunner
from test_rfci_adapter import _capability
from test_rfci_stage import _disabled_capability, _unavailable_capability
from test_fci_supervisor import _table as _observational_table


pytest_plugins = ("test_jci_stage",)


def _valid_result(
    table: CausalTableRecord,
    _rows: object,
    knowledge: BackgroundKnowledgeRecord,
    config: object,
    *,
    capability: RFCICapabilityRecord,
) -> RFCISensitivityResult:
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind.RFCI_SENSITIVITY,
        table_id=table.table_id,
        backend=RFCI_BACKEND,
        backend_version=config.py_tetrad_commit,
        ci_test="gsq",
        config_sha256=canonical_sha256(config.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=(),
    )
    return RFCISensitivityResult(capability=capability, pag=pag)


def _synthetic_runtime_evidence(
    capability: RFCICapabilityRecord,
    root: Path,
):
    from secaware.discovery import rfci_backend

    return rfci_backend._RFCICapabilityEvidence(
        capability=capability,
        jpype=rfci_backend._DistributionEvidence(
            distribution_name="JPype1",
            module_name="jpype",
            distribution_root=str(root),
            package_root=str(root / "jpype"),
            module_origin=str(root / "jpype" / "__init__.py"),
            manifest_sha256="1" * 64,
        ),
        pytetrad=rfci_backend._DistributionEvidence(
            distribution_name="py-tetrad",
            module_name="pytetrad",
            distribution_root=str(root),
            package_root=str(root / "pytetrad"),
            module_origin=str(root / "pytetrad" / "__init__.py"),
            manifest_sha256="2" * 64,
        ),
        java=rfci_backend._JavaRuntimeEvidence(
            executable=sys.executable,
            home=str(root),
            jvm_library=str(root / "jvm.dll"),
            executable_sha256="3" * 64,
            jvm_library_sha256="4" * 64,
            major=capability.java_major,
        ),
        py_tetrad_installation=rfci_backend._PyTetradInstallationEvidence(
            commit=capability.py_tetrad_commit,
            direct_url_path=str(root / "direct_url.json"),
            direct_url_sha256="5" * 64,
            direct_url_size=1,
            jar_path=str(root / "tetrad-current.jar"),
            jar_sha256=capability.tetrad_jar_sha256,
            jar_size=1,
        ),
    )


@pytest.fixture(scope="session")
def rfci_available_committed(tmp_path_factory: pytest.TempPathFactory):
    feature_ids = (
        "safety.path_normalization",
        "safety.path_normalization",
        "safety.sql_parameterization",
        "safety.sql_parameterization",
        "safety.safe_subprocess",
        "safety.safe_subprocess",
    )
    config, store = _base_store(
        tmp_path_factory.mktemp("rfci-available-base"),
        rfci_enabled=True,
        task_count=1,
        confirmation_feature_ids=feature_ids,
        hypothesis_records=tuple(
            hypothesis(feature_id=feature_id)
            for feature_id in (
                "safety.path_normalization",
                "safety.sql_parameterization",
                "safety.safe_subprocess",
            )
        ),
        discovery_min_independent_tasks=2,
        randomization_min_independent_tasks=2,
    )
    effects_stage(config, store, force=True)
    jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)
    capability = _capability()
    result = rfci_stage(
        config,
        store,
        capability_probe=lambda _config: capability,
        runner=_valid_result,
        force=True,
    )
    return config, store, capability, result


def _rfci_artifact_bytes(store) -> tuple[bytes, ...]:
    return tuple((store.root / path).read_bytes() for path, _model in RFCI_STAGE_OUTPUTS) + (
        store.path(".stages", "rfci-confirmation.json").read_bytes(),
    )


def _jci_artifact_bytes(store) -> tuple[bytes, ...]:
    return tuple((store.root / path).read_bytes() for path, _model in JCI_STAGE_OUTPUTS) + (
        store.path(".stages", "jci-confirmation.json").read_bytes(),
    )


def _rfci_groups(store) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(
            read_jsonl(
                store.root / path,
                model,
                required=True,
                allow_empty=index > 0,
            )
        )
        for index, (path, model) in enumerate(RFCI_STAGE_OUTPUTS)
    )


def _jci_groups(store) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(
            read_jsonl(
                store.root / path,
                model,
                required=True,
                allow_empty=index in {2, 4, 5, 6},
            )
        )
        for index, (path, model) in enumerate(JCI_STAGE_OUTPUTS)
    )


def _replace_first_jci_success_with_failure(
    groups: list[list[object]],
    *,
    duplicate: bool,
) -> None:
    table_id = groups[0][0].table_id
    raw = next(item for item in groups[2] if item.table_id == table_id)
    groups[2] = [item for item in groups[2] if item.table_id != table_id]
    groups[4] = [item for item in groups[4] if item.table_id != table_id]
    groups[5] = [item for item in groups[5] if item.raw_pag_id != raw.pag_id]
    failure = AnalysisFailureRecord.from_content(
        stage=AnalysisStage.JCI,
        subject_id=table_id,
        reason_code=AnalysisFailureReason.BACKEND_FAILURE,
        config_sha256="a" * 64,
        input_bundle_sha256="b" * 64,
    )
    groups[6].extend((failure, failure) if duplicate else (failure,))


def test_rfci_available_fixture_publishes_one_pag_per_jci_table(
    rfci_available_committed,
) -> None:
    _config, store, _capability_record, result = rfci_available_committed
    table_count = len(
        read_jsonl(
            store.root / JCI_STAGE_OUTPUTS[0][0],
            CausalTableRecord,
            required=True,
            allow_empty=False,
        )
    )

    assert result.pag_count == table_count >= 1
    assert result.failure_count == 0


def test_rfci_snapshot_prebuilds_immutable_rows_by_table_index(
    rfci_available_committed,
) -> None:
    config, store, _capability_record, _result = rfci_available_committed

    snapshot = rfci_module._validate_jci_snapshot(config, _jci_groups(store))

    assert isinstance(snapshot.rows_by_table, MappingProxyType)
    assert tuple(snapshot.rows_by_table) == tuple(table.table_id for table in snapshot.tables)
    assert sum(len(local) for local in snapshot.rows_by_table.values()) == len(snapshot.rows)
    with pytest.raises(TypeError):
        snapshot.rows_by_table[snapshot.tables[0].table_id] = ()


def test_rfci_available_loop_never_rescans_snapshot_rows_per_table(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, capability, _result = rfci_available_committed
    validate_snapshot = rfci_module._validate_jci_snapshot
    row_scans = 0

    class CountableRows(tuple):
        def __iter__(self):
            nonlocal row_scans
            row_scans += 1
            return super().__iter__()

    def counted_snapshot(*args):
        checked = validate_snapshot(*args)
        return replace(checked, rows=CountableRows(checked.rows))

    monkeypatch.setattr(rfci_module, "_validate_jci_snapshot", counted_snapshot)

    rfci_stage(
        config,
        store,
        capability_probe=lambda _config: capability,
        runner=_valid_result,
        force=True,
    )

    assert row_scans == 0


def test_rfci_disabled_config_publishes_one_capability_and_rejects_status_mismatch(
    committed_jci_base,
) -> None:
    config, store, _jci_result, _jci_runner, _effect_bytes = committed_jci_base
    calls = {"probe": 0, "run": 0}

    def probe(_config):
        calls["probe"] += 1
        return _disabled_capability()

    def forbidden_runner(*_args, **_kwargs):
        calls["run"] += 1
        raise AssertionError("disabled RFCI invoked its runner")

    result = rfci_stage(
        config,
        store,
        capability_probe=probe,
        runner=forbidden_runner,
        force=True,
    )
    capabilities, pags, failures = _rfci_groups(store)

    assert capabilities == (_disabled_capability(),)
    assert not pags and not failures
    assert calls == {"probe": 1, "run": 0}
    assert result.capability_count == 1
    assert result.pag_count == result.failure_count == 0

    before = _rfci_artifact_bytes(store)
    for mismatch in (_unavailable_capability(), _capability()):
        with pytest.raises(SecAwareError, match="configuration mismatch"):
            rfci_stage(
                config,
                store,
                capability_probe=lambda _config, value=mismatch: value,
                runner=forbidden_runner,
                force=True,
            )
        assert _rfci_artifact_bytes(store) == before


def test_rfci_enabled_unavailable_publishes_no_analysis_and_rejects_disabled_status(
    rfci_available_committed,
) -> None:
    config, store, capability, _result = rfci_available_committed
    calls = {"probe": 0, "run": 0}

    def unavailable_probe(_config):
        calls["probe"] += 1
        return _unavailable_capability()

    def forbidden_runner(*_args, **_kwargs):
        calls["run"] += 1
        raise AssertionError("unavailable RFCI invoked its runner")

    try:
        result = rfci_stage(
            config,
            store,
            capability_probe=unavailable_probe,
            runner=forbidden_runner,
            force=True,
        )
        capabilities, pags, failures = _rfci_groups(store)
        assert capabilities == (_unavailable_capability(),)
        assert not pags and not failures
        assert calls == {"probe": 1, "run": 0}
        assert result.capability_count == 1
        assert result.pag_count == result.failure_count == 0
        before = _rfci_artifact_bytes(store)
        with pytest.raises(SecAwareError, match="configuration mismatch"):
            rfci_stage(
                config,
                store,
                capability_probe=lambda _config: _disabled_capability(),
                runner=forbidden_runner,
                force=True,
            )
        assert _rfci_artifact_bytes(store) == before
    finally:
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            runner=_valid_result,
            force=True,
        )


def test_rfci_default_probe_runs_once_and_freezes_one_capability_for_all_tables(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, capability, _result = rfci_available_committed
    probe_calls = 0
    supplied: list[RFCICapabilityRecord] = []

    def probe(_config):
        nonlocal probe_calls
        probe_calls += 1
        return capability

    def runner(*args, capability, **kwargs):
        supplied.append(capability)
        return _valid_result(*args, capability=capability, **kwargs)

    monkeypatch.setattr(rfci_module, "detect_rfci_capability", probe)
    result = rfci_stage(config, store, runner=runner, force=True)

    assert result.pag_count >= 3
    assert probe_calls == 1
    assert len(supplied) == result.pag_count
    assert all(item is supplied[0] for item in supplied)
    persisted = _rfci_groups(store)[0][0]
    assert supplied[0] == persisted == capability


@pytest.mark.parametrize(
    ("provenance_change", "runner_error"),
    (
        ({"python_version": "3.11.9"}, TimeoutError),
        ({"jpype_version": "9.9.9"}, RuntimeError),
        ({"py_tetrad_commit": "f" * 40}, TimeoutError),
        ({"tetrad_jar_sha256": "f" * 64}, RuntimeError),
    ),
)
def test_rfci_wrong_available_capability_hard_aborts_before_typed_runner_failures(
    rfci_available_committed,
    provenance_change: dict[str, object],
    runner_error: type[Exception],
) -> None:
    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)
    wrong_capability = _capability(**provenance_change)
    runner_calls = 0

    def failing_runner(*_args, **_kwargs):
        nonlocal runner_calls
        runner_calls += 1
        raise runner_error("private")

    try:
        with pytest.raises(SecAwareError, match="capability"):
            rfci_stage(
                config,
                store,
                capability_probe=lambda _config: wrong_capability,
                runner=failing_runner,
                force=True,
            )
        assert runner_calls == 0
        assert _rfci_artifact_bytes(store) == before
    finally:
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            runner=_valid_result,
            force=True,
        )


def test_rfci_zero_pag_output_validation_rejects_wrong_available_capability(
    rfci_available_committed,
) -> None:
    config, store, _capability_record, _result = rfci_available_committed
    snapshot = rfci_module._validate_jci_snapshot(config, _jci_groups(store))
    wrong_capability = _capability(python_version="3.11.9")
    config_sha256 = canonical_sha256(config.rfci.model_dump(mode="json"))
    input_bundle_sha256 = canonical_sha256(
        {"schema_version": "1.0", "input_sha256": list(snapshot.input_sha256)}
    )
    failures = tuple(
        AnalysisFailureRecord.from_content(
            stage=AnalysisStage.RFCI,
            subject_id=table.table_id,
            reason_code=AnalysisFailureReason.BACKEND_TIMEOUT,
            config_sha256=config_sha256,
            input_bundle_sha256=input_bundle_sha256,
        )
        for table in snapshot.tables
    )

    with pytest.raises(SecAwareError):
        rfci_module._validate_outputs(
            config,
            ((wrong_capability,), (), failures),
            snapshot,
        )


def test_rfci_available_multitable_publishes_exact_pag_or_typed_failure_partition(
    rfci_available_committed,
) -> None:
    config, store, capability, _result = rfci_available_committed
    tables = tuple(
        read_jsonl(
            store.root / JCI_STAGE_OUTPUTS[0][0],
            CausalTableRecord,
            required=True,
            allow_empty=False,
        )
    )
    assert len(tables) >= 3
    outcome_by_table = {table.table_id: index % 3 for index, table in enumerate(tables)}
    supplied: list[RFCICapabilityRecord] = []
    probe_calls = 0

    def probe(_config):
        nonlocal probe_calls
        probe_calls += 1
        return capability

    def runner(table, *args, capability, **kwargs):
        supplied.append(capability)
        outcome = outcome_by_table[table.table_id]
        if outcome == 1:
            raise TimeoutError("private")
        if outcome == 2:
            raise RuntimeError("private")
        return _valid_result(table, *args, capability=capability, **kwargs)

    result = rfci_stage(
        config,
        store,
        capability_probe=probe,
        runner=runner,
        force=True,
    )
    capabilities, pags, failures = _rfci_groups(store)
    pag_ids = {item.table_id for item in pags}
    failure_by_table = {item.subject_id: item.reason_code for item in failures}

    assert probe_calls == 1
    assert len(supplied) == len(tables)
    assert all(item is supplied[0] for item in supplied)
    assert capabilities == (supplied[0],)
    assert pag_ids == {table_id for table_id, outcome in outcome_by_table.items() if outcome == 0}
    assert failure_by_table == {
        table_id: (
            AnalysisFailureReason.BACKEND_TIMEOUT
            if outcome == 1
            else AnalysisFailureReason.BACKEND_FAILURE
        )
        for table_id, outcome in outcome_by_table.items()
        if outcome != 0
    }
    assert result.pag_count == len(pag_ids)
    assert result.failure_count == len(failure_by_table)
    assert pag_ids.isdisjoint(failure_by_table)
    assert pag_ids | set(failure_by_table) == set(outcome_by_table)


def test_rfci_default_backend_timeout_survives_real_isolation_wrappers(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend
    from secaware.process_isolation import run_isolated_process

    config, store, capability, _result = rfci_available_committed
    evidence = _synthetic_runtime_evidence(capability, tmp_path)

    def timed_out_process(*_args, **_kwargs):
        return run_isolated_process(
            (sys.executable, "-I", "-c", "import time;time.sleep(30)"),
            cwd=tmp_path,
            environment={"PATH": "", "PYTHONUTF8": "1"},
            timeout_seconds=0.05,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            require_canonical_json=True,
        )

    monkeypatch.setattr(rfci_backend, "_collect_runtime_evidence", lambda _config: evidence)
    monkeypatch.setattr(rfci_backend, "run_isolated_process", timed_out_process)
    try:
        result = rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            force=True,
        )
        _capabilities, pags, failures = _rfci_groups(store)

        assert not pags
        assert result.failure_count == len(failures) >= 3
        assert {item.reason_code for item in failures} == {AnalysisFailureReason.BACKEND_TIMEOUT}
    finally:
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            runner=_valid_result,
            force=True,
        )


def test_rfci_default_backend_crash_survives_real_isolation_wrappers(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend
    from secaware.process_isolation import run_isolated_process

    config, store, capability, _result = rfci_available_committed
    evidence = _synthetic_runtime_evidence(capability, tmp_path)

    def crashed_process(*_args, **_kwargs):
        return run_isolated_process(
            (sys.executable, "-I", "-c", "import os;os._exit(7)"),
            cwd=tmp_path,
            environment={"PATH": "", "PYTHONUTF8": "1"},
            timeout_seconds=2.0,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            require_canonical_json=True,
        )

    monkeypatch.setattr(rfci_backend, "_collect_runtime_evidence", lambda _config: evidence)
    monkeypatch.setattr(rfci_backend, "run_isolated_process", crashed_process)
    try:
        result = rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            force=True,
        )
        _capabilities, pags, failures = _rfci_groups(store)

        assert not pags
        assert result.failure_count == len(failures) >= 3
        assert {item.reason_code for item in failures} == {AnalysisFailureReason.BACKEND_FAILURE}
    finally:
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            runner=_valid_result,
            force=True,
        )


def test_rfci_default_backend_noncanonical_output_is_hard_failure(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend
    from secaware.process_isolation import run_isolated_process

    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)
    evidence = _synthetic_runtime_evidence(capability, tmp_path)

    def noncanonical_process(*_args, **_kwargs):
        return run_isolated_process(
            (sys.executable, "-I", "-c", "import sys;sys.stdout.write('{} ')"),
            cwd=tmp_path,
            environment={"PATH": "", "PYTHONUTF8": "1"},
            timeout_seconds=2.0,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            require_canonical_json=True,
        )

    monkeypatch.setattr(rfci_backend, "_collect_runtime_evidence", lambda _config: evidence)
    monkeypatch.setattr(rfci_backend, "run_isolated_process", noncanonical_process)

    with pytest.raises(SecAwareError):
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            force=True,
        )

    assert _rfci_artifact_bytes(store) == before


@pytest.mark.parametrize("stream_name", ("stdout", "stderr"))
def test_rfci_default_backend_live_output_overflow_is_hard_failure(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stream_name: str,
) -> None:
    from secaware.discovery import rfci_backend
    from secaware.process_isolation import run_isolated_process

    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)
    evidence = _synthetic_runtime_evidence(capability, tmp_path)
    script = (
        "import sys,time;"
        f"stream=sys.{stream_name}.buffer;"
        "stream.write(b'x'*8192);stream.flush();time.sleep(30)"
    )

    def overflowing_process(*_args, **_kwargs):
        return run_isolated_process(
            (sys.executable, "-I", "-c", script),
            cwd=tmp_path,
            environment={"PATH": "", "PYTHONUTF8": "1"},
            timeout_seconds=5.0,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            require_canonical_json=False,
        )

    monkeypatch.setattr(rfci_backend, "_collect_runtime_evidence", lambda _config: evidence)
    monkeypatch.setattr(rfci_backend, "run_isolated_process", overflowing_process)
    try:
        with pytest.raises(SecAwareError):
            rfci_stage(
                config,
                store,
                capability_probe=lambda _config: capability,
                force=True,
            )
        assert _rfci_artifact_bytes(store) == before
    finally:
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            runner=_valid_result,
            force=True,
        )


@pytest.mark.parametrize("mode", ("pag_schema", "pag_relation"))
def test_rfci_default_backend_invalid_pag_is_hard_failure(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
) -> None:
    from secaware.discovery import rfci_backend
    from secaware.process_isolation import IsolatedProcessResult

    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)
    evidence = _synthetic_runtime_evidence(capability, tmp_path)
    if mode == "pag_schema":
        payload = b"{}"
    else:
        tables, _rows, _raw, backgrounds, _constrained, _deltas, _failures = _jci_groups(store)
        table = tables[0]
        knowledge = next(
            item.materialized_background_knowledge
            for item in backgrounds
            if item.materialized_background_knowledge.table_id == table.table_id
        )
        pag = PAGRecord.from_content(
            run_kind=PAGRunKind.RFCI_SENSITIVITY,
            table_id=table.table_id,
            backend=RFCI_BACKEND,
            backend_version=config.rfci.py_tetrad_commit,
            ci_test="gsq",
            config_sha256="f" * 64,
            background_knowledge_sha256=knowledge.knowledge_sha256,
            variable_ids=tuple(item.variable_id for item in table.variables),
            edges=(),
        )
        payload = rfci_backend._canonical_json(pag.model_dump(mode="json"))

    monkeypatch.setattr(rfci_backend, "_collect_runtime_evidence", lambda _config: evidence)
    monkeypatch.setattr(
        rfci_backend,
        "run_isolated_process",
        lambda *_args, **_kwargs: IsolatedProcessResult(
            stdout=payload,
            stderr=b"",
            returncode=0,
        ),
    )

    with pytest.raises(SecAwareError):
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            force=True,
        )

    assert _rfci_artifact_bytes(store) == before


def test_rfci_default_backend_invalid_job_input_is_hard_failure(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend

    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)
    evidence = _synthetic_runtime_evidence(capability, tmp_path)

    monkeypatch.setattr(rfci_backend, "_collect_runtime_evidence", lambda _config: evidence)
    monkeypatch.setattr(
        rfci_backend,
        "_build_rfci_worker_argv",
        lambda _path: (_ for _ in ()).throw(ValueError),
    )
    monkeypatch.setattr(
        rfci_backend,
        "run_isolated_process",
        lambda *_args, **_kwargs: pytest.fail("invalid job input reached process execution"),
    )

    with pytest.raises(SecAwareError):
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            force=True,
        )

    assert _rfci_artifact_bytes(store) == before


@pytest.mark.parametrize("interrupt", (MemoryError(), KeyboardInterrupt(), SystemExit()))
def test_rfci_default_backend_fatal_signals_propagate(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interrupt: BaseException,
) -> None:
    from secaware.discovery import rfci_backend

    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)
    evidence = _synthetic_runtime_evidence(capability, tmp_path)

    def fatal_process(*_args, **_kwargs):
        raise interrupt

    monkeypatch.setattr(rfci_backend, "_collect_runtime_evidence", lambda _config: evidence)
    monkeypatch.setattr(rfci_backend, "run_isolated_process", fatal_process)

    with pytest.raises(type(interrupt)) as exc_info:
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            force=True,
        )

    assert exc_info.value is interrupt
    assert _rfci_artifact_bytes(store) == before


def test_rfci_default_backend_runtime_failure_is_typed_backend_failure(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery import rfci_backend

    config, store, capability, _result = rfci_available_committed

    def runtime_failure(_config):
        raise RuntimeError("private runtime failure")

    monkeypatch.setattr(rfci_backend, "_collect_runtime_evidence", runtime_failure)
    try:
        result = rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            force=True,
        )
        _capabilities, pags, failures = _rfci_groups(store)

        assert not pags
        assert result.failure_count == len(failures) >= 3
        assert {item.reason_code for item in failures} == {AnalysisFailureReason.BACKEND_FAILURE}
    finally:
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            runner=_valid_result,
            force=True,
        )


@pytest.mark.parametrize(
    "mutation",
    ("capability", "pag", "table", "background", "config", "invalid_result"),
)
def test_rfci_invalid_runner_return_hard_aborts_and_rolls_back(
    rfci_available_committed,
    mutation: str,
) -> None:
    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)

    def invalid_runner(*args, **kwargs):
        valid = _valid_result(*args, **kwargs)
        if mutation == "capability":
            wrong = capability.model_copy(update={"python_version": "3.13.1"})
            return RFCISensitivityResult(capability=wrong, pag=valid.pag)
        if mutation == "invalid_result":
            return object()
        if mutation == "pag":
            pag = None
        else:
            update = {
                "table": {"table_id": "table_" + "f" * 64},
                "background": {"background_knowledge_sha256": "f" * 64},
                "config": {"config_sha256": "f" * 64},
            }[mutation]
            pag = valid.pag.model_copy(update=update)
        return RFCISensitivityResult.model_construct(capability=capability, pag=pag)

    with pytest.raises(SecAwareError, match="runner output"):
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            runner=invalid_runner,
            force=True,
        )

    assert _rfci_artifact_bytes(store) == before


def test_rfci_persisted_readback_revalidates_every_available_table_relation(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, capability, _result = rfci_available_committed
    tables = tuple(
        read_jsonl(
            store.root / JCI_STAGE_OUTPUTS[0][0],
            CausalTableRecord,
            required=True,
            allow_empty=False,
        )
    )
    validate = rfci_module.validate_rfci_sensitivity_result
    calls: list[tuple[str, RFCICapabilityRecord]] = []

    def tracking_validate(result, table, knowledge, checked_config):
        calls.append((table.table_id, result.capability))
        return validate(result, table, knowledge, checked_config)

    monkeypatch.setattr(
        rfci_module,
        "validate_rfci_sensitivity_result",
        tracking_validate,
    )
    result = rfci_stage(
        config,
        store,
        capability_probe=lambda _config: capability,
        runner=_valid_result,
        force=True,
    )

    assert result.pag_count == len(tables)
    assert Counter(table_id for table_id, _capability_record in calls) == {
        table.table_id: 4 for table in tables
    }
    assert all(item == capability for _table_id, item in calls)


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate_raw",
        "duplicate_constrained",
        "duplicate_delta",
        "dangling_raw_delta",
        "dangling_constrained_delta",
        "raw_constrained_relation",
        "failure_overlap",
        "dangling_failure",
        "duplicate_failure",
        "materialized_background",
        "row_payload",
    ),
)
def test_rfci_jci_snapshot_rejects_duplicate_dangling_and_deep_relation_mutations(
    rfci_available_committed,
    mutation: str,
) -> None:
    config, store, _capability_record, _result = rfci_available_committed
    groups = [list(group) for group in _jci_groups(store)]
    if mutation == "duplicate_raw":
        groups[2].append(groups[2][0])
    elif mutation == "duplicate_constrained":
        groups[4].append(groups[4][0])
    elif mutation == "duplicate_delta":
        groups[5].append(groups[5][0])
    elif mutation == "dangling_raw_delta":
        groups[5][0] = groups[5][0].model_copy(update={"raw_pag_id": "pag_" + "f" * 64})
    elif mutation == "dangling_constrained_delta":
        groups[5][0] = groups[5][0].model_copy(update={"constrained_pag_id": "pag_" + "f" * 64})
    elif mutation == "raw_constrained_relation":
        groups[4][0] = groups[4][0].model_copy(update={"background_knowledge_sha256": "f" * 64})
    elif mutation == "failure_overlap":
        groups[6].append(
            AnalysisFailureRecord.from_content(
                stage=AnalysisStage.JCI,
                subject_id=groups[0][0].table_id,
                reason_code=AnalysisFailureReason.BACKEND_FAILURE,
                config_sha256="a" * 64,
                input_bundle_sha256="b" * 64,
            )
        )
    elif mutation == "dangling_failure":
        groups[6].append(
            AnalysisFailureRecord.from_content(
                stage=AnalysisStage.JCI,
                subject_id="table_" + "f" * 64,
                reason_code=AnalysisFailureReason.BACKEND_FAILURE,
                config_sha256="a" * 64,
                input_bundle_sha256="b" * 64,
            )
        )
    elif mutation == "duplicate_failure":
        _replace_first_jci_success_with_failure(groups, duplicate=True)
    elif mutation == "materialized_background":
        background = groups[3][0]
        groups[3][0] = background.model_copy(
            update={
                "materialized_background_knowledge": (
                    background.materialized_background_knowledge.model_copy(
                        update={"knowledge_sha256": "f" * 64}
                    )
                )
            }
        )
    else:
        row = groups[1][0]
        values = (1 - row.values[0], *row.values[1:])
        groups[1][0] = row.model_copy(update={"values": values})

    with pytest.raises(SecAwareError):
        rfci_module._validate_jci_snapshot(
            config,
            tuple(tuple(group) for group in groups),
        )


def test_rfci_jci_snapshot_accepts_exact_success_failure_partition(
    rfci_available_committed,
) -> None:
    config, store, _capability_record, _result = rfci_available_committed
    groups = [list(group) for group in _jci_groups(store)]
    _replace_first_jci_success_with_failure(groups, duplicate=False)

    snapshot = rfci_module._validate_jci_snapshot(
        config,
        tuple(tuple(group) for group in groups),
    )

    assert len(snapshot.tables) == len(groups[0])


def test_rfci_background_accepts_jci_context_but_observational_fci_remains_strict(
    rfci_available_committed,
) -> None:
    config, store, capability, _result = rfci_available_committed
    tables, rows, _raw, backgrounds, _constrained, _deltas, _failures = _jci_groups(store)
    table = tables[0]
    local_rows = tuple(row for row in rows if row.table_id == table.table_id)
    knowledge = next(
        item.materialized_background_knowledge
        for item in backgrounds
        if item.materialized_background_knowledge.table_id == table.table_id
    )
    rfci_pag = _valid_result(
        table,
        local_rows,
        knowledge,
        config.rfci,
        capability=capability,
    ).pag

    validate_pag_against_background(rfci_pag, knowledge)

    observational_jci_pag = PAGRecord.from_content(
        run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
        table_id=table.table_id,
        backend=config.discovery.backend,
        backend_version=config.discovery.backend_version,
        ci_test=config.discovery.ci_test,
        config_sha256=canonical_sha256(config.discovery.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=(),
    )
    with pytest.raises(SecAwareError):
        validate_pag_against_background(observational_jci_pag, knowledge)

    observational_table = _observational_table()
    observational_knowledge = build_background_knowledge(observational_table)
    observational_pag = PAGRecord.from_content(
        run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
        table_id=observational_table.table_id,
        backend=config.discovery.backend,
        backend_version=config.discovery.backend_version,
        ci_test=config.discovery.ci_test,
        config_sha256=canonical_sha256(config.discovery.model_dump(mode="json")),
        background_knowledge_sha256=observational_knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in observational_table.variables),
        edges=(),
    )
    validate_pag_against_background(observational_pag, observational_knowledge)


def test_rfci_holds_full_jci_snapshot_through_exact_three_output_commit(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, capability, _result = rfci_available_committed
    held: list[tuple[str, ...]] = []
    required: list[tuple[str, tuple[str, ...]]] = []
    transaction_inputs: list[tuple[str, ...]] = []
    snapshot_args: list[tuple[object, ...]] = []
    analysis_validations: list[str] = []
    active = False
    observed = {"install": 0, "seal": 0, "record": 0}
    hold = store.hold_dependency_stages
    require = store.require_committed_output
    execute = rfci_module.execute_jsonl_stage_transaction
    validate_snapshot = rfci_module._validate_jci_snapshot
    install = ArtifactTransaction.install
    seal = store.seal_stage_outputs
    record = store.record_stage

    @contextmanager
    def tracking_hold(stages):
        nonlocal active
        held.append(tuple(stages))
        with hold(stages) as leased:
            active = True
            try:
                yield leased
            finally:
                active = False

    def tracking_require(stage, outputs, **kwargs):
        required.append((stage, tuple(path.relative_to(store.root).as_posix() for path in outputs)))
        return require(stage, outputs, **kwargs)

    def tracking_execute(*args, **kwargs):
        transaction_inputs.append(
            tuple(path.relative_to(store.root).as_posix() for path in kwargs["inputs"])
        )
        return execute(*args, **kwargs)

    def tracking_snapshot(*args):
        snapshot_args.append(args)
        return validate_snapshot(*args)

    def tracking_analysis(table, *_args, **_kwargs):
        analysis_validations.append(table.table_id)

    def tracking_install(self, index, candidate):
        assert active
        observed["install"] += 1
        return install(self, index, candidate)

    def tracking_seal(stage, outputs):
        assert active
        observed["seal"] += 1
        return seal(stage, outputs)

    def tracking_record(*args, **kwargs):
        assert active
        observed["record"] += 1
        return record(*args, **kwargs)

    monkeypatch.setattr(store, "hold_dependency_stages", tracking_hold)
    monkeypatch.setattr(store, "require_committed_output", tracking_require)
    monkeypatch.setattr(rfci_module, "execute_jsonl_stage_transaction", tracking_execute)
    monkeypatch.setattr(rfci_module, "_validate_jci_snapshot", tracking_snapshot)
    monkeypatch.setattr(
        rfci_module,
        "validate_jci_analysis_result",
        tracking_analysis,
        raising=False,
    )
    monkeypatch.setattr(ArtifactTransaction, "install", tracking_install)
    monkeypatch.setattr(store, "seal_stage_outputs", tracking_seal)
    monkeypatch.setattr(store, "record_stage", tracking_record)

    rfci_stage(
        config,
        store,
        capability_probe=lambda _config: capability,
        runner=_valid_result,
        force=True,
    )

    expected_jci = tuple(path.as_posix() for path, _model in JCI_STAGE_OUTPUTS)
    expected_inputs = expected_jci + (".stages/jci-confirmation.json",)
    assert held == [("jci-confirmation",)]
    assert required == [("jci-confirmation", expected_jci)] * 2
    assert transaction_inputs == [expected_inputs]
    assert len(analysis_validations) == len(_jci_groups(store)[2])
    assert snapshot_args and snapshot_args[0][0] is config
    assert observed == {"install": 3, "seal": 1, "record": 1}
    committed = store.require_committed_output(
        "rfci-confirmation",
        tuple(store.root / path for path, _model in RFCI_STAGE_OUTPUTS),
    )
    assert committed == {
        path.as_posix(): sha256_path(store.root / path) for path, _model in RFCI_STAGE_OUTPUTS
    }


def test_rfci_all_reads_and_outputs_are_finitely_bounded_and_fingerprinted(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, capability, _result = rfci_available_committed
    observed: list[tuple[int | None, int | None, int | None]] = []
    read = rfci_module.read_jsonl

    def tracking_read(*args, **kwargs):
        observed.append(
            (
                kwargs.get("max_records"),
                kwargs.get("max_line_chars"),
                kwargs.get("max_total_chars"),
            )
        )
        return read(*args, **kwargs)

    monkeypatch.setattr(rfci_module, "read_jsonl", tracking_read)
    rfci_stage(
        config,
        store,
        capability_probe=lambda _config: capability,
        runner=_valid_result,
        force=True,
    )

    assert observed and set(observed) == {(100_000, 4_000_000, 256_000_000)}
    specs = rfci_module._output_specs(store)
    assert len(specs) == 3
    assert all(
        spec.max_records > 0 and spec.max_line_chars > 0 and spec.max_total_chars > 0
        for spec in specs
    )
    assert store._requires_output_seal("rfci-confirmation")
    inputs = tuple(store.root / path for path in RFCI_STAGE_INPUTS)
    manifest = read_stage_manifest(store.path(".stages", "rfci-confirmation.json"))
    assert manifest.fingerprint == store.stage_fingerprint("rfci-confirmation", inputs)


def test_rfci_skip_avoids_probe_and_runner_but_output_tamper_rebuilds(
    rfci_available_committed,
) -> None:
    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("valid RFCI skip crossed an execution boundary")

    rfci_stage(
        config,
        store,
        capability_probe=forbidden,
        runner=forbidden,
        force=False,
    )
    assert _rfci_artifact_bytes(store) == before

    path = store.root / RFCI_STAGE_OUTPUTS[1][0]
    canonical = path.read_bytes()
    path.write_bytes(canonical + b"\n")
    calls = {"probe": 0, "run": 0}

    def probe(_config):
        calls["probe"] += 1
        return capability

    def run(*args, **kwargs):
        calls["run"] += 1
        return _valid_result(*args, **kwargs)

    rfci_stage(config, store, capability_probe=probe, runner=run, force=False)

    table_count = len(
        read_jsonl(
            store.root / JCI_STAGE_OUTPUTS[0][0],
            CausalTableRecord,
            required=True,
            allow_empty=False,
        )
    )
    assert calls == {"probe": 1, "run": table_count}
    assert path.read_bytes() == canonical


@pytest.mark.parametrize("failure_point", ("install", "record"))
def test_rfci_force_failure_restores_three_outputs_and_manifest(
    rfci_available_committed,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)
    if failure_point == "install":
        install = ArtifactTransaction.install
        failed = False

        def fail_second(self, index, candidate):
            nonlocal failed
            if index == 1 and not failed:
                failed = True
                raise TransactionStateError("private")
            return install(self, index, candidate)

        monkeypatch.setattr(ArtifactTransaction, "install", fail_second)
    else:
        monkeypatch.setattr(
            store,
            "record_stage",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("private")),
        )

    with pytest.raises(Exception):
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            runner=_valid_result,
            force=True,
        )

    assert _rfci_artifact_bytes(store) == before


def test_rfci_producer_mutation_hard_aborts_and_restores_prior_commit(
    rfci_available_committed,
) -> None:
    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)
    jci_before = _jci_artifact_bytes(store)
    producer = store.root / JCI_STAGE_OUTPUTS[0][0]
    original = producer.read_bytes()
    mutated = False

    def mutate_then_return(*args, **kwargs):
        nonlocal mutated
        if not mutated:
            producer.write_bytes(original + b"\n")
            mutated = True
        return _valid_result(*args, **kwargs)

    try:
        with pytest.raises(SecAwareError, match="producer changed"):
            rfci_stage(
                config,
                store,
                capability_probe=lambda _config: capability,
                runner=mutate_then_return,
                force=True,
            )
        assert _rfci_artifact_bytes(store) == before
    finally:
        producer.write_bytes(original)
    assert _jci_artifact_bytes(store) == jci_before


def test_rfci_invalid_return_is_hard_abort_not_typed_backend_failure(
    rfci_available_committed,
) -> None:
    config, store, capability, _result = rfci_available_committed
    before = _rfci_artifact_bytes(store)
    wrong_capability = capability.model_copy(update={"python_version": "3.11.9"})

    def wrong_capability_result(*args, **kwargs):
        valid = _valid_result(*args, **kwargs)
        return RFCISensitivityResult(capability=wrong_capability, pag=valid.pag)

    with pytest.raises(SecAwareError):
        rfci_stage(
            config,
            store,
            capability_probe=lambda _config: capability,
            runner=wrong_capability_result,
            force=True,
        )

    assert _rfci_artifact_bytes(store) == before
