from __future__ import annotations

import csv
from dataclasses import replace
from importlib import import_module
from io import StringIO
import json
from pathlib import Path
import re
import threading
from types import SimpleNamespace

import pytest

from secaware.config import RFCIConfig
from secaware.errors import SecAwareError
from secaware.io.run_store import RunStore
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
from secaware.pipeline.artifact import sha256_path
from secaware.pipeline.manifest import read_stage_manifest, write_stage_manifest
from secaware.pipeline.stages.effects import EFFECT_STAGE_OUTPUTS
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.jci import JCI_STAGE_OUTPUTS
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.pipeline.stages.rfci import RFCI_STAGE_OUTPUTS
from secaware.schema.outcomes import (
    AnalysisFailureReason,
    AnalysisFailureRecord,
    AnalysisStage,
    AssignmentOutcomeRecord,
    RFCICapabilityRecord,
)


pytest_plugins = ("test_jci_stage",)


EXPECTED_REPORT_OUTPUTS = (
    "reports/discovery_pags.jsonl",
    "reports/hypotheses.jsonl",
    "reports/interventions.jsonl",
    "reports/assignments.jsonl",
    "reports/effects.csv",
    "reports/jci_orientations.csv",
    "reports/failures.csv",
    "reports/hypothesis_cards.jsonl",
    "reports/summary.md",
)

EXPECTED_REPORT_PRODUCERS = (
    "build-confirmation-variants",
    "estimate-confirmation-effects",
    "fci-discovery",
    "jci-confirmation",
    "randomize-confirmation",
    "rfci-confirmation",
)

REMOVED_LEGACY_REPORTING_WRAPPERS = (
    Path("src/secaware/discovery/stability.py"),
    Path("src/secaware/intervention/patch.py"),
)


def _relative_outputs(definition: tuple) -> tuple[Path, ...]:
    return tuple(Path(item[0] if isinstance(item, tuple) else item) for item in definition)


EXPECTED_REPORT_INPUTS = (
    *(Path("discovery") / name for name, _model in FCI_DISCOVERY_OUTPUTS),
    *(Path("interventions") / name for name, _model in PROMPT_VARIANT_OUTPUTS),
    *(Path("interventions") / name for name, _model in RANDOMIZATION_OUTPUTS),
    *_relative_outputs(EFFECT_STAGE_OUTPUTS),
    *_relative_outputs(JCI_STAGE_OUTPUTS),
    *_relative_outputs(RFCI_STAGE_OUTPUTS),
    *(Path(".stages") / f"{stage}.json" for stage in EXPECTED_REPORT_PRODUCERS),
)


def _report_output_paths(module: object) -> tuple[Path, ...]:
    return _relative_outputs(module.REPORT_STAGE_OUTPUTS)  # type: ignore[attr-defined]


def test_unused_legacy_reporting_wrappers_are_absent() -> None:
    project_root = Path(__file__).resolve().parents[1]

    assert [
        path.as_posix()
        for path in REMOVED_LEGACY_REPORTING_WRAPPERS
        if (project_root / path).exists()
    ] == []


def _jsonl_dicts(path: Path) -> tuple[dict[str, object], ...]:
    return tuple(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line)


def _csv_rows(path: Path) -> tuple[tuple[str, ...], tuple[dict[str, str], ...]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return tuple(reader.fieldnames or ()), tuple(reader)


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


def _available_capability() -> RFCICapabilityRecord:
    return RFCICapabilityRecord(
        schema_version="1.0",
        available=True,
        status="available",
        requires_java=True,
        python_version="3.12.9",
        java_major=21,
        jpype_version="1.7.1",
        py_tetrad_commit="a30707264aa4363a23ac5f136a70bbdd62212f07",
        tetrad_jar_sha256="3c898047c26a909495925d3e50264150f58ee57cd5b48d95683c45e3ab0e17f4",
        reason_code=None,
    )


def _report_commit_bytes(store: RunStore) -> tuple[bytes, ...]:
    return tuple((store.root / relative).read_bytes() for relative in EXPECTED_REPORT_OUTPUTS) + (
        store.path(".stages", "report.json").read_bytes(),
    )


def test_report_stage_declares_complete_outputs_and_only_upstream_inputs() -> None:
    module = import_module("secaware.pipeline.stages.reporting")

    assert tuple(path.as_posix() for path in _report_output_paths(module)) == (
        EXPECTED_REPORT_OUTPUTS
    )
    assert tuple(module.REPORT_PRODUCER_STAGES) == EXPECTED_REPORT_PRODUCERS
    assert len(module.REPORT_STAGE_INPUTS) == len(set(module.REPORT_STAGE_INPUTS))
    assert set(module.REPORT_STAGE_INPUTS) == set(EXPECTED_REPORT_INPUTS)
    assert all(path.parts[0] != "reports" for path in module.REPORT_STAGE_INPUTS)
    assert all("code" not in path.name for path in module.REPORT_STAGE_INPUTS)
    assert RunStore._requires_output_seal("report")


def test_report_contract_binds_render_shapes_and_every_failure_source_schema() -> None:
    contracts = import_module("secaware.pipeline.stage_contracts")
    payload = contracts.report_stage_contract_payload()

    assert payload["render_contract_version"] == "prompt-only-report-render-v1"
    assert payload["jsonl_row_shape_version"] == "prompt-only-report-jsonl-v1"
    assert payload["csv_row_shape_version"] == "prompt-only-report-csv-v1"
    assert payload["hypothesis_card_shape_version"] == "prompt-only-hypothesis-card-v1"
    assert payload["summary_shape_version"] == "prompt-only-summary-v1"
    assert payload["bootstrap_failure_schema"]
    assert payload["discovery_failure_schema"]
    assert payload["analysis_failure_schema"]


def test_cli_report_stage_delegates_only_to_prompt_only_reporting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli = import_module("secaware.cli")
    config = object()
    store = object()
    calls: list[tuple[object, object, bool]] = []

    def delegate(given_config: object, given_store: object, *, force: bool) -> None:
        calls.append((given_config, given_store, force))

    monkeypatch.setattr(cli, "write_reports", delegate)

    cli.report_stage(config, store, force=True)

    assert calls == [(config, store, True)]


@pytest.fixture(scope="module")
def published_reports(committed_jci_base):
    config, store, _jci_result, _runner, _effect_bytes = committed_jci_base
    rfci_module = import_module("secaware.pipeline.stages.rfci")
    reporting_module = import_module("secaware.pipeline.stages.reporting")

    rfci_module.rfci_stage(
        config,
        store,
        force=True,
        capability_probe=lambda _config: _disabled_capability(),
        runner=lambda *_args, **_kwargs: pytest.fail("disabled RFCI invoked Java"),
    )
    input_paths = tuple(store.root / path for path in reporting_module.REPORT_STAGE_INPUTS)
    before = {path.relative_to(store.root).as_posix(): path.read_bytes() for path in input_paths}

    result = reporting_module.write_reports(config, store, force=True)

    after = {path.relative_to(store.root).as_posix(): path.read_bytes() for path in input_paths}
    return reporting_module, store, result, before, after


def test_reports_publish_exact_transaction_without_mutating_any_producer(
    published_reports,
) -> None:
    module, store, _result, before, after = published_reports
    report_files = tuple(
        sorted(
            path.relative_to(store.root).as_posix()
            for path in store.path("reports").iterdir()
            if path.is_file()
        )
    )

    assert report_files == tuple(sorted(EXPECTED_REPORT_OUTPUTS))
    assert before == after
    manifest = read_stage_manifest(store.path(".stages", "report.json"))
    assert tuple(manifest.outputs) == EXPECTED_REPORT_OUTPUTS
    assert set(manifest.output_sha256) == set(EXPECTED_REPORT_OUTPUTS)
    assert manifest.output_sha256 == {
        relative: sha256_path(store.root / relative) for relative in EXPECTED_REPORT_OUTPUTS
    }


def test_prompt_only_reports_have_no_legacy_or_code_mechanism_language(
    published_reports,
) -> None:
    _module, store, _result, _before, _after = published_reports
    filenames = {path.name.casefold() for path in store.path("reports").iterdir()}
    assert filenames.isdisjoint(
        {
            "funnel.csv",
            "mechanism_cards.jsonl",
            "pair_results.jsonl",
            "hypothesis_effects.jsonl",
        }
    )

    rendered = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(store.path("reports").iterdir())
        if path.is_file()
    ).casefold()
    forbidden_phrases = (
        "code mechanism",
        "code-mechanism",
        "code_mechanism",
        "mechanism card",
        "mechanism_card",
        "mediator",
        "source-to-sink code path",
        "source_to_sink_code_path",
    )
    assert all(phrase not in rendered for phrase in forbidden_phrases)
    assert re.search(r"circle.{0,80}directed cause|directed cause.{0,80}circle", rendered) is None

    cards = _jsonl_dicts(store.path("reports", "hypothesis_cards.jsonl"))
    assert cards
    for card in cards:
        assert len({"prompt_path", "hypothesis_path"} & set(card)) == 1
        keys = json.dumps(card, ensure_ascii=False, sort_keys=True).casefold()
        assert all(phrase not in keys for phrase in forbidden_phrases)


def test_report_manifest_and_rows_preserve_basic_source_provenance(
    published_reports,
) -> None:
    module, store, _result, _before, _after = published_reports
    manifest = read_stage_manifest(store.path(".stages", "report.json"))
    expected_inputs = {
        path.as_posix(): sha256_path(store.root / path) for path in module.REPORT_STAGE_INPUTS
    }
    assert manifest.stage == "report"
    assert manifest.inputs == expected_inputs

    pag_ids = {
        row["pag_id"]
        for relative in (
            Path("discovery/reference_pags.jsonl"),
            Path("analysis/jci_raw_pags.jsonl"),
            Path("analysis/jci_constrained_pags.jsonl"),
            Path("analysis/rfci_pags.jsonl"),
        )
        for row in _jsonl_dicts(store.root / relative)
    }
    hypothesis_rows = _jsonl_dicts(store.path("discovery", "hypotheses_frozen.jsonl"))
    hypothesis_ids = {row["hypothesis_id"] for row in hypothesis_rows}
    variant_rows = _jsonl_dicts(store.path("interventions", "prompt_variants.jsonl"))
    delta_rows = _jsonl_dicts(store.path("interventions", "graph_deltas.jsonl"))
    assignment_rows = _jsonl_dicts(store.path("interventions", "assignments.jsonl"))
    effect_rows = _jsonl_dicts(store.path("analysis", "itt_effects.jsonl"))
    jci_delta_rows = _jsonl_dicts(store.path("analysis", "jci_orientation_deltas.jsonl"))

    report_pag_text = store.path("reports", "discovery_pags.jsonl").read_text(encoding="utf-8")
    report_hypothesis_text = store.path("reports", "hypotheses.jsonl").read_text(encoding="utf-8")
    report_intervention_text = store.path("reports", "interventions.jsonl").read_text(
        encoding="utf-8"
    )
    report_assignment_text = store.path("reports", "assignments.jsonl").read_text(encoding="utf-8")
    report_card_text = store.path("reports", "hypothesis_cards.jsonl").read_text(encoding="utf-8")

    assert all(identifier in report_pag_text for identifier in pag_ids)
    assert all(identifier in report_hypothesis_text for identifier in hypothesis_ids)
    assert all(identifier in report_card_text for identifier in hypothesis_ids)
    assert all(row["hypothesis_sha256"] in report_card_text for row in hypothesis_rows)
    assert all(row["variant_id"] in report_intervention_text for row in variant_rows)
    assert all(row["prompt_sha256"] in report_intervention_text for row in variant_rows)
    assert all(row["delta_id"] in report_intervention_text for row in delta_rows)
    assert all(row["before_graph_sha256"] in report_intervention_text for row in delta_rows)
    assert all(row["after_graph_sha256"] in report_intervention_text for row in delta_rows)
    assert all(row["assignment_id"] in report_assignment_text for row in assignment_rows)
    assert all(
        row["randomization_plan_sha256"] in report_assignment_text for row in assignment_rows
    )

    effect_fields, reported_effects = _csv_rows(store.path("reports", "effects.csv"))
    assert {
        "effect_id",
        "hypothesis_id",
        "target_spec_id",
        "arm_protocol_id",
        "model_id",
        "contrast_id",
        "outcome_id",
        "assignment_universe_sha256",
        "target_instance_universe_sha256",
        "bootstrap_manifest_sha256",
    } <= set(effect_fields)
    assert {row["effect_id"] for row in reported_effects} == {
        row["effect_id"] for row in effect_rows
    }

    jci_fields, reported_jci = _csv_rows(store.path("reports", "jci_orientations.csv"))
    assert {
        "delta_id",
        "raw_pag_id",
        "constrained_pag_id",
        "assumption_set_sha256",
    } <= set(jci_fields)
    assert {row["delta_id"] for row in reported_jci} == {row["delta_id"] for row in jci_delta_rows}

    failure_fields, _reported_failures = _csv_rows(store.path("reports", "failures.csv"))
    assert {
        "source_stage",
        "record_id",
        "reason_code",
        "config_sha256",
        "input_bundle_sha256",
        "detail_sha256",
    } <= set(failure_fields)
    summary = store.path("reports", "summary.md").read_text(encoding="utf-8").casefold()
    assert "rfcI".casefold() in summary
    assert "disabled" in summary


def test_valid_skip_authenticates_typed_sources_without_running_report_builder(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    before = _report_commit_bytes(store)
    validations = 0
    delegate_validate = module._validate_snapshot

    def tracking_validate(snapshot):
        nonlocal validations
        validations += 1
        return delegate_validate(snapshot)

    monkeypatch.setattr(module, "_validate_snapshot", tracking_validate)
    monkeypatch.setattr(
        module,
        "_build_documents",
        lambda *_args, **_kwargs: pytest.fail("valid report skip rebuilt documents"),
    )

    module.write_reports(store.config, store, force=False)

    assert validations >= 1
    assert _report_commit_bytes(store) == before


def test_validate_committed_reports_never_rebuilds(published_reports, monkeypatch) -> None:
    module, store, result, _before, _after = published_reports
    monkeypatch.setattr(
        module,
        "_build_documents",
        lambda _snapshot: pytest.fail("validate-only path rebuilt reports"),
    )

    assert module.validate_committed_reports(store.config, store) == result


def test_validate_committed_reports_rejects_invalid_pending_transaction(published_reports) -> None:
    module, store, _result, _before, _after = published_reports
    journal = store.path(".stages", ".report.transaction.json")
    journal.write_text("{}\n", encoding="utf-8", newline="\n")
    try:
        with pytest.raises(SecAwareError, match="transaction recovery failed"):
            module.validate_committed_reports(store.config, store)
    finally:
        journal.unlink(missing_ok=True)


COORDINATED_SKIP_MUTATIONS = (
    "duplicate",
    "dangling",
    "formula",
    "markdown",
    "capability",
)


def _unsafe_csv_bytes(fields: tuple[str, ...], rows: list[dict[str, str]]) -> bytes:
    handle = StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=list(fields), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return handle.getvalue().encode("utf-8")


def _coordinate_report_tamper(module, store: RunStore, mutation: str) -> None:
    if mutation == "duplicate":
        target = store.path("reports", "hypotheses.jsonl")
        data = target.read_bytes()
        target.write_bytes(data + data.splitlines(keepends=True)[0])
    elif mutation == "dangling":
        target = store.path("reports", "assignments.jsonl")
        rows = list(_jsonl_dicts(target))
        rows[0]["assignment_outcome"]["assignment_id"] = "assignment_" + "0" * 64
        target.write_bytes(module.canonical_jsonl_bytes(rows))
    elif mutation == "formula":
        target = store.path("reports", "effects.csv")
        fields, rows_tuple = _csv_rows(target)
        rows = list(rows_tuple)
        rows[0]["model_id"] = "=1+1"
        target.write_bytes(_unsafe_csv_bytes(fields, rows))
    elif mutation == "markdown":
        target = store.path("reports", "summary.md")
        text = target.read_text(encoding="utf-8")
        text = re.sub(r"- Frozen hypotheses: [0-9]+", "- Frozen hypotheses: 999999", text)
        target.write_text(text, encoding="utf-8", newline="\n")
    else:
        target = store.path("reports", "summary.md")
        capability = _unavailable_capability()
        canonical = json.dumps(
            capability.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        lines = target.read_text(encoding="utf-8").splitlines()
        lines = [
            "- RFCI status: unavailable"
            if line.startswith("- RFCI status: ")
            else (
                f"- RFCI reason: {module.canonical_markdown_code('jpype_missing')}"
                if line.startswith("- RFCI reason: ")
                else (
                    f"{module.RFCI_CAPABILITY_PREFIX}{module.canonical_markdown_code(canonical)}"
                    if line.startswith(module.RFCI_CAPABILITY_PREFIX)
                    else line
                )
            )
            for line in lines
        ]
        target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    manifest_path = store.path(".stages", "report.json")
    manifest = read_stage_manifest(manifest_path)
    hashes = {relative: sha256_path(store.root / relative) for relative in EXPECTED_REPORT_OUTPUTS}
    write_stage_manifest(manifest_path, manifest.model_copy(update={"output_sha256": hashes}))


@pytest.mark.parametrize("mutation", COORDINATED_SKIP_MUTATIONS)
def test_coordinated_report_and_manifest_tamper_cannot_pass_skip(
    published_reports,
    mutation: str,
) -> None:
    module, store, _result, _before, _after = published_reports
    before = _report_commit_bytes(store)
    try:
        _coordinate_report_tamper(module, store, mutation)

        with pytest.raises(SecAwareError):
            module.write_reports(store.config, store, force=False)
    finally:
        for relative, data in zip(
            (*EXPECTED_REPORT_OUTPUTS, ".stages/report.json"), before, strict=True
        ):
            (store.root / relative).write_bytes(data)


@pytest.mark.parametrize("relative", EXPECTED_REPORT_OUTPUTS)
def test_any_tampered_report_output_invalidates_skip_and_rebuilds_exact_bytes(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    module, store, _result, _before, _after = published_reports
    before = _report_commit_bytes(store)
    target = store.root / relative
    target.write_bytes(target.read_bytes() + b"tamper\n")
    builds = 0
    delegate = module._build_documents

    def tracking_build(snapshot):
        nonlocal builds
        builds += 1
        return delegate(snapshot)

    monkeypatch.setattr(module, "_build_documents", tracking_build)

    module.write_reports(store.config, store, force=False)

    assert builds == 1
    assert _report_commit_bytes(store) == before


@pytest.mark.parametrize("failure_point", ("install", "seal", "record"))
def test_force_failure_restores_all_reports_and_manifest_byte_for_byte(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    module, store, _result, _before, _after = published_reports
    before = _report_commit_bytes(store)
    if failure_point == "install":
        delegate = ArtifactTransaction.install

        def fail_install(transaction, index, candidate):
            if index == 4:
                raise TransactionStateError("private")
            return delegate(transaction, index, candidate)

        monkeypatch.setattr(ArtifactTransaction, "install", fail_install)
    elif failure_point == "seal":
        monkeypatch.setattr(
            store,
            "seal_stage_outputs",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("private")),
        )
    else:
        delegate_record = store.record_stage

        def fail_after_record(*args, **kwargs):
            delegate_record(*args, **kwargs)
            raise RuntimeError("private")

        monkeypatch.setattr(store, "record_stage", fail_after_record)

    with pytest.raises(Exception):
        module.write_reports(store.config, store, force=True)

    assert _report_commit_bytes(store) == before


FATAL_EXCEPTION_TYPES = (MemoryError, KeyboardInterrupt, SystemExit)
PAIRED_FATAL_EXCEPTION_TYPES = (
    (MemoryError, KeyboardInterrupt),
    (KeyboardInterrupt, SystemExit),
    (SystemExit, MemoryError),
)
TRIPLE_FATAL_EXCEPTION_TYPES = (
    (MemoryError, KeyboardInterrupt, SystemExit),
    (KeyboardInterrupt, SystemExit, MemoryError),
    (SystemExit, MemoryError, KeyboardInterrupt),
)


def _raise_exact(error: BaseException) -> None:
    raise error


def _run_report_precommit_failure(
    module,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    active_error: BaseException,
    recovery_error: BaseException | None,
    abort_error: BaseException | None = None,
    cleanup_error: BaseException | None = None,
) -> tuple[BaseException, list[str]]:
    active = True
    aborts: list[str] = []

    def abort(stage: str) -> None:
        nonlocal active
        aborts.append(stage)
        active = False
        if abort_error is not None:
            _raise_exact(abort_error)

    store = SimpleNamespace(
        path=lambda *parts: tmp_path.joinpath(*parts),
        should_skip_stage=lambda *_args, **_kwargs: False,
        stage_is_active=lambda stage: stage == "report" and active,
        abort_stage=abort,
    )
    transaction = SimpleNamespace(backup=lambda _count: None)
    monkeypatch.setattr(
        module.ArtifactTransaction,
        "begin",
        lambda *_args, **_kwargs: transaction,
    )

    def recover(_transaction: object) -> None:
        if recovery_error is not None:
            _raise_exact(recovery_error)

    monkeypatch.setattr(module, "recover_transaction", recover)
    if cleanup_error is not None:
        monkeypatch.setattr(module, "_cleanup_paths", lambda _paths: _raise_exact(cleanup_error))

    try:
        module._execute_report_transaction(
            store,
            inputs=(),
            outputs=(),
            force=False,
            validate_only=False,
            capture_input_snapshot=lambda: (),
            verify_input_snapshot=lambda: None,
            validate_committed=lambda: None,
            build=lambda: _raise_exact(active_error),
        )
    except BaseException as error:
        return error, aborts
    pytest.fail("report transaction unexpectedly succeeded")


@pytest.mark.parametrize("fatal_type", FATAL_EXCEPTION_TYPES)
def test_finalize_ordinary_failure_yields_later_fatal_release(
    fatal_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    ordinary = RuntimeError("finalize")
    release_fatal = fatal_type("release")
    store = SimpleNamespace(
        finalize_stage_commit=lambda _lease: _raise_exact(ordinary),
        ensure_stage_commit_released=lambda _lease: _raise_exact(release_fatal),
    )

    with pytest.raises(BaseException) as exc_info:
        module._finalize_stage_commit(store, object())

    assert exc_info.value is release_fatal


@pytest.mark.parametrize(("active_type", "release_type"), PAIRED_FATAL_EXCEPTION_TYPES)
def test_finalize_active_fatal_preserves_identity_over_later_fatal_release(
    active_type: type[BaseException],
    release_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    active_fatal = active_type("finalize")
    release_fatal = release_type("release")
    store = SimpleNamespace(
        finalize_stage_commit=lambda _lease: _raise_exact(active_fatal),
        ensure_stage_commit_released=lambda _lease: _raise_exact(release_fatal),
    )

    with pytest.raises(BaseException) as exc_info:
        module._finalize_stage_commit(store, object())

    assert exc_info.value is active_fatal


@pytest.mark.parametrize("fatal_type", FATAL_EXCEPTION_TYPES)
def test_active_fatal_precommit_survives_transaction_state_rollback_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fatal_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    active_fatal = fatal_type("active")

    raised, aborts = _run_report_precommit_failure(
        module,
        tmp_path,
        monkeypatch,
        active_error=active_fatal,
        recovery_error=TransactionStateError(),
    )

    assert raised is active_fatal
    assert aborts == ["report"]


@pytest.mark.parametrize("fatal_type", FATAL_EXCEPTION_TYPES)
def test_ordinary_precommit_failure_yields_fatal_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fatal_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    rollback_fatal = fatal_type("rollback")

    raised, aborts = _run_report_precommit_failure(
        module,
        tmp_path,
        monkeypatch,
        active_error=RuntimeError("active"),
        recovery_error=rollback_fatal,
    )

    assert raised is rollback_fatal
    assert aborts == ["report"]


@pytest.mark.parametrize(("active_type", "abort_type"), PAIRED_FATAL_EXCEPTION_TYPES)
def test_active_fatal_survives_fatal_abort_after_transaction_state_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_type: type[BaseException],
    abort_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    active_fatal = active_type("active")
    abort_fatal = abort_type("abort")

    raised, aborts = _run_report_precommit_failure(
        module,
        tmp_path,
        monkeypatch,
        active_error=active_fatal,
        recovery_error=TransactionStateError(),
        abort_error=abort_fatal,
    )

    assert raised is active_fatal
    assert aborts == ["report"]


@pytest.mark.parametrize("fatal_type", FATAL_EXCEPTION_TYPES)
def test_ordinary_failure_yields_fatal_abort_after_transaction_state_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fatal_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    abort_fatal = fatal_type("abort")

    raised, aborts = _run_report_precommit_failure(
        module,
        tmp_path,
        monkeypatch,
        active_error=RuntimeError("active"),
        recovery_error=TransactionStateError(),
        abort_error=abort_fatal,
    )

    assert raised is abort_fatal
    assert aborts == ["report"]


@pytest.mark.parametrize(("active_type", "rollback_type"), PAIRED_FATAL_EXCEPTION_TYPES)
def test_active_fatal_precommit_preserves_identity_over_fatal_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_type: type[BaseException],
    rollback_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    active_fatal = active_type("active")
    rollback_fatal = rollback_type("rollback")

    raised, aborts = _run_report_precommit_failure(
        module,
        tmp_path,
        monkeypatch,
        active_error=active_fatal,
        recovery_error=rollback_fatal,
    )

    assert raised is active_fatal
    assert aborts == ["report"]


@pytest.mark.parametrize(
    ("active_type", "rollback_type", "abort_type"),
    TRIPLE_FATAL_EXCEPTION_TYPES,
)
def test_active_fatal_survives_fatal_rollback_and_fatal_abort(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_type: type[BaseException],
    rollback_type: type[BaseException],
    abort_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    active_fatal = active_type("active")
    rollback_fatal = rollback_type("rollback")
    abort_fatal = abort_type("abort")

    raised, aborts = _run_report_precommit_failure(
        module,
        tmp_path,
        monkeypatch,
        active_error=active_fatal,
        recovery_error=rollback_fatal,
        abort_error=abort_fatal,
    )

    assert raised is active_fatal
    assert aborts == ["report"]


@pytest.mark.parametrize(("rollback_type", "abort_type"), PAIRED_FATAL_EXCEPTION_TYPES)
def test_fatal_rollback_survives_later_fatal_abort_after_ordinary_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rollback_type: type[BaseException],
    abort_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    rollback_fatal = rollback_type("rollback")
    abort_fatal = abort_type("abort")

    raised, aborts = _run_report_precommit_failure(
        module,
        tmp_path,
        monkeypatch,
        active_error=RuntimeError("active"),
        recovery_error=rollback_fatal,
        abort_error=abort_fatal,
    )

    assert raised is rollback_fatal
    assert aborts == ["report"]


@pytest.mark.parametrize(("active_type", "cleanup_type"), PAIRED_FATAL_EXCEPTION_TYPES)
def test_active_fatal_precommit_preserves_identity_over_fatal_candidate_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_type: type[BaseException],
    cleanup_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    active_fatal = active_type("active")
    cleanup_fatal = cleanup_type("cleanup")

    raised, aborts = _run_report_precommit_failure(
        module,
        tmp_path,
        monkeypatch,
        active_error=active_fatal,
        recovery_error=None,
        cleanup_error=cleanup_fatal,
    )

    assert raised is active_fatal
    assert aborts == ["report"]


@pytest.mark.parametrize("fatal_type", FATAL_EXCEPTION_TYPES)
def test_ordinary_precommit_failure_yields_fatal_candidate_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fatal_type: type[BaseException],
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    cleanup_fatal = fatal_type("cleanup")

    raised, aborts = _run_report_precommit_failure(
        module,
        tmp_path,
        monkeypatch,
        active_error=RuntimeError("active"),
        recovery_error=None,
        cleanup_error=cleanup_fatal,
    )

    assert raised is cleanup_fatal
    assert aborts == ["report"]


def test_first_publish_failure_leaves_no_ghost_report_or_manifest(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    output_paths = tuple(store.root / relative for relative in EXPECTED_REPORT_OUTPUTS)
    manifest_path = store.path(".stages", "report.json")
    for path in (*output_paths, manifest_path):
        path.unlink()
    delegate = ArtifactTransaction.install

    def fail_install(transaction, index, candidate):
        if index == 3:
            raise TransactionStateError("private")
        return delegate(transaction, index, candidate)

    monkeypatch.setattr(ArtifactTransaction, "install", fail_install)
    try:
        with pytest.raises(Exception):
            module.write_reports(store.config, store, force=True)
        assert all(not path.exists() for path in output_paths)
        assert not manifest_path.exists()
    finally:
        monkeypatch.setattr(ArtifactTransaction, "install", delegate)
        module.write_reports(store.config, store, force=True)


PRODUCER_MUTATION_CASES = tuple((stage, "artifact") for stage in EXPECTED_REPORT_PRODUCERS) + tuple(
    (stage, "manifest") for stage in EXPECTED_REPORT_PRODUCERS
)


@pytest.mark.parametrize(("producer_stage", "target_kind"), PRODUCER_MUTATION_CASES)
def test_any_producer_artifact_or_manifest_mutation_aborts_and_restores_prior_report(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
    producer_stage: str,
    target_kind: str,
) -> None:
    module, store, _result, _before, _after = published_reports
    before_report = _report_commit_bytes(store)
    producer_paths = module._producer_paths(store)
    target = (
        producer_paths[producer_stage][0]
        if target_kind == "artifact"
        else store.path(".stages", f"{producer_stage}.json")
    )
    before_producer = target.read_bytes()
    delegate = module._build_documents

    def mutate_after_build(snapshot):
        documents = delegate(snapshot)
        target.write_bytes(before_producer + b" \n")
        return documents

    monkeypatch.setattr(module, "_build_documents", mutate_after_build)
    try:
        with pytest.raises(SecAwareError):
            module.write_reports(store.config, store, force=True)
        assert _report_commit_bytes(store) == before_report
    finally:
        target.write_bytes(before_producer)


def test_producer_aba_between_capture_parse_and_final_verify_hard_rolls_back(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    before_report = _report_commit_bytes(store)
    target = module._producer_paths(store)["fci-discovery"][6]
    a_bytes = target.read_bytes()
    rows = list(_jsonl_dicts(target))
    b_bytes = (
        "\n".join(
            json.dumps(
                dict(reversed(tuple(row.items()))),
                ensure_ascii=False,
                separators=(", ", ": "),
            )
            for row in rows
        )
        + "\n"
    ).encode("utf-8")
    assert b_bytes != a_bytes
    delegate_read = module._read
    writer_ran = False

    def aba_read(source, model, *, allow_empty: bool):
        nonlocal writer_ran
        source_path = source.path if hasattr(source, "path") else source
        if source_path != target:
            return delegate_read(source, model, allow_empty=allow_empty)
        writer_ran = True
        target.write_bytes(b_bytes)
        try:
            return delegate_read(source, model, allow_empty=allow_empty)
        finally:
            target.write_bytes(a_bytes)

    monkeypatch.setattr(module, "_read", aba_read)
    try:
        with pytest.raises(SecAwareError) as exc_info:
            module.write_reports(store.config, store, force=True)
        assert exc_info.value.stage == "report"
        assert writer_ran
        assert _report_commit_bytes(store) == before_report
    finally:
        target.write_bytes(a_bytes)


def test_all_producer_bundles_are_verified_under_leases_before_and_after_commit(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    producer_paths = module._producer_paths(store)
    observed: dict[str, list[dict[str, str]]] = {stage: [] for stage in EXPECTED_REPORT_PRODUCERS}
    delegate = store.require_committed_output

    def tracking(stage, outputs, **kwargs):
        assert store._owned_dependency_lease(stage) is not None
        assert tuple(outputs) == producer_paths[stage]
        hashes = delegate(stage, outputs, **kwargs)
        observed[stage].append(hashes)
        return hashes

    monkeypatch.setattr(store, "require_committed_output", tracking)

    module.write_reports(store.config, store, force=True)

    assert set(observed) == set(EXPECTED_REPORT_PRODUCERS)
    assert all(len(calls) == 3 and calls[0] == calls[1] == calls[2] for calls in observed.values())


@pytest.mark.parametrize("prefix", ("=", "+", "-", "@"))
def test_csv_renderer_neutralizes_spreadsheet_formula_prefixes(prefix: str) -> None:
    module = import_module("secaware.reports.tables")

    rendered = module.canonical_csv_bytes(("value",), ({"value": prefix + "private"},))

    parsed = tuple(csv.DictReader(rendered.decode("utf-8").splitlines()))
    assert parsed == ({"value": "'" + prefix + "private"},)


def test_input_and_output_validators_enforce_record_line_and_file_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    input_path = tmp_path / "bounded.jsonl"
    input_path.write_text("{}\n{}\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(module, "_MAX_INPUT_RECORDS", 1)
    with pytest.raises(SecAwareError):
        module._read(input_path, None, allow_empty=True)

    spec = module._OutputSpec(tmp_path / "out.jsonl", "jsonl", max_bytes=3)
    with pytest.raises(SecAwareError, match="byte bound"):
        module._validate_output_bytes(spec, b"{}\n{}\n")

    spec = replace(spec, max_bytes=100)
    monkeypatch.setattr(module, "_MAX_REPORT_RECORDS", 1)
    with pytest.raises(SecAwareError, match="record bound"):
        module._validate_output_bytes(spec, b"{}\n{}\n")

    monkeypatch.setattr(module, "_MAX_REPORT_RECORDS", 10)
    monkeypatch.setattr(module, "_MAX_REPORT_LINE_BYTES", 2)
    with pytest.raises(SecAwareError, match="line exceeds"):
        module._validate_output_bytes(spec, b'{"a":1}\n')


def test_full_producer_hash_snapshot_enforces_per_file_and_total_input_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    left = tmp_path / "left.bin"
    right = tmp_path / "right.bin"
    left.write_bytes(b"1234")
    right.write_bytes(b"5678")

    monkeypatch.setattr(module, "_MAX_REPORT_INPUT_FILE_BYTES", 3)
    with pytest.raises(SecAwareError, match="input file byte bound"):
        module._bounded_input_sha256((left,))

    monkeypatch.setattr(module, "_MAX_REPORT_INPUT_FILE_BYTES", 4)
    monkeypatch.setattr(module, "_MAX_REPORT_INPUT_TOTAL_BYTES", 7)
    with pytest.raises(SecAwareError, match="input bundle byte bound"):
        module._bounded_input_sha256((left, right))


def test_input_snapshot_rejects_non_regular_paths(tmp_path: Path) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    with pytest.raises(SecAwareError, match="input byte bound failed validation"):
        module._bounded_input_sha256((tmp_path,))


def test_input_snapshot_rejects_symlink_paths(tmp_path: Path) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    regular = tmp_path / "regular.jsonl"
    regular.write_text("{}\n", encoding="utf-8", newline="\n")
    symlink = tmp_path / "linked.jsonl"
    try:
        symlink.symlink_to(regular)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(SecAwareError, match="input byte bound failed validation"):
        module._bounded_input_sha256((symlink,))


def test_input_snapshot_detects_mutation_between_pre_and_post_fstat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    path = tmp_path / "changing.jsonl"
    original = b'{"value":"a"}\n'
    path.write_bytes(original)
    delegate_read = module.os.read
    mutated = False

    def mutate_during_read(fd: int, count: int) -> bytes:
        nonlocal mutated
        chunk = delegate_read(fd, count)
        if not mutated:
            mutated = True
            path.write_bytes(b'{"value":"changed"}\n')
        return chunk

    monkeypatch.setattr(module.os, "read", mutate_during_read)
    try:
        with pytest.raises(SecAwareError, match="changed while reading"):
            module._bounded_input_sha256((path,))
        assert mutated
    finally:
        path.write_bytes(original)


def test_csv_readback_rejects_missing_or_extra_columns(tmp_path: Path) -> None:
    module = import_module("secaware.pipeline.stages.reporting")
    spec = module._OutputSpec(tmp_path / "out.csv", "csv", ("left", "right"), 100)

    with pytest.raises(SecAwareError, match="CSV readback"):
        module._validate_output_bytes(spec, b"left\nvalue\n")
    with pytest.raises(SecAwareError, match="CSV readback"):
        module._validate_output_bytes(spec, b"left,right,extra\na,b,c\n")


def test_report_transaction_enforces_total_output_byte_bound(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    before = _report_commit_bytes(store)
    monkeypatch.setattr(module, "_MAX_REPORT_TOTAL_BYTES", 1)

    with pytest.raises(SecAwareError, match="bundle exceeds"):
        module.write_reports(store.config, store, force=True)

    assert _report_commit_bytes(store) == before


def test_report_files_have_canonical_lf_stable_headers_and_sorted_rows(
    published_reports,
) -> None:
    module, store, _result, _before, _after = published_reports
    for spec in module._output_specs(store):
        data = spec.path.read_bytes()
        assert 0 < len(data) <= spec.max_bytes
        assert b"\r" not in data
        assert data.endswith(b"\n")
    pag_rows = _jsonl_dicts(store.path("reports", "discovery_pags.jsonl"))
    pag_order = [(row["run_kind"], row["pag_id"]) for row in pag_rows]
    assert pag_order == sorted(pag_order)
    for relative, key in (
        ("reports/hypotheses.jsonl", "hypothesis_id"),
        ("reports/interventions.jsonl", "variant_id"),
        ("reports/assignments.jsonl", "assignment_id"),
        ("reports/hypothesis_cards.jsonl", "hypothesis_id"),
    ):
        values = [row[key] for row in _jsonl_dicts(store.root / relative)]
        assert values == sorted(values)
    assert _csv_rows(store.path("reports", "effects.csv"))[0] == tuple(module.EFFECT_FIELDS)
    assert _csv_rows(store.path("reports", "jci_orientations.csv"))[0] == tuple(
        module.JCI_ORIENTATION_FIELDS
    )
    assert _csv_rows(store.path("reports", "failures.csv"))[0] == tuple(module.FAILURE_FIELDS)


REPORT_SEMANTIC_MUTATIONS = (
    "duplicate_hypothesis",
    "pag_digest",
    "dangling_assignment_outcome",
    "dangling_effect_contrast",
    "dangling_jci_pag",
    "invalid_failure_stage",
    "invalid_rfci_status",
)


def _mutate_report_documents(module, documents, mutation: str):
    payloads = list(documents.ordered())
    if mutation == "duplicate_hypothesis":
        payloads[1] += payloads[1].splitlines(keepends=True)[0]
    elif mutation == "pag_digest":
        rows = list(_json_bytes_dicts(payloads[0]))
        rows[0]["config_sha256"] = "0" * 64
        payloads[0] = module.canonical_jsonl_bytes(rows)
    elif mutation == "dangling_assignment_outcome":
        rows = list(_json_bytes_dicts(payloads[3]))
        rows[0]["assignment_outcome"]["assignment_id"] = "assignment_" + "0" * 64
        payloads[3] = module.canonical_jsonl_bytes(rows)
    elif mutation == "dangling_effect_contrast":
        fields, rows = _csv_bytes_rows(payloads[4])
        rows[0]["contrast_id"] = "dangling_contrast"
        payloads[4] = module.canonical_csv_bytes(fields, rows)
    elif mutation == "dangling_jci_pag":
        fields, rows = _csv_bytes_rows(payloads[5])
        rows[0]["raw_pag_id"] = "pag_" + "0" * 64
        payloads[5] = module.canonical_csv_bytes(fields, rows)
    elif mutation == "invalid_failure_stage":
        fields, rows = _csv_bytes_rows(payloads[6])
        rows.append(
            {
                "source_stage": "unknown",
                "record_id": "analysis_failure_" + "0" * 64,
                "subject_id": "subject",
                "reason_code": "backend_failure",
                "config_sha256": "0" * 64,
                "input_bundle_sha256": "1" * 64,
                "detail_sha256": "",
            }
        )
        payloads[6] = module.canonical_csv_bytes(fields, rows)
    else:
        payloads[8] = payloads[8].replace(b"RFCI status: disabled", b"RFCI status: impossible")
    return module.ReportDocuments(*payloads)


def _json_bytes_dicts(data: bytes) -> tuple[dict[str, object], ...]:
    return tuple(json.loads(line) for line in data.decode("utf-8").splitlines())


def _csv_bytes_rows(data: bytes) -> tuple[tuple[str, ...], list[dict[str, str]]]:
    reader = csv.DictReader(StringIO(data.decode("utf-8"), newline=""))
    return tuple(reader.fieldnames or ()), list(reader)


@pytest.mark.parametrize("mutation", REPORT_SEMANTIC_MUTATIONS)
def test_candidate_readback_rejects_semantic_provenance_mutation_and_restores_prior_report(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    module, store, _result, _before, _after = published_reports
    before = _report_commit_bytes(store)
    delegate = module._build_documents

    def invalid_documents(snapshot):
        return _mutate_report_documents(module, delegate(snapshot), mutation)

    monkeypatch.setattr(module, "_build_documents", invalid_documents)
    try:
        with pytest.raises(SecAwareError):
            module.write_reports(store.config, store, force=True)
        assert _report_commit_bytes(store) == before
    finally:
        for relative, data in zip(
            (*EXPECTED_REPORT_OUTPUTS, ".stages/report.json"), before, strict=True
        ):
            (store.root / relative).write_bytes(data)


def _capture_snapshot(module, store, monkeypatch: pytest.MonkeyPatch):
    captured = []
    delegate = module._build_documents

    def capture(snapshot):
        captured.append(snapshot)
        return delegate(snapshot)

    monkeypatch.setattr(module, "_build_documents", capture)
    module.write_reports(store.config, store, force=True)
    assert len(captured) == 1
    return captured[0]


def test_snapshot_validation_rejects_misplaced_failures_and_invalid_capability_state(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    snapshot = _capture_snapshot(module, store, monkeypatch)
    misplaced = AnalysisFailureRecord.from_content(
        stage=AnalysisStage.EFFECTS,
        subject_id="subject",
        reason_code=AnalysisFailureReason.INSUFFICIENT_SUPPORT,
        config_sha256="0" * 64,
        input_bundle_sha256="1" * 64,
    )
    with pytest.raises(SecAwareError):
        module._validate_snapshot(replace(snapshot, jci_failures=(misplaced,)))

    inconsistent = snapshot.rfci_capability.model_copy(update={"status": "available"})
    with pytest.raises(SecAwareError):
        module._validate_snapshot(replace(snapshot, rfci_capability=inconsistent))


def test_snapshot_uses_protocol_scoped_contrast_identity(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    snapshot = _capture_snapshot(module, store, monkeypatch)
    assert snapshot.contrasts and snapshot.effects
    effect = snapshot.effects[0]
    matching = next(
        contrast
        for contrast in snapshot.contrasts
        if (contrast.arm_protocol_id, contrast.contrast_id)
        == (effect.arm_protocol_id, effect.contrast_id)
    )
    foreign_protocol_id = "arm_protocol_" + "0" * 64
    assert foreign_protocol_id != matching.arm_protocol_id
    same_id_other_protocol = matching.model_copy(update={"arm_protocol_id": foreign_protocol_id})

    module._validate_snapshot(
        replace(snapshot, contrasts=(*snapshot.contrasts, same_id_other_protocol))
    )

    with pytest.raises(SecAwareError):
        module._validate_snapshot(replace(snapshot, contrasts=(*snapshot.contrasts, matching)))

    without_matching = tuple(
        contrast
        for contrast in snapshot.contrasts
        if (contrast.arm_protocol_id, contrast.contrast_id)
        != (effect.arm_protocol_id, effect.contrast_id)
    )
    with pytest.raises(SecAwareError):
        module._validate_snapshot(
            replace(snapshot, contrasts=(*without_matching, same_id_other_protocol))
        )


@pytest.mark.parametrize(
    ("capability", "rfci_config"),
    (
        (_disabled_capability(), RFCIConfig(enabled=True)),
        (_unavailable_capability(), RFCIConfig(enabled=False)),
        (
            _available_capability().model_copy(update={"jpype_version": "1.7.0"}),
            RFCIConfig(enabled=True),
        ),
    ),
    ids=("enabled-disabled", "disabled-unavailable", "wrong-pinned-provenance"),
)
def test_snapshot_rejects_rfci_capability_not_bound_to_config(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
    capability: RFCICapabilityRecord,
    rfci_config: RFCIConfig,
) -> None:
    module, store, _result, _before, _after = published_reports
    snapshot = _capture_snapshot(module, store, monkeypatch)

    with pytest.raises(SecAwareError):
        module._validate_snapshot(
            replace(snapshot, rfci_capability=capability, rfci_config=rfci_config)
        )


def test_config_mismatched_rfci_capability_hard_fails_before_build_and_rolls_back(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    before = _report_commit_bytes(store)
    delegate_read = module._read
    build_calls: list[object] = []

    def forged_read(path: Path, model: type, *, allow_empty: bool):
        if model is RFCICapabilityRecord:
            return (_unavailable_capability(),)
        return delegate_read(path, model, allow_empty=allow_empty)

    def forbidden_build(snapshot):
        build_calls.append(snapshot)
        pytest.fail("report build continued after RFCI capability mismatch")

    monkeypatch.setattr(module, "_read", forged_read)
    monkeypatch.setattr(module, "_build_documents", forbidden_build)

    with pytest.raises(SecAwareError) as exc_info:
        module.write_reports(store.config, store, force=True)

    assert exc_info.value.stage == "report"
    assert build_calls == []
    assert _report_commit_bytes(store) == before


def test_empty_contrasts_and_all_empty_failure_families_render_stable_headers(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    snapshot = _capture_snapshot(module, store, monkeypatch)
    empty = replace(
        snapshot,
        contrasts=(),
        effects=(),
        bootstrap_failures=(),
        discovery_failures=(),
        exclusions=(),
        effect_failures=(),
        jci_failures=(),
        rfci_failures=(),
    )

    module._validate_snapshot(empty)
    documents = module._render_documents(empty)

    effect_fields, effect_rows = _csv_bytes_rows(documents.effects)
    failure_fields, failure_rows = _csv_bytes_rows(documents.failures)
    assert effect_fields == tuple(module.EFFECT_FIELDS)
    assert failure_fields == tuple(module.FAILURE_FIELDS)
    assert not effect_rows and not failure_rows


def test_rfci_unavailable_without_pag_is_a_valid_report_state(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    snapshot = _capture_snapshot(module, store, monkeypatch)
    unavailable = replace(
        snapshot,
        rfci_capability=_unavailable_capability(),
        rfci_config=RFCIConfig(enabled=True),
        rfci_pags=(),
        rfci_failures=(),
    )

    module._validate_snapshot(unavailable)
    summary = module._render_documents(unavailable).summary.decode("utf-8").casefold()

    assert "rfci status: unavailable" in summary
    assert "jpype_missing" in summary


@pytest.mark.parametrize(
    "capability",
    (_available_capability(), _unavailable_capability(), _disabled_capability()),
    ids=("available", "unavailable", "disabled"),
)
def test_summary_round_trips_full_rfci_capability_provenance(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
    capability: RFCICapabilityRecord,
) -> None:
    module, store, _result, _before, _after = published_reports
    snapshot = _capture_snapshot(module, store, monkeypatch)
    rfci_config = RFCIConfig(enabled=capability.status != "disabled")
    summary = module._render_documents(
        replace(
            snapshot,
            rfci_capability=capability,
            rfci_config=rfci_config,
            rfci_pags=(),
        )
    ).summary
    expected_json = json.dumps(
        capability.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    capability_line = next(
        (
            line
            for line in summary.decode("utf-8").splitlines()
            if line.startswith("- RFCI capability record: ")
        ),
        None,
    )

    assert capability_line is not None
    assert capability_line.startswith("- RFCI capability record: `")
    assert capability_line.endswith("`")
    assert capability_line != f"- RFCI capability record: {expected_json}"
    assert module._read_summary_capability(summary) == capability


def test_summary_escapes_untrusted_rfci_reason_without_losing_readback(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    snapshot = _capture_snapshot(module, store, monkeypatch)
    reason = "<script>alert(1)</script>\n[docs](javascript:alert(2)) `code`"
    capability = _unavailable_capability().model_copy(update={"reason_code": reason})
    summary_bytes = module._render_documents(
        replace(
            snapshot,
            rfci_config=RFCIConfig(enabled=True),
            rfci_capability=capability,
            rfci_pags=(),
        )
    ).summary
    summary = summary_bytes.decode("utf-8")

    assert "<script>" not in summary
    assert "\n[docs](" not in summary
    assert "`code`" not in summary
    assert "&lt;script&gt;" in summary
    assert module._read_summary_capability(summary_bytes) == capability


def test_target_and_semantic_diagnostics_are_displayed_without_filtering_itt_effects(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    snapshot = _capture_snapshot(module, store, monkeypatch)
    changed_outcomes = []
    for outcome in snapshot.outcomes:
        payload = outcome.model_dump(mode="python", exclude={"outcome_id"})
        payload["target_changed"] = False
        payload["semantic_compliance"] = False
        changed_outcomes.append(AssignmentOutcomeRecord.from_content(**payload))
    diagnostics_only = replace(snapshot, outcomes=tuple(changed_outcomes))

    module._validate_snapshot(diagnostics_only)
    original = module._render_documents(snapshot)
    rendered = module._render_documents(diagnostics_only)
    assignments = _json_bytes_dicts(rendered.assignments)

    assert rendered.effects == original.effects
    assert len(assignments) == len(snapshot.assignments)
    assert all(row["assignment_outcome"]["target_changed"] is False for row in assignments)
    assert all(row["assignment_outcome"]["semantic_compliance"] is False for row in assignments)


def test_cards_preserve_endpoint_marks_without_adding_a_causal_claim(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    snapshot = _capture_snapshot(module, store, monkeypatch)
    cards = _json_bytes_dicts(module._render_documents(snapshot).hypothesis_cards)
    hypotheses = {item.hypothesis_id: item for item in snapshot.hypotheses}

    for card in cards:
        source = hypotheses[card["hypothesis_id"]]
        assert card["hypothesis_path"] == source.path.model_dump(mode="json")
        rendered = json.dumps(card, ensure_ascii=False, sort_keys=True).casefold()
        assert "directed cause" not in rendered
        assert "code mechanism" not in rendered
        assert "mediator" not in rendered
        assert "source-to-sink" not in rendered
        assert "pair" not in rendered


def test_concurrent_report_writer_fails_without_disturbing_active_commit(
    published_reports,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, store, _result, _before, _after = published_reports
    before = _report_commit_bytes(store)
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    delegate = module._build_documents

    def blocking_build(snapshot):
        entered.set()
        if not release.wait(timeout=15):
            raise TimeoutError("private")
        return delegate(snapshot)

    def publish() -> None:
        try:
            module.write_reports(store.config, store, force=True)
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(module, "_build_documents", blocking_build)
    worker = threading.Thread(target=publish, daemon=True)
    worker.start()
    assert entered.wait(timeout=15)
    competing = RunStore(store.config)
    try:
        with pytest.raises(SecAwareError):
            module.write_reports(store.config, competing, force=True)
    finally:
        release.set()
        worker.join(timeout=20)

    assert not worker.is_alive()
    assert not errors
    assert _report_commit_bytes(store) == before
