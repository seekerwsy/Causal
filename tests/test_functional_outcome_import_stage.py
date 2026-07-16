from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import shutil
import threading
from pathlib import Path

import pytest

from m5_executor_fixtures import request
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.io.transaction import (
    ArtifactTransaction,
    TransactionArtifact,
    recover_transaction,
)
from secaware.pipeline.artifact import sha256_path
from secaware.pipeline.bounded_traversal import BoundedTreeEntry
from secaware.pipeline.manifest import read_stage_manifest
from secaware.pipeline.stages.functional_outcomes import import_functional_outcomes_stage
import secaware.pipeline.stages.functional_outcomes as functional_stage
from secaware.pipeline.stages.prompt_variants import (
    PROMPT_VARIANT_OUTPUTS,
    prompt_variant_stage_policy_sha256,
)
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.pipeline.stage_contracts import functional_outcome_import_stage_contract_payload
from secaware.schema.experiments import (
    ConfirmationProtocolRecord,
    FeatureFamily,
    RandomizationManifestRecord,
)
from secaware.schema.outcomes import (
    FunctionalOutcomeRecord,
    FunctionalOutcomeStatus,
)
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256

from test_functional_outcome_contract import (
    _functional_case,
    _functional_outcome,
)


def _assignment_digest(assignments: tuple[object, ...]) -> str:
    return hashlib.sha256(
        json.dumps(
            [item.model_dump(mode="json") for item in assignments],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _commit_outputs(
    store: RunStore,
    stage: str,
    outputs: tuple[tuple[Path, tuple[object, ...]], ...],
) -> None:
    paths = tuple(path for path, _records in outputs)
    policy_sha256 = (
        prompt_variant_stage_policy_sha256(store.config)
        if stage == "build-confirmation-variants"
        else None
    )
    catalog_sha256 = (
        PROMPT_FEATURE_CATALOG_SHA256 if stage == "build-confirmation-variants" else None
    )
    assert not store.should_skip_stage(
        stage,
        (),
        paths,
        False,
        policy_sha256=policy_sha256,
        catalog_sha256=catalog_sha256,
    )
    for path, records in outputs:
        write_jsonl(path, records)
    store.seal_stage_outputs(stage, paths)
    store.record_stage(
        stage,
        (),
        paths,
        policy_sha256=policy_sha256,
        catalog_sha256=catalog_sha256,
    )


def _stage_case(tmp_path: Path):
    assignment, protocol, contract, outcome = _functional_case()
    safety_protocol = request(FeatureFamily.SAFETY_CONTROL).protocol
    prompts = tmp_path / "prompts.jsonl"
    attestations = tmp_path / "attestations.jsonl"
    contracts = tmp_path / "functional_contracts.jsonl"
    results = tmp_path / "external_functional_results.jsonl"
    write_jsonl(prompts, ({"placeholder": True},))
    write_jsonl(attestations, ({"placeholder": True},))
    write_jsonl(contracts, (contract,))
    write_jsonl(results, (outcome,))
    config = AppConfig.model_validate(
        {
            "run": {
                "name": "functional-import",
                "random_seed": 7,
                "output_dir": str(tmp_path / "run"),
            },
            "data": {
                "prompts_path": str(prompts),
                "prompt_attestations_path": str(attestations),
                "functional_outcome_contracts_path": str(contracts),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1", "llm": None},
            "intervention": {"executor": "deterministic"},
        }
    )
    store = RunStore(config)
    store.prepare()
    task4_paths = tuple(
        store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    _commit_outputs(
        store,
        "build-confirmation-variants",
        tuple(
            (
                path,
                tuple(sorted((protocol, safety_protocol), key=lambda item: item.arm_protocol_id))
                if name == "confirmation_protocols.jsonl"
                else (),
            )
            for path, (name, _model) in zip(task4_paths, PROMPT_VARIANT_OUTPUTS, strict=True)
        ),
    )
    manifest = RandomizationManifestRecord.from_content(
        global_seed=config.run.random_seed,
        rng_version="sha256-rejection-fisher-yates-v1",
        randomization_plan_sha256=assignment.randomization_plan_sha256,
        block_ids=(assignment.block_id,),
        assignment_ids=(assignment.assignment_id,),
        assignments_sha256=_assignment_digest((assignment,)),
    )
    task5_paths = tuple(store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS)
    _commit_outputs(
        store,
        "randomize-confirmation",
        tuple(
            (
                path,
                (manifest,) if name == "randomization_manifest.jsonl" else (assignment,),
            )
            for path, (name, _model) in zip(task5_paths, RANDOMIZATION_OUTPUTS, strict=True)
        ),
    )
    return config, store, results, assignment, protocol, contract, outcome


def _bytes(store: RunStore) -> tuple[bytes, bytes]:
    return (
        store.path("analysis", "functional_outcomes.jsonl").read_bytes(),
        store.path(".stages", "import-functional-outcomes.json").read_bytes(),
    )


def _remove_committed_safety_protocol(store: RunStore) -> None:
    protocol_path = store.path("interventions", "confirmation_protocols.jsonl")
    protocols = read_jsonl(
        protocol_path,
        ConfirmationProtocolRecord,
        required=True,
        allow_empty=False,
    )
    task_protocols = tuple(
        item for item in protocols if item.feature_family is FeatureFamily.TASK_FUNCTION
    )
    assert len(task_protocols) == 1
    assert len(protocols) > len(task_protocols)
    write_jsonl(protocol_path, task_protocols)


def test_import_stage_transactionally_publishes_exact_sorted_external_results(
    tmp_path: Path,
) -> None:
    config, store, results, assignment, _protocol, _contract, outcome = _stage_case(tmp_path)

    result = import_functional_outcomes_stage(config, store, results)

    imported = read_jsonl(
        store.path("analysis", "functional_outcomes.jsonl"),
        FunctionalOutcomeRecord,
        required=True,
        allow_empty=False,
    )
    assert imported == [outcome]
    assert result.assignment_count == result.outcome_count == 1
    assert result.assignment_count == len({assignment.assignment_id})
    manifest = read_stage_manifest(store.path(".stages", "import-functional-outcomes.json"))
    assert manifest.outputs == ["analysis/functional_outcomes.jsonl"]
    assert sha256_path(results) in manifest.inputs.values()
    assert (
        sha256_path(Path(config.data.functional_outcome_contracts_path)) in manifest.inputs.values()
    )
    assert sum(key.startswith("@external/") for key in manifest.inputs) == 2


def test_import_stage_contract_fingerprint_binds_declared_downstream_order_and_families() -> None:
    payload = functional_outcome_import_stage_contract_payload()

    assert payload["confirmation_stage_order"][4:] == [
        "import-functional-outcomes",
        "assemble-assignment-outcomes",
        "estimate-confirmation-effects",
        "jci-confirmation",
        "rfci-confirmation",
        "reporting",
    ]
    downstream_families = payload["confirmation_stage_manifest_families"][5:]
    assert "confirm" in downstream_families[0]
    assert "effects" in downstream_families[1]
    assert payload["stage_version_affix_pattern"]


@pytest.mark.parametrize("mutation", ("missing", "duplicate", "extra", "contract", "policy"))
def test_import_stage_requires_exact_contract_and_assignment_coverage(
    tmp_path: Path, mutation: str
) -> None:
    config, store, results, assignment, _protocol, contract, outcome = _stage_case(tmp_path)
    records: tuple[FunctionalOutcomeRecord, ...] = (outcome,)
    if mutation == "missing":
        records = ()
    elif mutation == "duplicate":
        records = (outcome, outcome)
    elif mutation == "extra":
        records = (
            outcome,
            FunctionalOutcomeRecord.from_content(
                assignment_id="assignment_" + "f" * 64,
                contract_id=contract.contract_id,
                evaluator_policy_sha256=contract.evaluator_policy_sha256,
                status=FunctionalOutcomeStatus.UNKNOWN,
                evidence_sha256="f" * 64,
            ),
        )
    elif mutation == "contract":
        records = (
            FunctionalOutcomeRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id="functional_contract_" + "f" * 64,
                evaluator_policy_sha256=contract.evaluator_policy_sha256,
                status=outcome.status,
                evidence_sha256=outcome.evidence_sha256,
            ),
        )
    else:
        records = (
            FunctionalOutcomeRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id=contract.contract_id,
                evaluator_policy_sha256="f" * 64,
                status=outcome.status,
                evidence_sha256=outcome.evidence_sha256,
            ),
        )
    write_jsonl(results, records)

    with pytest.raises(SecAwareError):
        import_functional_outcomes_stage(config, store, results)
    assert not store.path("analysis", "functional_outcomes.jsonl").exists()


@pytest.mark.parametrize("kind", ("missing", "directory", "corrupt", "symlink"))
def test_import_stage_rejects_invalid_external_result_paths(tmp_path: Path, kind: str) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    path = results
    if kind == "missing":
        results.unlink()
    elif kind == "directory":
        results.unlink()
        results.mkdir()
    elif kind == "corrupt":
        results.write_text('{"raw_secret":"unterminated"\n', encoding="utf-8")
    else:
        target = tmp_path / "real-results.jsonl"
        shutil.copyfile(results, target)
        results.unlink()
        try:
            results.symlink_to(target)
        except OSError:
            pytest.skip("symlinks unavailable")

    with pytest.raises(SecAwareError) as captured:
        import_functional_outcomes_stage(config, store, path)
    assert captured.value.code in {ErrorCode.CONTRACT, ErrorCode.MANIFEST_CONFLICT}


def test_import_stage_rejects_lexical_parent_traversal_without_path_leak(tmp_path: Path) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    secret_component = "lexical-secret-component"
    (results.parent / secret_component).mkdir()
    traversing_path = results.parent / secret_component / ".." / results.name

    with pytest.raises(SecAwareError) as captured:
        import_functional_outcomes_stage(config, store, traversing_path)

    assert captured.value.code is ErrorCode.CONTRACT
    assert secret_component not in str(captured.value)
    cursor = captured.value.__traceback__
    while cursor is not None:
        if "/src/secaware/" in cursor.tb_frame.f_code.co_filename.replace("\\", "/"):
            assert secret_component not in repr(dict(cursor.tb_frame.f_locals))
        cursor = cursor.tb_next
    assert not store.path("analysis", "functional_outcomes.jsonl").exists()


def test_import_stage_does_not_derive_functional_results_from_prompts_or_oracle(
    tmp_path: Path,
) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    write_jsonl(results, ())
    store.path("oracle", "confirmation_oracle.jsonl").write_text(
        '{"security_label":"secure","functional_ok":true}\n', encoding="utf-8"
    )

    with pytest.raises(SecAwareError):
        import_functional_outcomes_stage(config, store, results)


def test_external_result_toctou_aborts_before_commit(tmp_path: Path, monkeypatch) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    real_validate = functional_stage.validate_functional_outcomes
    calls = 0

    def mutate_after_validation(*args, **kwargs):
        nonlocal calls
        value = real_validate(*args, **kwargs)
        calls += 1
        if calls == 1:
            results.write_bytes(results.read_bytes() + b"\n")
        return value

    monkeypatch.setattr(functional_stage, "validate_functional_outcomes", mutate_after_validation)
    with pytest.raises(SecAwareError):
        import_functional_outcomes_stage(config, store, results)
    assert not store.path("analysis", "functional_outcomes.jsonl").exists()


def test_force_failure_rolls_back_and_preserves_old_commit(tmp_path: Path) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    before = _bytes(store)
    results.write_text("not-json\n", encoding="utf-8")

    with pytest.raises(SecAwareError):
        import_functional_outcomes_stage(config, store, results, force=True)

    assert _bytes(store) == before


def test_legal_force_atomically_replaces_committed_functional_outcome(tmp_path: Path) -> None:
    config, store, results, assignment, _protocol, contract, _outcome = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    before = _bytes(store)
    replacement = _functional_outcome(
        assignment_id=assignment.assignment_id,
        contract_id=contract.contract_id,
        evaluator_policy_sha256=contract.evaluator_policy_sha256,
        status=FunctionalOutcomeStatus.FAIL,
        evidence_sha256="d" * 64,
    )
    write_jsonl(results, (replacement,))

    result = import_functional_outcomes_stage(config, store, results, force=True)

    assert result.outcome_count == 1
    assert read_jsonl(
        store.path("analysis", "functional_outcomes.jsonl"),
        FunctionalOutcomeRecord,
        required=True,
        allow_empty=False,
    ) == [replacement]
    assert _bytes(store) != before


def test_force_rejects_transaction_backup_that_does_not_match_journal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, store, results, assignment, _protocol, contract, _outcome = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    before = _bytes(store)
    replacement = _functional_outcome(
        assignment_id=assignment.assignment_id,
        contract_id=contract.contract_id,
        evaluator_policy_sha256=contract.evaluator_policy_sha256,
        status=FunctionalOutcomeStatus.FAIL,
        evidence_sha256="e" * 64,
    )
    write_jsonl(results, (replacement,))
    real_guard = functional_stage._guard_no_future_artifacts
    guard_calls = 0

    def mismatch_backup_journal_on_precommit(run_store: RunStore) -> None:
        nonlocal guard_calls
        guard_calls += 1
        if guard_calls == 2:
            journal_path = run_store.path(".stages", ".import-functional-outcomes.transaction.json")
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            artifact = journal["artifacts"][0]
            assert artifact["old_exists"] is True
            original_sha256 = artifact["old_sha256"]
            artifact["old_sha256"] = "0" * 64 if original_sha256 != "0" * 64 else "1" * 64
            backup = run_store.path(
                "analysis",
                f".functional_outcomes.jsonl.{journal['token']}.output0.recovery.backup",
            )
            assert sha256_path(backup) == original_sha256
            assert sha256_path(backup) != artifact["old_sha256"]
            journal_path.write_text(
                json.dumps(journal, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="utf-8",
            )
        real_guard(run_store)

    monkeypatch.setattr(
        functional_stage,
        "_guard_no_future_artifacts",
        mismatch_backup_journal_on_precommit,
    )

    with pytest.raises(SecAwareError) as captured:
        import_functional_outcomes_stage(config, store, results, force=True)

    assert guard_calls == 2
    assert captured.value.code is ErrorCode.CONTRACT
    assert captured.value.stage == "import-functional-outcomes"
    assert _bytes(store) == before


def test_future_analysis_artifact_blocks_import_and_preserves_commit(tmp_path: Path) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    before = _bytes(store)
    store.path("reports", "future-report.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as captured:
        import_functional_outcomes_stage(config, store, results, force=True)
    assert captured.value.code is ErrorCode.CONTRACT
    assert captured.value.stage == "import-functional-outcomes"
    assert (
        captured.value.message == "future analysis artifact exists before functional outcome import"
    )
    assert _bytes(store) == before


def test_manifest_only_future_outcome_stage_blocks_import_and_preserves_commit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    before = _bytes(store)
    store.path(".stages", "assemble-assignment-outcomes.json").write_text("{}\n", encoding="utf-8")
    real_guard = functional_stage._guard_no_future_artifacts

    def controlled_guard(run_store: RunStore) -> None:
        def future_manifest_only(*_args, **_kwargs):
            yield BoundedTreeEntry(
                relative_path=".stages/assemble-assignment-outcomes.json",
                name="assemble-assignment-outcomes.json",
                is_file=True,
                is_dir=False,
            )

        real_guard(
            run_store,
            traversal=future_manifest_only,
        )

    monkeypatch.setattr(functional_stage, "_guard_no_future_artifacts", controlled_guard)

    with pytest.raises(SecAwareError) as captured:
        import_functional_outcomes_stage(config, store, results, force=True)
    assert captured.value.code is ErrorCode.CONTRACT
    assert captured.value.stage == "import-functional-outcomes"
    assert (
        captured.value.message == "future analysis artifact exists before functional outcome import"
    )
    assert _bytes(store) == before


@pytest.mark.parametrize(
    "manifest_name",
    (
        "effects.json",
        "v2-confirm.json",
        "estimate-confirmation-effects-v2.json",
        "jci-confirmation-v3.json",
        "rfci-analysis-2026.json",
        "reporting-v2.json",
    ),
)
def test_any_downstream_stage_manifest_variant_blocks_import_and_preserves_commit(
    tmp_path: Path,
    monkeypatch,
    manifest_name: str,
) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    before = _bytes(store)
    store.path(".stages", manifest_name).write_text("{}\n", encoding="utf-8")
    real_guard = functional_stage._guard_no_future_artifacts

    def controlled_guard(run_store: RunStore) -> None:
        def future_manifest_only(*_args, **_kwargs):
            yield BoundedTreeEntry(
                relative_path=f".stages/{manifest_name}",
                name=manifest_name,
                is_file=True,
                is_dir=False,
            )

        real_guard(run_store, traversal=future_manifest_only)

    monkeypatch.setattr(functional_stage, "_guard_no_future_artifacts", controlled_guard)

    with pytest.raises(SecAwareError) as captured:
        import_functional_outcomes_stage(config, store, results, force=True)
    assert captured.value.code is ErrorCode.CONTRACT
    assert captured.value.stage == "import-functional-outcomes"
    assert _bytes(store) == before


def test_future_guard_allows_only_backups_owned_by_active_transaction(tmp_path: Path) -> None:
    config, store, results, *_rest = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    output = store.path("analysis", "functional_outcomes.jsonl")
    manifest = store.path(".stages", "import-functional-outcomes.json")
    transaction = ArtifactTransaction.begin(
        store.path(".stages", ".import-functional-outcomes.transaction.json"),
        (
            TransactionArtifact(output, "output0"),
            TransactionArtifact(manifest, "manifest"),
        ),
    )
    transaction.backup(0)
    transaction.backup(1)
    try:
        functional_stage._guard_no_future_artifacts(store)
    finally:
        recover_transaction(transaction)


@pytest.mark.parametrize("mutation", ("content", "type"))
def test_future_guard_rejects_transaction_backup_entity_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    config, store, results, *_rest = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    before = _bytes(store)
    output = store.path("analysis", "functional_outcomes.jsonl")
    manifest = store.path(".stages", "import-functional-outcomes.json")
    transaction = ArtifactTransaction.begin(
        store.path(".stages", ".import-functional-outcomes.transaction.json"),
        (
            TransactionArtifact(output, "output0"),
            TransactionArtifact(manifest, "manifest"),
        ),
    )
    transaction.backup(0)
    transaction.backup(1)
    backup = output.with_name(f".{output.name}.{transaction.journal.token}.output0.recovery.backup")
    backup_bytes = backup.read_bytes()
    if mutation == "content":
        backup.write_bytes(backup_bytes + b"\n")
    else:
        backup.unlink()
        backup.mkdir()
    try:
        with pytest.raises(SecAwareError) as captured:
            functional_stage._guard_no_future_artifacts(store)
        assert captured.value.code is ErrorCode.CONTRACT
        assert captured.value.stage == "import-functional-outcomes"
    finally:
        if backup.is_dir():
            backup.rmdir()
        backup.write_bytes(backup_bytes)
        recover_transaction(transaction)
    assert _bytes(store) == before


def test_randomization_manifest_and_assignment_index_are_revalidated(tmp_path: Path) -> None:
    config, store, results, assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    manifest_path = store.path("interventions", "randomization_manifest.jsonl")
    manifest = read_jsonl(
        manifest_path, RandomizationManifestRecord, required=True, allow_empty=False
    )[0]
    forged = RandomizationManifestRecord.from_content(
        global_seed=manifest.global_seed,
        rng_version=manifest.rng_version,
        randomization_plan_sha256=manifest.randomization_plan_sha256,
        block_ids=manifest.block_ids,
        assignment_ids=(assignment.assignment_id,),
        assignments_sha256="f" * 64,
    )
    write_jsonl(manifest_path, (forged,))
    # Re-sealing the producer manifest cannot make a false assignment digest valid.
    producer_manifest = read_stage_manifest(store.path(".stages", "randomize-confirmation.json"))
    producer_manifest.output_sha256["interventions/randomization_manifest.jsonl"] = sha256_path(
        manifest_path
    )
    from secaware.pipeline.manifest import write_stage_manifest

    write_stage_manifest(store.path(".stages", "randomize-confirmation.json"), producer_manifest)

    with pytest.raises(SecAwareError):
        import_functional_outcomes_stage(config, store, results)


def test_producer_universe_mutation_after_hold_before_capture_is_rejected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    before = _bytes(store)
    real_hold = RunStore.hold_committed_output
    mutated = False

    @contextmanager
    def mutate_after_hold(
        current: RunStore,
        stage: str,
        output_paths,
        *,
        expected_catalog_sha256: str | None = None,
    ):
        nonlocal mutated
        with real_hold(
            current,
            stage,
            output_paths,
            expected_catalog_sha256=expected_catalog_sha256,
        ) as hashes:
            if current is store and stage == "randomize-confirmation" and not mutated:
                _remove_committed_safety_protocol(store)
                mutated = True
            yield hashes

    monkeypatch.setattr(RunStore, "hold_committed_output", mutate_after_hold)
    monkeypatch.setattr(functional_stage, "_guard_no_future_artifacts", lambda _store: None)

    with pytest.raises(SecAwareError):
        import_functional_outcomes_stage(config, store, results, force=True)

    assert mutated
    assert _bytes(store) == before


def test_producer_universe_mutation_after_capture_before_commit_preserves_old_commit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    import_functional_outcomes_stage(config, store, results)
    before = _bytes(store)
    real_validate = functional_stage.validate_functional_outcomes
    mutated = False

    def mutate_after_capture(*args, **kwargs):
        nonlocal mutated
        value = real_validate(*args, **kwargs)
        if not mutated:
            _remove_committed_safety_protocol(store)
            mutated = True
        return value

    monkeypatch.setattr(functional_stage, "validate_functional_outcomes", mutate_after_capture)
    monkeypatch.setattr(functional_stage, "_guard_no_future_artifacts", lambda _store: None)

    with pytest.raises(SecAwareError):
        import_functional_outcomes_stage(config, store, results, force=True)

    assert mutated
    assert _bytes(store) == before


def test_import_stage_holds_both_m5_producer_leases(tmp_path: Path, monkeypatch) -> None:
    config, owner, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    contender = RunStore(config)
    entered = threading.Event()
    release = threading.Event()
    real_validate = functional_stage.validate_functional_outcomes

    def block(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=15)
        return real_validate(*args, **kwargs)

    monkeypatch.setattr(functional_stage, "validate_functional_outcomes", block)
    errors: list[BaseException] = []

    def consume() -> None:
        try:
            import_functional_outcomes_stage(config, owner, results)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=consume)
    thread.start()
    assert entered.wait(timeout=15)
    try:
        for producer in ("build-confirmation-variants", "randomize-confirmation"):
            with pytest.raises(SecAwareError) as captured:
                contender.invalidate_stage(producer)
            assert captured.value.code is ErrorCode.MANIFEST_CONFLICT
    finally:
        release.set()
        thread.join(timeout=30)
    assert not thread.is_alive()
    assert errors == []


def test_corrupt_external_payload_is_not_retained_in_stage_frames(tmp_path: Path) -> None:
    config, store, results, _assignment, _protocol, _contract, _outcome = _stage_case(tmp_path)
    secret = "external-functional-raw-secret"
    results.write_text('{"evidence":"' + secret + '"}\n', encoding="utf-8")

    with pytest.raises(SecAwareError) as captured:
        import_functional_outcomes_stage(config, store, results)

    assert secret not in str(captured.value)
    cursor = captured.value.__traceback__
    while cursor is not None:
        if "/src/secaware/" in cursor.tb_frame.f_code.co_filename.replace("\\", "/"):
            assert secret not in repr(dict(cursor.tb_frame.f_locals))
        cursor = cursor.tb_next
