import json
import multiprocessing
import os
from pathlib import Path
import threading
import traceback
from dataclasses import replace

import pytest

from secaware import __version__
import secaware.cli as pipeline_cli
from secaware.cli import generate_observed_stage
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io import run_store as run_store_module
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore, StageCommitLease
from secaware.pipeline.artifact import canonical_sha256, sha256_file, sha256_path
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.records import GeneratedCodeRecord, PromptRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_cli_does_not_define_jsonl_stage_transaction_runner() -> None:
    assert not hasattr(pipeline_cli, "_execute_jsonl_stage_transaction")


def test_recovery_callback_authorizes_transaction_mode_for_a_new_stage(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    recovered = False

    def recover() -> None:
        nonlocal recovered
        recovered = True

    assert (
        store.should_skip_stage(
            "transaction-test",
            [input_path],
            [output_path],
            force=True,
            preserve_committed=True,
            after_lease_acquired=recover,
        )
        is False
    )
    assert recovered is True
    store.abort_stage("transaction-test")


def test_new_stage_cannot_enable_transaction_mode_without_a_recovery_callback(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)

    with pytest.raises(SecAwareError) as exc_info:
        store.should_skip_stage(
            "transaction-test",
            [input_path],
            [output_path],
            force=True,
            preserve_committed=True,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def _assert_manifest_error_is_safe(error: SecAwareError, *hidden: str) -> None:
    surfaces = (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.to_dict(), sort_keys=True),
    )
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.details == {}
    for value in hidden:
        assert all(value not in surface for surface in surfaces)


def _store(tmp_path: Path, *, bootstrap_samples: int = 200) -> RunStore:
    config = AppConfig.model_validate(
        {
            "run": {"name": "stage-test", "output_dir": str(tmp_path / "run")},
            "data": {
                "prompts_path": str(tmp_path / "source-prompts.jsonl"),
                "prompt_attestations_path": str(tmp_path / "attestations.jsonl"),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "analysis": {"bootstrap_samples": bootstrap_samples},
        }
    )
    store = RunStore(config)
    store.mkdirs()
    return store


def _input_and_output(store: RunStore) -> tuple[Path, Path]:
    input_path = store.path("inputs", "source.txt")
    output_path = store.path("reports", "result.txt")
    input_path.write_text("input-v1\n", encoding="utf-8")
    output_path.write_text("output-v1\n", encoding="utf-8")
    return input_path, output_path


def _begin_deferred_stage_commit(
    store: RunStore,
    stage: str,
    input_path: Path,
    output_path: Path,
) -> StageCommitLease:
    assert (
        store.should_skip_stage(
            stage,
            [input_path],
            [output_path],
            force=True,
            preserve_committed=True,
        )
        is False
    )
    store.seal_stage_outputs(stage, [output_path])
    return store.begin_stage_commit(stage)


def _record_report_stage(store: RunStore, input_path: Path, outputs: list[Path]) -> Path:
    assert store.should_skip_stage("report", [input_path], outputs, force=False) is False
    store.record_stage("report", [input_path], outputs)
    manifest_path = store.path(".stages", "report.json")
    assert manifest_path.is_file()
    return manifest_path


def _hold_stage_lease_until_process_exit(
    config_payload: dict[str, object],
    input_path: str,
    output_path: str,
    ready: object,
    release: object,
) -> None:
    store = RunStore(AppConfig.model_validate(config_payload))
    decision = store.should_skip_stage(
        "report",
        [Path(input_path)],
        [Path(output_path)],
        force=False,
    )
    ready.send(decision)  # type: ignore[attr-defined]
    release.wait(timeout=10)  # type: ignore[attr-defined]


def _probe_held_committed_stage_from_process(
    config_payload: dict[str, object],
    input_path: str,
    output_path: str,
    sender: object,
) -> None:
    store = RunStore(AppConfig.model_validate(config_payload))
    source = Path(input_path)
    output = Path(output_path)
    outcomes: list[int | str] = []
    for operation in (
        lambda: store.should_skip_stage("report", [source], [output], force=True),
        lambda: store.invalidate_stage("report"),
        lambda: store.require_committed_stage("report", [source], [output]),
    ):
        try:
            operation()
        except SecAwareError as error:
            outcomes.append(int(error.code))
        except BaseException as error:
            outcomes.append(type(error).__name__)
        else:
            outcomes.append("success")
    sender.send(outcomes)  # type: ignore[attr-defined]
    sender.close()  # type: ignore[attr-defined]


def _file_provider_store(tmp_path: Path, provider_dir: Path) -> tuple[AppConfig, RunStore]:
    prompts_path = tmp_path / "source-prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            PromptRecord(
                prompt_id="prompt-1",
                task_id="task-prompt-1",
                split="discover",
                language="python",
                task_family="path_handling",
                cwe="CWE-22",
                prompt="write a helper",
                prompt_role="neutral_baseline",
                counterpart_prompt_id=None,
            )
        ],
    )
    config = AppConfig.model_validate(
        {
            "run": {"name": "file-provider", "output_dir": str(tmp_path / "run")},
            "data": {
                "prompts_path": str(prompts_path),
                "prompt_attestations_path": str(tmp_path / "attestations.jsonl"),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "generation": {
                "provider": "file",
                "models": ["model-a"],
                "seeds": [7],
                "file_provider_dir": str(provider_dir),
            },
        }
    )
    store = RunStore(config)
    store.prepare()
    return config, store


def test_mkdirs_creates_private_stage_manifest_directory(tmp_path: Path) -> None:
    store = _store(tmp_path)

    assert store.path(".stages").is_dir()


@pytest.mark.parametrize("failure", ["copy", "write_config"])
def test_prepare_wraps_expected_filesystem_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    store = _store(tmp_path)
    prompts_path = Path(store.config.data.prompts_path)
    prompts_path.write_text("source\n", encoding="utf-8")

    def fail_with_private_error(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("top-secret filesystem detail")

    if failure == "copy":
        monkeypatch.setattr(run_store_module.shutil, "copyfile", fail_with_private_error)
    else:
        monkeypatch.setattr(run_store_module, "write_resolved_config", fail_with_private_error)

    with pytest.raises(SecAwareError) as exc_info:
        store.prepare()

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.stage == "prepare"
    assert set(exc_info.value.details) == {"path"}
    assert "top-secret" not in str(exc_info.value)


def test_stage_is_skippable_only_after_matching_manifest_is_recorded(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    store.record_stage("report", [input_path], [output_path])

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is True
    manifest_path = store.path(".stages", "report.json")
    assert manifest_path.is_file()
    manifest = read_stage_manifest(manifest_path)
    assert manifest.schema_version == "1.0"
    assert manifest.stage == "report"
    assert manifest.inputs == {"inputs/source.txt": sha256_file(input_path)}
    assert manifest.outputs == ["reports/result.txt"]
    assert manifest.output_sha256 == {"reports/result.txt": sha256_path(output_path)}
    assert manifest.config_sha256 == canonical_sha256(store.config.model_dump(mode="json"))
    assert manifest.code_version == __version__
    assert manifest.fingerprint == store.stage_fingerprint("report", [input_path])


def test_committed_stage_and_output_gates_accept_a_valid_manifest(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])
    before = manifest_path.read_bytes()

    store.require_committed_stage("report", [input_path], [output_path])
    store.require_committed_output("report", [output_path])

    assert manifest_path.read_bytes() == before


def test_committed_gates_return_defensive_output_hash_copies(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    _record_report_stage(store, input_path, [output_path])
    expected = {"reports/result.txt": sha256_path(output_path)}

    stage_hashes = store.require_committed_stage("report", [input_path], [output_path])
    output_hashes = store.require_committed_output("report", [output_path])
    stage_hashes["reports/result.txt"] = "0" * 64
    output_hashes.clear()

    assert store.require_committed_stage("report", [input_path], [output_path]) == expected
    assert store.require_committed_output("report", [output_path]) == expected


def test_held_committed_stage_blocks_mutation_and_allows_holder_revalidation(
    tmp_path: Path,
) -> None:
    holder = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(holder)
    manifest_path = _record_report_stage(holder, input_path, [output_path])
    manifest_bytes = manifest_path.read_bytes()
    expected = {"reports/result.txt": sha256_path(output_path)}

    with holder.hold_committed_stage("report", [input_path], [output_path]) as hashes:
        hashes["reports/result.txt"] = "0" * 64
        assert holder.require_committed_stage("report", [input_path], [output_path]) == expected
        for operation in (
            lambda: holder.should_skip_stage("report", [input_path], [output_path], force=True),
            lambda: holder.invalidate_stage("report"),
            lambda: holder.abort_stage("report"),
            lambda: contender.should_skip_stage("report", [input_path], [output_path], force=True),
            lambda: contender.invalidate_stage("report"),
            lambda: contender.require_committed_stage("report", [input_path], [output_path]),
        ):
            with pytest.raises(SecAwareError) as exc_info:
                operation()
            assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
        assert manifest_path.read_bytes() == manifest_bytes

    assert contender.require_committed_stage("report", [input_path], [output_path]) == expected
    assert manifest_path.read_bytes() == manifest_bytes


@pytest.mark.parametrize(
    "stages",
    [(), ("",), ("   ",), ("report", "report")],
)
def test_multi_stage_dependency_lease_rejects_invalid_stage_sets(
    tmp_path: Path,
    stages: tuple[str, ...],
) -> None:
    store = _store(tmp_path)

    with pytest.raises(SecAwareError) as exc_info:
        with store.hold_dependency_stages(stages):
            pytest.fail("invalid dependency stage set must not acquire leases")

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_multi_stage_dependency_lease_rejects_same_store_reentry(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)

    with store.hold_dependency_stages(("z-stage", "a-stage")) as ordered:
        assert ordered == ("a-stage", "z-stage")
        with pytest.raises(SecAwareError) as exc_info:
            with store.hold_dependency_stages(("a-stage",)):
                pytest.fail("same-store lease reentry must be rejected")

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


@pytest.mark.parametrize("signal_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_multi_stage_dependency_lease_releases_every_stage_on_exception(
    tmp_path: Path,
    signal_type: type[BaseException],
) -> None:
    owner = _store(tmp_path)
    contender = _store(tmp_path)
    signal = signal_type("private-multi-stage-control-flow")

    with pytest.raises(signal_type) as exc_info:
        with owner.hold_dependency_stages(("z-stage", "a-stage")):
            raise signal

    assert exc_info.value is signal
    with contender.hold_dependency_stages(("a-stage", "z-stage")) as ordered:
        assert ordered == ("a-stage", "z-stage")


def test_multi_stage_dependency_lease_acquires_in_total_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    opened: list[str] = []
    real_open = store._open_stage_lease

    def tracked_open(stage: str):
        opened.append(stage)
        return real_open(stage)

    monkeypatch.setattr(store, "_open_stage_lease", tracked_open)

    with store.hold_dependency_stages(("z-stage", "a-stage", "m-stage")) as ordered:
        assert ordered == ("a-stage", "m-stage", "z-stage")

    assert opened == ["a-stage", "m-stage", "z-stage"]


def test_held_committed_stage_blocks_other_process_operations(tmp_path: Path) -> None:
    holder = _store(tmp_path)
    input_path, output_path = _input_and_output(holder)
    manifest_path = _record_report_stage(holder, input_path, [output_path])
    manifest_bytes = manifest_path.read_bytes()
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)

    with holder.hold_committed_stage("report", [input_path], [output_path]):
        process = context.Process(
            target=_probe_held_committed_stage_from_process,
            args=(
                holder.config.model_dump(mode="python"),
                str(input_path),
                str(output_path),
                sender,
            ),
        )
        process.start()
        sender.close()
        try:
            assert receiver.poll(10)
            assert receiver.recv() == [
                int(ErrorCode.MANIFEST_CONFLICT),
                int(ErrorCode.MANIFEST_CONFLICT),
                int(ErrorCode.MANIFEST_CONFLICT),
            ]
        finally:
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
            receiver.close()
        assert process.exitcode == 0
        assert manifest_path.read_bytes() == manifest_bytes


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_held_committed_stage_releases_on_control_flow_exit(
    tmp_path: Path,
    signal_type: type[BaseException],
) -> None:
    holder = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(holder)
    _record_report_stage(holder, input_path, [output_path])
    signal = signal_type("private-held-dependency-control-flow")

    with pytest.raises(signal_type) as exc_info:
        with holder.hold_committed_stage("report", [input_path], [output_path]):
            raise signal

    assert exc_info.value is signal
    assert contender.require_committed_stage("report", [input_path], [output_path])


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_held_committed_stage_closes_handle_when_lock_acquisition_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    holder = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(holder)
    _record_report_stage(holder, input_path, [output_path])
    signal = signal_type("private-held-dependency-acquisition-control-flow")
    real_lock = RunStore._lock_stage_handle
    handles: list[object] = []

    def interrupt_after_lock(handle: object) -> None:
        real_lock(handle)  # type: ignore[arg-type]
        handles.append(handle)
        raise signal

    monkeypatch.setattr(
        RunStore,
        "_lock_stage_handle",
        staticmethod(interrupt_after_lock),
    )
    with pytest.raises(signal_type) as exc_info:
        with holder.hold_committed_stage("report", [input_path], [output_path]):
            pytest.fail("interrupted lease acquisition must not enter the context")

    assert exc_info.value is signal
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert len(handles) == 1
    handle = handles[0]
    was_closed = handle.closed  # type: ignore[attr-defined]
    monkeypatch.setattr(RunStore, "_lock_stage_handle", staticmethod(real_lock))
    if not was_closed:
        RunStore._release_stage_handle(handle)  # type: ignore[arg-type]
    assert was_closed
    assert contender.require_committed_stage("report", [input_path], [output_path])


def test_run_store_close_releases_held_dependency_without_deleting_manifest(
    tmp_path: Path,
) -> None:
    holder = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(holder)
    manifest_path = _record_report_stage(holder, input_path, [output_path])
    guard = holder.hold_committed_stage("report", [input_path], [output_path])
    guard.__enter__()

    holder.close()

    assert manifest_path.exists()
    assert contender.require_committed_stage("report", [input_path], [output_path])
    guard.__exit__(None, None, None)


def test_stale_held_context_cannot_release_a_reacquired_dependency_lease(
    tmp_path: Path,
) -> None:
    holder = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(holder)
    _record_report_stage(holder, input_path, [output_path])
    stale_guard = holder.hold_committed_stage("report", [input_path], [output_path])
    stale_guard.__enter__()
    holder.close()
    current_guard = holder.hold_committed_stage("report", [input_path], [output_path])
    current_guard.__enter__()

    stale_guard.__exit__(None, None, None)

    with pytest.raises(SecAwareError) as exc_info:
        contender.require_committed_stage("report", [input_path], [output_path])
    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    current_guard.__exit__(None, None, None)
    assert contender.require_committed_stage("report", [input_path], [output_path])


@pytest.mark.parametrize(
    "forged_field",
    ["stage", "fingerprint", "config_sha256", "code_version", "outputs", "output_hash"],
)
def test_committed_stage_gate_rejects_forged_manifest_without_mutating_it(
    tmp_path: Path,
    forged_field: str,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if forged_field == "stage":
        payload["stage"] = "private-forged-stage"
    elif forged_field == "outputs":
        payload["outputs"] = ["reports/private-forged-output.txt"]
        payload["output_sha256"] = {"reports/private-forged-output.txt": sha256_path(output_path)}
    elif forged_field == "output_hash":
        payload["output_sha256"]["reports/result.txt"] = "0" * 64
    else:
        payload[forged_field] = "private-forged-value"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    forged_bytes = manifest_path.read_bytes()

    with pytest.raises(SecAwareError) as exc_info:
        store.require_committed_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(
        exc_info.value,
        "private-forged",
        str(manifest_path),
        str(output_path),
    )
    assert manifest_path.read_bytes() == forged_bytes


def test_committed_output_gate_rejects_tampering_without_mutating_manifest(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])
    manifest_bytes = manifest_path.read_bytes()
    secret = "private-uncommitted-output"
    output_path.write_text(secret, encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.require_committed_output("report", [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(exc_info.value, secret, str(output_path))
    assert manifest_path.read_bytes() == manifest_bytes


def test_successful_skip_does_not_authorize_a_later_stage_record(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is True
    output_path.write_text("changed-without-execution\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not manifest_path.exists()


@pytest.mark.parametrize("state", ["pending", "sealed"])
def test_same_stage_reentry_is_rejected_without_destroying_active_execution(
    tmp_path: Path,
    state: str,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    if state == "sealed":
        store.seal_stage_outputs("report", [output_path])

    with pytest.raises(SecAwareError) as exc_info:
        store.should_skip_stage("report", [input_path], [output_path], force=False)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(exc_info.value)
    store.record_stage("report", [input_path], [output_path])
    assert store.path(".stages", "report.json").exists()


def test_same_stage_concurrent_decision_has_one_executor_and_one_conflict(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    start = threading.Barrier(3)
    result_lock = threading.Lock()
    outcomes: list[str] = []

    def decide() -> None:
        start.wait()
        try:
            should_skip = store.should_skip_stage(
                "report",
                [input_path],
                [output_path],
                force=False,
            )
        except SecAwareError as error:
            outcome = f"error-{int(error.code)}"
        else:
            outcome = f"skip-{should_skip}"
        with result_lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=decide) for _ in range(2)]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(outcomes) == ["error-40", "skip-False"]
    store.record_stage("report", [input_path], [output_path])
    assert store.path(".stages", "report.json").exists()


def test_cross_instance_stage_lease_blocks_without_clearing_owner_state(
    tmp_path: Path,
) -> None:
    owner = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    lock_path = owner.path(".stages", "report.lock")
    secret = "private-cross-instance-lease-secret"

    assert owner.should_skip_stage("report", [input_path], [output_path], force=False) is False
    assert lock_path.is_file()
    inode = lock_path.stat().st_ino

    with pytest.raises(SecAwareError) as decision_info:
        contender.should_skip_stage("report", [input_path], [output_path], force=False)
    with pytest.raises(SecAwareError) as invalidation_info:
        contender.invalidate_stage("report")

    assert decision_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert invalidation_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(
        decision_info.value,
        str(owner.root),
        str(os.getpid()),
        secret,
    )
    assert owner.stage_is_active("report")

    owner.record_stage("report", [input_path], [output_path])

    assert secret.encode() not in lock_path.read_bytes()
    assert str(os.getpid()).encode() not in lock_path.read_bytes()
    assert contender.should_skip_stage("report", [input_path], [output_path], force=False)
    assert lock_path.is_file()
    assert lock_path.stat().st_ino == inode


def test_deferred_stage_commit_keeps_lease_until_explicit_finalize(tmp_path: Path) -> None:
    owner = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    stage = "discover"
    assert (
        owner.should_skip_stage(
            stage,
            [input_path],
            [output_path],
            force=False,
            preserve_committed=True,
        )
        is False
    )
    owner.seal_stage_outputs(stage, [output_path])

    lease = owner.begin_stage_commit(stage)
    owner.record_stage(
        stage,
        [input_path],
        [output_path],
        lease=lease,
    )

    assert owner.stage_is_active(stage)
    with pytest.raises(SecAwareError) as exc_info:
        contender.should_skip_stage(stage, [input_path], [output_path], force=False)
    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT

    owner.finalize_stage_commit(lease)
    assert not owner.stage_is_active(stage)
    assert contender.should_skip_stage(stage, [input_path], [output_path], force=False)


def test_deferred_stage_commit_rejects_missing_or_forged_owner(tmp_path: Path) -> None:
    owner = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    stage = "discover"
    assert (
        owner.should_skip_stage(
            stage,
            [input_path],
            [output_path],
            force=False,
            preserve_committed=True,
        )
        is False
    )
    owner.seal_stage_outputs(stage, [output_path])

    with pytest.raises(SecAwareError):
        owner.record_stage(stage, [input_path], [output_path])
    lease = owner.begin_stage_commit(stage)
    with pytest.raises(SecAwareError):
        RunStore(owner.config).finalize_stage_commit(lease)
    owner.abort_stage(stage)


def test_record_stage_rejects_forged_released_commit_lease_without_releasing_owner(
    tmp_path: Path,
) -> None:
    owner = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    stage = "discover"
    lease = _begin_deferred_stage_commit(owner, stage, input_path, output_path)
    forged = replace(lease, released=True)

    with pytest.raises(SecAwareError) as exc_info:
        owner.record_stage(stage, [input_path], [output_path], lease=forged)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not owner.path(".stages", f"{stage}.json").exists()
    assert owner._stage_commit_leases[stage] is lease
    assert owner._stage_leases[stage] is not None
    assert not owner._stage_leases[stage].closed
    owner.record_stage(stage, [input_path], [output_path], lease=lease)
    owner.finalize_stage_commit(lease)


def test_record_stage_rejects_real_released_token_during_new_transaction(
    tmp_path: Path,
) -> None:
    owner = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    stage = "discover"
    old = _begin_deferred_stage_commit(owner, stage, input_path, output_path)
    owner.record_stage(stage, [input_path], [output_path], lease=old)
    owner.finalize_stage_commit(old)
    assert old.released is True
    manifest_path = owner.path(".stages", f"{stage}.json")
    manifest_before = manifest_path.read_bytes()
    current = _begin_deferred_stage_commit(owner, stage, input_path, output_path)

    with pytest.raises(SecAwareError) as exc_info:
        owner.record_stage(stage, [input_path], [output_path], lease=old)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert manifest_path.read_bytes() == manifest_before
    assert owner._stage_commit_leases[stage] is current
    assert owner._pending_snapshots[stage].preserve_committed is True
    assert not owner._stage_leases[stage].closed
    owner.record_stage(stage, [input_path], [output_path], lease=current)
    owner.finalize_stage_commit(current)


def test_record_stage_rejects_released_token_from_another_store_and_keeps_new_owner(
    tmp_path: Path,
) -> None:
    original = _store(tmp_path)
    input_path, output_path = _input_and_output(original)
    stage = "discover"
    old = _begin_deferred_stage_commit(original, stage, input_path, output_path)
    original.record_stage(stage, [input_path], [output_path], lease=old)
    original.finalize_stage_commit(old)
    contender = RunStore(original.config)
    current = _begin_deferred_stage_commit(
        contender,
        stage,
        input_path,
        output_path,
    )

    with pytest.raises(SecAwareError) as exc_info:
        contender.record_stage(stage, [input_path], [output_path], lease=old)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert contender._stage_commit_leases[stage] is current
    assert not contender._stage_leases[stage].closed
    contender.record_stage(stage, [input_path], [output_path], lease=current)
    contender.finalize_stage_commit(current)
    original.close()
    contender.close()


def test_record_stage_rejects_commit_token_when_os_stage_handle_was_replaced(
    tmp_path: Path,
) -> None:
    owner = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    stage = "discover"
    lease = _begin_deferred_stage_commit(owner, stage, input_path, output_path)
    original_handle = owner._stage_leases[stage]
    replacement_handle = owner._open_stage_lease("confirm")
    owner._stage_leases[stage] = replacement_handle

    try:
        with pytest.raises(SecAwareError) as exc_info:
            owner.record_stage(stage, [input_path], [output_path], lease=lease)

        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
        assert not owner.path(".stages", f"{stage}.json").exists()
        assert owner._stage_commit_leases[stage] is lease
        assert not original_handle.closed
        assert not replacement_handle.closed
    finally:
        owner._stage_leases[stage] = original_handle
        owner._release_stage_handle(replacement_handle)
    owner.record_stage(stage, [input_path], [output_path], lease=lease)
    owner.finalize_stage_commit(lease)


@pytest.mark.parametrize("failures", [2, 100])
def test_deferred_stage_commit_release_retries_and_remains_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failures: int,
) -> None:
    owner = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    stage = "discover"
    assert (
        owner.should_skip_stage(
            stage,
            [input_path],
            [output_path],
            force=False,
            preserve_committed=True,
        )
        is False
    )
    owner.seal_stage_outputs(stage, [output_path])
    lease = owner.begin_stage_commit(stage)
    owner.record_stage(stage, [input_path], [output_path], lease=lease)
    real_release = owner._release_stage_handle
    attempts = 0

    def flaky_release(handle: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts <= failures:
            raise OSError("private-release-failure")
        real_release(handle)  # type: ignore[arg-type]

    monkeypatch.setattr(owner, "_release_stage_handle", flaky_release)
    if failures < 3:
        owner.finalize_stage_commit(lease)
        assert attempts == failures + 1
    else:
        with pytest.raises(SecAwareError) as exc_info:
            owner.finalize_stage_commit(lease)
        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
        assert attempts == 3
        assert owner.stage_is_active(stage)
        monkeypatch.setattr(owner, "_release_stage_handle", real_release)
        owner.ensure_stage_commit_released(lease)

    owner.finalize_stage_commit(lease)
    owner.ensure_stage_commit_released(lease)
    assert lease.released is True
    assert not owner.stage_is_active(stage)


def test_deferred_stage_commit_resumes_after_closed_handle_was_observed(
    tmp_path: Path,
) -> None:
    owner = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    stage = "discover"
    assert (
        owner.should_skip_stage(
            stage,
            [input_path],
            [output_path],
            force=False,
            preserve_committed=True,
        )
        is False
    )
    owner.seal_stage_outputs(stage, [output_path])
    lease = owner.begin_stage_commit(stage)
    owner.record_stage(stage, [input_path], [output_path], lease=lease)

    owner._release_stage_handle(owner._stage_leases[stage])
    assert not owner.stage_is_active(stage)
    owner.ensure_stage_commit_released(lease)

    assert lease.released is True
    owner.finalize_stage_commit(lease)


def test_nonowner_cannot_trust_or_delete_manifest_while_owner_holds_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    manifest_path = _record_report_stage(owner, input_path, [output_path])
    before = manifest_path.read_bytes()
    entered = threading.Event()
    release = threading.Event()
    real_allows_skip = run_store_module.manifest_allows_skip
    decision_errors: list[BaseException] = []

    def hold_decision(*args: object, **kwargs: object) -> bool:
        entered.set()
        assert release.wait(timeout=5)
        del args, kwargs
        return False

    monkeypatch.setattr(run_store_module, "manifest_allows_skip", hold_decision)

    def decide() -> None:
        try:
            owner.should_skip_stage("report", [input_path], [output_path], force=False)
        except BaseException as error:
            decision_errors.append(error)

    thread = threading.Thread(target=decide)
    thread.start()
    assert entered.wait(timeout=5)
    try:
        with pytest.raises(SecAwareError) as require_info:
            contender.require_committed_stage("report", [input_path], [output_path])
        with pytest.raises(SecAwareError) as invalidate_info:
            contender.invalidate_stage("report")

        assert require_info.value.code is ErrorCode.MANIFEST_CONFLICT
        assert invalidate_info.value.code is ErrorCode.MANIFEST_CONFLICT
        assert manifest_path.read_bytes() == before
    finally:
        release.set()
        thread.join(timeout=5)
        monkeypatch.setattr(run_store_module, "manifest_allows_skip", real_allows_skip)

    assert not thread.is_alive()
    assert decision_errors == []
    owner.abort_stage("report")


@pytest.mark.parametrize("release_path", ["skip", "record", "reject", "invalidate", "abort"])
def test_stage_lease_is_released_on_every_terminal_path(
    tmp_path: Path,
    release_path: str,
) -> None:
    owner = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    lock_path = owner.path(".stages", "report.lock")

    if release_path == "skip":
        _record_report_stage(owner, input_path, [output_path])
        assert owner.should_skip_stage("report", [input_path], [output_path], force=False)
    else:
        assert owner.should_skip_stage("report", [input_path], [output_path], force=False) is False
        if release_path == "record":
            owner.record_stage("report", [input_path], [output_path])
        elif release_path == "reject":
            output_path.unlink()
            with pytest.raises(SecAwareError):
                owner.record_stage("report", [input_path], [output_path])
            output_path.write_text("replacement\n", encoding="utf-8")
        elif release_path == "invalidate":
            owner.invalidate_stage("report")
        else:
            owner.abort_stage("report")

    assert lock_path.is_file()
    acquired = contender.should_skip_stage(
        "report", [input_path], [output_path], force=release_path != "skip"
    )
    assert acquired is (release_path == "skip")
    if not acquired:
        contender.abort_stage("report")


def test_closed_stage_lease_handle_allows_another_store_to_recover(
    tmp_path: Path,
) -> None:
    owner = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)

    assert owner.should_skip_stage("report", [input_path], [output_path], force=False) is False
    owner._stage_leases["report"].close()

    assert contender.should_skip_stage("report", [input_path], [output_path], force=False) is False
    contender.abort_stage("report")
    owner.abort_stage("report")


def test_stage_decision_baseexception_releases_lease_and_pending_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = _store(tmp_path)
    contender = _store(tmp_path)
    input_path, output_path = _input_and_output(owner)
    real_allows_skip = run_store_module.manifest_allows_skip

    def interrupt_decision(*args: object, **kwargs: object) -> bool:
        del args, kwargs
        raise KeyboardInterrupt("private-decision-interrupt")

    monkeypatch.setattr(run_store_module, "manifest_allows_skip", interrupt_decision)

    with pytest.raises(KeyboardInterrupt):
        owner.should_skip_stage("report", [input_path], [output_path], force=False)

    monkeypatch.setattr(run_store_module, "manifest_allows_skip", real_allows_skip)
    assert not owner.stage_is_active("report")
    assert contender.should_skip_stage("report", [input_path], [output_path], force=False) is False
    contender.abort_stage("report")


def test_stage_lease_is_released_automatically_when_owner_process_exits(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    context = multiprocessing.get_context("spawn")
    receive_ready, send_ready = context.Pipe(duplex=False)
    release = context.Event()
    process = context.Process(
        target=_hold_stage_lease_until_process_exit,
        args=(
            store.config.model_dump(mode="python"),
            str(input_path),
            str(output_path),
            send_ready,
            release,
        ),
    )
    process.start()
    send_ready.close()
    assert receive_ready.poll(10)
    assert receive_ready.recv() is False
    try:
        with pytest.raises(SecAwareError) as exc_info:
            store.should_skip_stage("report", [input_path], [output_path], force=False)
        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    finally:
        release.set()
        process.join(timeout=10)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        receive_ready.close()

    assert process.exitcode == 0
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    store.abort_stage("report")


def test_stage_inputs_rejects_a_missing_required_input(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(SecAwareError) as exc_info:
        store.stage_inputs([store.path("inputs", "missing.jsonl")])

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_external_stage_input_uses_a_stable_private_key_without_relpath(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    external = tmp_path / "private-external-provider" / "result.txt"
    external.parent.mkdir()
    external.write_text("private external bytes\n", encoding="utf-8")

    def reject_relpath(*args: object, **kwargs: object) -> str:
        del args, kwargs
        raise ValueError("cross-volume relpath must not be used")

    monkeypatch.setattr(os.path, "relpath", reject_relpath)

    first = store.stage_inputs([external])
    second = store.stage_inputs([external])

    assert first == second
    key = next(iter(first))
    assert key.startswith("@external/")
    assert len(key.removeprefix("@external/")) == 64
    assert str(external) not in key
    assert external.name not in key


def test_missing_external_stage_input_error_does_not_disclose_its_path(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    external = tmp_path / "private-missing-external" / "results.jsonl"

    with pytest.raises(SecAwareError) as exc_info:
        store.stage_inputs([external])

    error = exc_info.value
    surfaces = (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.to_dict(), sort_keys=True),
    )
    assert error.code is ErrorCode.CONTRACT
    assert error.__cause__ is None
    assert error.__context__ is None
    assert all(str(external) not in surface for surface in surfaces)
    assert all("private-missing-external" not in surface for surface in surfaces)
    assert str(error.details.get("path", "")).startswith("@external/")


@pytest.mark.skipif(os.name != "nt", reason="Windows drive semantics")
def test_external_path_key_handles_a_different_windows_drive_without_leaking_it(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    private_path = Path("Z:/private-cross-volume/results.jsonl")

    key = store._relative_path(private_path, kind="input", allow_outside=True)

    assert key.startswith("@external/")
    assert "private-cross-volume" not in key
    assert "Z:" not in key


def test_file_provider_directory_change_invalidates_generation_stage(tmp_path: Path) -> None:
    provider_dir = tmp_path / "provider-files"
    provider_dir.mkdir()
    generated_path = provider_dir / "model-a_7.py"
    generated_path.write_text("result = 'first'\n", encoding="utf-8")
    config, store = _file_provider_store(tmp_path, provider_dir)

    generate_observed_stage(config, store, force=False)

    manifest = read_stage_manifest(store.path(".stages", "generate-observed.json"))
    external_keys = [key for key in manifest.inputs if key.startswith("@external/")]
    assert len(external_keys) == 1
    assert str(provider_dir) not in json.dumps(manifest.inputs)
    assert provider_dir.name not in json.dumps(manifest.inputs)
    generated_path.write_text("result = 'second'\n", encoding="utf-8")

    generate_observed_stage(config, store, force=False)

    records = read_jsonl(
        store.path("generation", "observed_code.jsonl"),
        GeneratedCodeRecord,
        required=True,
    )
    assert records[0].code == "result = 'second'\n"


def test_missing_file_provider_directory_is_a_contract_error(tmp_path: Path) -> None:
    config, store = _file_provider_store(tmp_path, tmp_path / "missing-provider-files")

    with pytest.raises(SecAwareError) as exc_info:
        generate_observed_stage(config, store, force=False)

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_compatibility_generation_seals_canonical_output_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts_path = tmp_path / "source-prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            PromptRecord(
                prompt_id="prompt-a",
                task_id="task-prompt-a",
                split="discover",
                language="python",
                task_family="path_handling",
                cwe="CWE-22",
                prompt="Return a Python function.",
                prompt_role="neutral_baseline",
                counterpart_prompt_id=None,
            )
        ],
    )
    config = AppConfig.model_validate(
        {
            "run": {"name": "compat", "output_dir": str(tmp_path / "run")},
            "data": {
                "prompts_path": str(prompts_path),
                "prompt_attestations_path": str(tmp_path / "attestations.jsonl"),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "generation": {"provider": "mock", "models": ["model-a"], "seeds": [1]},
        }
    )
    store = RunStore(config)
    store.prepare()
    real_seal = store.seal_stage_outputs
    sealed: list[str] = []

    def observe_seal(stage: str, outputs: list[Path]) -> None:
        sealed.append(stage)
        real_seal(stage, outputs)

    monkeypatch.setattr(store, "seal_stage_outputs", observe_seal)

    generate_observed_stage(config, store, force=False)

    assert sealed == ["generate-observed"]


def test_stage_skip_is_invalidated_by_input_content_change(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    store.record_stage("report", [input_path], [output_path])

    input_path.write_text("input-v2\n", encoding="utf-8")

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False


def test_stage_skip_is_invalidated_by_resolved_config_change(tmp_path: Path) -> None:
    original_store = _store(tmp_path, bootstrap_samples=200)
    input_path, output_path = _input_and_output(original_store)
    assert (
        original_store.should_skip_stage(
            "report",
            [input_path],
            [output_path],
            force=False,
        )
        is False
    )
    original_store.record_stage("report", [input_path], [output_path])
    changed_store = _store(tmp_path, bootstrap_samples=201)

    assert (
        changed_store.should_skip_stage(
            "report",
            [input_path],
            [output_path],
            force=False,
        )
        is False
    )


def test_stage_skip_requires_every_declared_output(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, first_output = _input_and_output(store)
    second_output = store.path("reports", "second.txt")
    second_output.write_text("second\n", encoding="utf-8")
    outputs = [first_output, second_output]
    assert store.should_skip_stage("report", [input_path], outputs, force=False) is False
    store.record_stage("report", [input_path], outputs)

    second_output.unlink()

    assert store.should_skip_stage("report", [input_path], outputs, force=False) is False


def test_stage_skip_is_invalidated_by_output_content_change(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])

    output_path.write_text("tampered-output\n", encoding="utf-8")

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    assert not manifest_path.exists()


def test_record_stage_hashes_directory_outputs(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path = store.path("inputs", "source.txt")
    input_path.write_text("input\n", encoding="utf-8")
    output_path = store.path("reports", "directory-output")
    output_path.mkdir()
    (output_path / "result.txt").write_text("output\n", encoding="utf-8")

    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    store.record_stage("report", [input_path], [output_path])

    manifest = read_stage_manifest(store.path(".stages", "report.json"))
    assert manifest.output_sha256 == {"reports/directory-output": sha256_path(output_path)}
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is True


def test_sealed_output_hash_is_committed_as_the_manifest_expectation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    expected_hash = sha256_path(output_path)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    store.seal_stage_outputs("report", [output_path])
    store.verify_sealed_outputs("report", [output_path])
    assert not store.path(".stages", "report.json").exists()
    store.record_stage("report", [input_path], [output_path])

    manifest = read_stage_manifest(store.path(".stages", "report.json"))
    assert manifest.output_sha256 == {"reports/result.txt": expected_hash}


def test_sealed_output_verification_rejects_mutation_and_clears_stage_state(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = store.path(".stages", "report.json")
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    store.seal_stage_outputs("report", [output_path])
    output_path.write_text("changed-after-seal\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.verify_sealed_outputs("report", [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(exc_info.value)
    assert not manifest_path.exists()
    with pytest.raises(SecAwareError) as record_info:
        store.record_stage("report", [input_path], [output_path])
    assert record_info.value.code is ErrorCode.MANIFEST_CONFLICT


@pytest.mark.parametrize("misuse", ["without_pending", "duplicate", "paths_mismatch"])
def test_output_seal_misuse_invalidates_all_stage_authorization(
    tmp_path: Path,
    misuse: str,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = store.path(".stages", "report.json")
    if misuse == "without_pending":
        manifest_path = _record_report_stage(store, input_path, [output_path])
    else:
        assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
        if misuse == "duplicate":
            store.seal_stage_outputs("report", [output_path])
    seal_outputs = [output_path]
    if misuse == "paths_mismatch":
        other_output = store.path("reports", "other.txt")
        other_output.write_text("other\n", encoding="utf-8")
        seal_outputs = [other_output]

    with pytest.raises(SecAwareError) as exc_info:
        store.seal_stage_outputs("report", seal_outputs)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(exc_info.value)
    assert not manifest_path.exists()
    with pytest.raises(SecAwareError) as record_info:
        store.record_stage("report", [input_path], [output_path])
    assert record_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_output_seal_path_escape_is_a_safe_manifest_conflict(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    outside_output = tmp_path / "private-outside-output.txt"
    outside_output.write_text("private output\n", encoding="utf-8")
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.seal_stage_outputs("report", [outside_output])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(
        exc_info.value,
        str(outside_output),
        "private-outside-output",
    )
    with pytest.raises(SecAwareError):
        store.record_stage("report", [input_path], [output_path])


def test_output_seal_hash_failure_is_safe_and_clears_pending_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    secret = "private-seal-hash-failure"
    real_sha256_path = run_store_module.sha256_path
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    def fail_output_hash(path: Path) -> str:
        if Path(path) == output_path:
            raise OSError(secret)
        return real_sha256_path(path)

    monkeypatch.setattr(run_store_module, "sha256_path", fail_output_hash)

    with pytest.raises(SecAwareError) as exc_info:
        store.seal_stage_outputs("report", [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(exc_info.value, secret, str(output_path), "OSError")
    with pytest.raises(SecAwareError):
        store.record_stage("report", [input_path], [output_path])


def test_generation_stage_record_requires_a_prior_output_seal(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    stage = "plan-generation-observed"
    assert store.should_skip_stage(stage, [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage(stage, [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", f"{stage}.json").exists()


def test_oracle_stage_snapshot_commit_and_skip_are_policy_bound(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    stage = "run-oracle-observed"
    policy = "b" * 64

    assert (
        store.should_skip_stage(
            stage,
            [input_path],
            [output_path],
            force=False,
            policy_sha256=policy,
        )
        is False
    )
    store.seal_stage_outputs(stage, [output_path])
    store.record_stage(
        stage,
        [input_path],
        [output_path],
        policy_sha256=policy,
    )

    manifest = read_stage_manifest(store.path(".stages", f"{stage}.json"))
    assert manifest.policy_sha256 == policy
    assert (
        store.should_skip_stage(
            stage,
            [input_path],
            [output_path],
            force=False,
            policy_sha256=policy,
        )
        is True
    )
    assert (
        store.should_skip_stage(
            stage,
            [input_path],
            [output_path],
            force=False,
            policy_sha256="c" * 64,
        )
        is False
    )
    store.abort_stage(stage)


def test_oracle_stage_rejects_execution_without_policy_binding(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)

    with pytest.raises(SecAwareError) as exc_info:
        store.should_skip_stage(
            "run-oracle-observed",
            [input_path],
            [output_path],
            force=False,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_record_stage_rejects_output_changed_after_manifest_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = store.path(".stages", "report.json")
    real_write = run_store_module.write_stage_manifest

    def write_then_change(path: Path, manifest: object) -> None:
        real_write(path, manifest)
        output_path.write_text("changed-after-manifest-write\n", encoding="utf-8")

    monkeypatch.setattr(run_store_module, "write_stage_manifest", write_then_change)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert exc_info.value.details == {}
    assert not manifest_path.exists()


def test_record_stage_wraps_manifest_publish_failure_without_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = store.path(".stages", "report.json")
    real_write = run_store_module.write_stage_manifest
    secret = "private-manifest-publish-error"

    def write_then_fail(path: Path, manifest: object) -> None:
        real_write(path, manifest)
        raise OSError(secret)

    monkeypatch.setattr(run_store_module, "write_stage_manifest", write_then_fail)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(
        exc_info.value,
        secret,
        str(output_path),
        "OSError",
    )
    assert not manifest_path.exists()


def test_record_stage_wraps_output_hash_failure_without_path_or_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = store.path(".stages", "report.json")
    real_sha256_path = run_store_module.sha256_path
    secret = "private-output-hash-error"

    def fail_output_hash(path: Path) -> str:
        if Path(path) == output_path:
            raise OSError(secret)
        return real_sha256_path(path)

    monkeypatch.setattr(run_store_module, "sha256_path", fail_output_hash)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    error = exc_info.value
    assert error.code is ErrorCode.MANIFEST_CONFLICT
    _assert_manifest_error_is_safe(error, secret, str(output_path), "OSError")
    assert not manifest_path.exists()


def test_force_disables_stage_skip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)

    assert store.should_skip_stage("report", [input_path], [output_path], force=True) is False
    store.record_stage("report", [input_path], [output_path])
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is True


@pytest.mark.parametrize("invalidation", ["force", "input", "config", "outputs"])
def test_execution_decision_invalidates_previous_manifest(
    tmp_path: Path,
    invalidation: str,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    outputs = [output_path]
    manifest_path = _record_report_stage(store, input_path, outputs)
    force = invalidation == "force"
    if invalidation == "input":
        input_path.write_text("changed-input\n", encoding="utf-8")
    elif invalidation == "config":
        store.config.analysis.bootstrap_samples += 1
    elif invalidation == "outputs":
        second_output = store.path("reports", "second.txt")
        second_output.write_text("second\n", encoding="utf-8")
        outputs = [output_path, second_output]

    assert store.should_skip_stage("report", [input_path], outputs, force=force) is False
    assert not manifest_path.exists()


def test_failed_stage_cannot_reuse_manifest_after_partial_output_overwrite(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])

    assert store.should_skip_stage("report", [input_path], [output_path], force=True) is False
    assert not manifest_path.exists()
    output_path.write_text("partial-stage-output\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as reentry_info:
        store.should_skip_stage("report", [input_path], [output_path], force=False)
    assert reentry_info.value.code is ErrorCode.MANIFEST_CONFLICT
    store.invalidate_stage("report")
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False


def test_record_conflict_cannot_restore_stale_manifest_skip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    original_input = input_path.read_text(encoding="utf-8")
    manifest_path = _record_report_stage(store, input_path, [output_path])
    assert store.should_skip_stage("report", [input_path], [output_path], force=True) is False
    output_path.write_text("partial-stage-output\n", encoding="utf-8")
    input_path.write_text("changed-during-stage\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not manifest_path.exists()
    input_path.write_text(original_input, encoding="utf-8")
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False


def test_manifest_invalidation_wraps_unlink_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    _record_report_stage(store, input_path, [output_path])

    def fail_unlink(path: Path, missing_ok: bool = False) -> None:
        del path, missing_ok
        raise OSError("private filesystem failure")

    monkeypatch.setattr(Path, "unlink", fail_unlink)

    with pytest.raises(SecAwareError) as exc_info:
        store.should_skip_stage("report", [input_path], [output_path], force=True)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert "private filesystem failure" not in str(exc_info.value)


def test_public_stage_invalidation_clears_manifest_and_pending_snapshot(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    manifest_path = _record_report_stage(store, input_path, [output_path])
    assert store.should_skip_stage("report", [input_path], [output_path], force=True) is False

    store.invalidate_stage("report")

    assert not manifest_path.exists()
    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])
    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_record_stage_rejects_a_missing_declared_output(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path = store.path("inputs", "source.txt")
    input_path.write_text("input\n", encoding="utf-8")
    output_path = store.path("reports", "missing.txt")
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage(
            "report",
            [input_path],
            [output_path],
        )

    assert exc_info.value.code is ErrorCode.CONTRACT

    output_path.write_text("late-output\n", encoding="utf-8")
    with pytest.raises(SecAwareError) as retry_info:
        store.record_stage("report", [input_path], [output_path])

    assert retry_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_record_stage_requires_an_execution_snapshot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "report.json").exists()


def test_record_stage_rejects_input_changed_after_execution_snapshot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    input_path.write_text("changed-during-stage\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "report.json").exists()


def test_record_stage_rejects_config_changed_after_execution_snapshot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path, output_path = _input_and_output(store)
    assert store.should_skip_stage("report", [input_path], [output_path], force=False) is False
    store.config.analysis.bootstrap_samples += 1

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [output_path])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "report.json").exists()


def test_record_stage_rejects_output_path_escape(tmp_path: Path) -> None:
    store = _store(tmp_path)
    input_path = store.path("inputs", "source.txt")
    input_path.write_text("input\n", encoding="utf-8")
    outside_output = tmp_path / "outside.txt"
    outside_output.write_text("outside\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage("report", [input_path], [outside_output])

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert not store.path(".stages", "report.json").exists()


def test_cli_source_no_longer_calls_legacy_should_skip() -> None:
    source = (PROJECT_ROOT / "src" / "secaware" / "cli.py").read_text(encoding="utf-8")

    assert ".should_skip(" not in source
