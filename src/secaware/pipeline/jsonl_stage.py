from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import cast

from pydantic import BaseModel

from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore, StageCommitLease
from secaware.io.transaction import (
    ArtifactTransaction,
    TransactionArtifact,
    TransactionStateError,
    cleanup_committed_transaction,
    recover_transaction,
    resolve_pending_transaction,
)


_TRANSACTION_CLEANUP_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class JsonlOutputSpec:
    path: Path
    model: type[BaseModel] | None
    require_nonempty: bool = False
    max_records: int = 100_000
    max_line_chars: int = 4_000_000
    max_total_chars: int = 256_000_000


BuildRecords = Callable[[], Sequence[Sequence[BaseModel | dict[str, object]]]]


def _stage_error(code: ErrorCode, stage: str, message: str) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=stage,
        message=message,
        details={},
        retryable=False,
    )


def _transaction_path(output: Path, suffix: str, *, stage: str) -> Path:
    handle = None
    try:
        handle = tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=f".{output.name}.",
            suffix=suffix,
            dir=output.parent,
            delete=False,
        )
        path = Path(handle.name)
        handle.close()
        handle = None
        path.unlink()
        return path
    except OSError:
        raise _stage_error(
            ErrorCode.CONTRACT,
            stage,
            "stage output transaction is unavailable",
        ) from None
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass


def _cleanup_failed_stage(store: RunStore, stage: str) -> None:
    if not store.stage_is_active(stage):
        return
    try:
        store.abort_stage(stage)
    except SecAwareError:
        pass


def _finalize_stage_commit(store: RunStore, lease: StageCommitLease) -> None:
    failure: BaseException | None = None
    try:
        store.finalize_stage_commit(lease)
    except BaseException as error:
        failure = error
    finally:
        try:
            store.ensure_stage_commit_released(lease)
        except BaseException as error:
            if failure is None or (
                isinstance(error, (KeyboardInterrupt, SystemExit))
                and not isinstance(failure, (KeyboardInterrupt, SystemExit))
            ):
                failure = error
    if failure is not None:
        raise failure


def _cleanup_transaction_paths(
    paths: Sequence[Path | None],
) -> KeyboardInterrupt | SystemExit | None:
    pending = list(dict.fromkeys(path for path in paths if path is not None))
    control: KeyboardInterrupt | SystemExit | None = None
    for _ in range(_TRANSACTION_CLEANUP_ATTEMPTS):
        remaining: list[Path] = []
        for path in pending:
            try:
                path.unlink(missing_ok=True)
            except (KeyboardInterrupt, SystemExit) as error:
                if control is None:
                    control = error
                remaining.append(path)
            except Exception:
                remaining.append(path)
        pending = remaining
        if not pending:
            break
    return control


def _stale_transaction_paths(path: Path, *suffixes: str) -> list[Path]:
    stale: list[Path] = []
    for suffix in suffixes:
        try:
            stale.extend(path.parent.glob(f".{path.name}.*{suffix}"))
        except OSError:
            pass
    return stale


def _read_jsonl_output(
    spec: JsonlOutputSpec,
    path: Path,
    *,
    stage: str,
) -> list[BaseModel] | list[dict]:
    return cast(
        list[BaseModel] | list[dict],
        read_jsonl(
            path,
            spec.model,
            required=True,
            allow_empty=not spec.require_nonempty,
            max_records=spec.max_records,
            max_line_chars=spec.max_line_chars,
            max_total_chars=spec.max_total_chars,
            stage=stage,
        ),
    )


def execute_jsonl_stage_transaction(
    store: RunStore,
    *,
    stage: str,
    inputs: Sequence[Path],
    outputs: Sequence[JsonlOutputSpec],
    force: bool,
    build: BuildRecords,
    catalog_sha256: str | None = None,
) -> None:
    if not outputs:
        raise SecAwareError(
            code=ErrorCode.CONTRACT,
            stage=stage,
            message="stage output transaction is invalid",
        )
    _execute_transaction_body(
        store=store,
        stage=stage,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        force=force,
        build=build,
        catalog_sha256=catalog_sha256,
    )


def _execute_transaction_body(
    store: RunStore,
    *,
    stage: str,
    inputs: tuple[Path, ...],
    outputs: tuple[JsonlOutputSpec, ...],
    force: bool,
    build: BuildRecords,
    catalog_sha256: str | None,
) -> None:
    output_paths = tuple(output.path for output in outputs)
    manifest_path = store.path(".stages", f"{stage}.json")
    journal_path = store.path(".stages", f".{stage}.transaction.json")
    try:
        artifacts = tuple(
            [
                TransactionArtifact(output, f"output{index}")
                for index, output in enumerate(output_paths)
            ]
            + [TransactionArtifact(manifest_path, "manifest")]
        )
    except TransactionStateError:
        raise _stage_error(
            ErrorCode.CONTRACT,
            stage,
            "stage output transaction is invalid",
        ) from None

    def recover_or_cleanup_transaction() -> None:
        try:
            resolve_pending_transaction(journal_path, artifacts)
        except (KeyboardInterrupt, SystemExit):
            raise
        except TransactionStateError:
            raise _stage_error(
                ErrorCode.CONTRACT,
                stage,
                "stage output transaction recovery failed",
            ) from None
        stale_paths: list[Path] = []
        for output in output_paths:
            stale_paths.extend(_stale_transaction_paths(output, ".stage.candidate"))
        stale_control = _cleanup_transaction_paths(stale_paths)
        if stale_control is not None:
            raise stale_control

    if store.should_skip_stage(
        stage,
        inputs,
        output_paths,
        force,
        catalog_sha256=catalog_sha256,
        preserve_committed=True,
        after_lease_acquired=recover_or_cleanup_transaction,
    ):
        return

    candidates: list[Path | None] = [None] * len(outputs)
    transaction: ArtifactTransaction | None = None
    stage_commit_lease = None
    commit_point = False
    try:
        try:
            transaction = ArtifactTransaction.begin(journal_path, artifacts)
            transaction.backup(len(outputs))
        except (KeyboardInterrupt, SystemExit):
            raise
        except TransactionStateError:
            raise _stage_error(
                ErrorCode.CONTRACT,
                stage,
                "stage output transaction could not be started",
            ) from None

        record_groups = list(build())
        if len(record_groups) != len(outputs):
            raise _stage_error(
                ErrorCode.CONTRACT,
                stage,
                "stage output transaction is invalid",
            )
        expected_groups = [list(records) for records in record_groups]
        if any(
            output.require_nonempty and not records
            for output, records in zip(outputs, expected_groups, strict=True)
        ):
            raise _stage_error(
                ErrorCode.CONTRACT,
                stage,
                "stage artifact must not be empty",
            )
        for index, (output, expected) in enumerate(
            zip(outputs, expected_groups, strict=True)
        ):
            candidate = _transaction_path(output.path, ".stage.candidate", stage=stage)
            candidates[index] = candidate
            write_jsonl(candidate, expected, stage=stage)
            if _read_jsonl_output(output, candidate, stage=stage) != expected:
                raise _stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "stage artifact failed canonical readback",
                )

        for index, _output in enumerate(outputs):
            try:
                candidate = candidates[index]
                if candidate is None:
                    raise TransactionStateError
                transaction.install(index, candidate)
                candidates[index] = None
            except (KeyboardInterrupt, SystemExit):
                raise
            except TransactionStateError:
                raise _stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "stage artifact could not be committed",
                ) from None

        store.seal_stage_outputs(stage, output_paths)
        for output, expected in zip(outputs, expected_groups, strict=True):
            if _read_jsonl_output(output, output.path, stage=stage) != expected:
                store.verify_sealed_outputs(stage, output_paths)
                raise _stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "stage artifact failed canonical readback",
                )
        store.verify_sealed_outputs(stage, output_paths)
        stage_commit_lease = store.begin_stage_commit(stage)
        store.record_stage(
            stage,
            inputs,
            output_paths,
            catalog_sha256=catalog_sha256,
            lease=stage_commit_lease,
        )
        try:
            transaction.mark_postcommit()
        except (KeyboardInterrupt, SystemExit):
            raise
        except TransactionStateError:
            raise _stage_error(
                ErrorCode.CONTRACT,
                stage,
                "stage commit verification failed",
            ) from None
        commit_point = True
        _finalize_stage_commit(store, stage_commit_lease)
        stage_commit_lease = None
        try:
            cleanup_committed_transaction(transaction)
        except (KeyboardInterrupt, SystemExit):
            raise
        except TransactionStateError:
            raise _stage_error(
                ErrorCode.CONTRACT,
                stage,
                "stage commit verification failed",
            ) from None
    except BaseException as error:
        if transaction is not None and not commit_point:
            try:
                recover_transaction(transaction)
            except (KeyboardInterrupt, SystemExit):
                _cleanup_failed_stage(store, stage)
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise error
                raise
            except TransactionStateError:
                _cleanup_failed_stage(store, stage)
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise error
                raise _stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "stage output transaction rollback failed",
                ) from None
        if not commit_point:
            _cleanup_failed_stage(store, stage)
        raise
    finally:
        if not commit_point:
            _cleanup_transaction_paths(candidates)


__all__ = [
    "BuildRecords",
    "JsonlOutputSpec",
    "execute_jsonl_stage_transaction",
]
