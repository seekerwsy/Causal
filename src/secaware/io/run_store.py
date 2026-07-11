import hashlib
import os
import re
import shutil
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
import threading
from typing import Any, BinaryIO, Callable, TypeVar

from secaware import __version__
from secaware.config import AppConfig, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.manifest import (
    StageManifest,
    build_stage_fingerprint,
    manifest_allows_skip,
    read_stage_manifest,
    write_stage_manifest,
)
from secaware.schema.common import SCHEMA_VERSION

_Result = TypeVar("_Result")


def _synchronized(method: Callable[..., _Result]) -> Callable[..., _Result]:
    @wraps(method)
    def wrapped(self: Any, *args: Any, **kwargs: Any) -> _Result:
        with self._state_lock:
            return method(self, *args, **kwargs)

    return wrapped


@dataclass(frozen=True)
class _StageSnapshot:
    stage: str
    inputs: tuple[tuple[str, str], ...]
    config_sha256: str
    fingerprint: str
    code_version: str
    outputs: tuple[str, ...]


@dataclass(frozen=True)
class _StageOutputSeal:
    stage: str
    outputs: tuple[str, ...]
    output_sha256: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _HeldDependencyLease:
    handle: BinaryIO


class RunStore:
    def __init__(self, config: AppConfig):
        self.config = config
        self.root = Path(config.run.output_dir)
        self._pending_snapshots: dict[str, _StageSnapshot] = {}
        self._sealed_outputs: dict[str, _StageOutputSeal] = {}
        self._stage_leases: dict[str, BinaryIO] = {}
        self._held_dependency_leases: dict[str, _HeldDependencyLease] = {}
        self._state_lock = threading.RLock()

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def mkdirs(self) -> None:
        for part in [
            "inputs",
            "tsg",
            "generation",
            "oracle",
            "discovery",
            "interventions",
            "analysis",
            "reports",
            ".stages",
        ]:
            self.path(part).mkdir(parents=True, exist_ok=True)

    def prepare(self) -> None:
        try:
            self.mkdirs()
        except OSError:
            raise self._prepare_error(self.root) from None
        prompts_src = Path(self.config.data.prompts_path)
        try:
            shutil.copyfile(prompts_src, self.path("inputs", "prompts.jsonl"))
        except OSError:
            raise self._prepare_error(prompts_src) from None
        resolved_config_path = self.path("config.resolved.yaml")
        try:
            write_resolved_config(self.config, resolved_config_path)
        except OSError:
            raise self._prepare_error(resolved_config_path) from None

    def _prepare_error(self, path: Path) -> SecAwareError:
        return SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="prepare",
            message="run inputs could not be prepared",
            details={"path": str(path)},
        )

    def _contract_error(self, message: str, path: Path) -> SecAwareError:
        return SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="run_store",
            message=message,
            details={"path": str(path)},
        )

    def _manifest_conflict(self, stage: str, message: str) -> SecAwareError:
        return SecAwareError(
            code=ErrorCode.MANIFEST_CONFLICT,
            stage=stage,
            message=message,
        )

    def _stage_contract_error(self, stage: str, message: str) -> SecAwareError:
        return SecAwareError(
            code=ErrorCode.CONTRACT,
            stage=stage,
            message=message,
        )

    def _relative_path(
        self,
        path: str | Path,
        *,
        kind: str,
        allow_outside: bool = False,
    ) -> str:
        candidate = Path(path)
        try:
            resolved = candidate.resolve()
            resolved_root = self.root.resolve()
        except (OSError, ValueError):
            raise self._contract_error(
                f"{kind} path must remain within the run directory",
                candidate,
            ) from None
        relative: Path | None = None
        try:
            relative = resolved.relative_to(resolved_root)
        except ValueError:
            pass
        if relative is not None:
            return relative.as_posix()
        if allow_outside:
            normalized = Path(
                os.path.normcase(os.path.normpath(str(resolved)))
            ).as_posix()
            digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            return f"@external/{digest}"
        raise self._contract_error(
            f"{kind} path must remain within the run directory",
            candidate,
        )

    @staticmethod
    def _safe_stage_name(stage: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "-", stage).strip(".-_") or "stage"

    def _manifest_path(self, stage: str) -> Path:
        safe_stage = self._safe_stage_name(stage)
        return self.path(".stages", f"{safe_stage}.json")

    def _lease_path(self, stage: str) -> Path:
        safe_stage = self._safe_stage_name(stage)
        return self.path(".stages", f"{safe_stage}.lock")

    @staticmethod
    def _lock_stage_handle(handle: BinaryIO) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _release_stage_handle(handle: BinaryIO) -> None:
        if handle.closed:
            return
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, ValueError):
            pass
        finally:
            try:
                handle.close()
            except OSError:
                pass

    def _open_stage_lease(self, stage: str) -> BinaryIO:
        path = self._lease_path(stage)
        handle: BinaryIO | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                raise OSError
            handle = path.open("a+b")
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
                os.fsync(handle.fileno())
            self._lock_stage_handle(handle)
            return handle
        except (OSError, ValueError):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
        except BaseException:
            if handle is not None:
                self._release_stage_handle(handle)
            raise
        raise self._manifest_conflict(
            stage,
            "stage execution lease is unavailable",
        ) from None

    def _owned_stage_lease(self, stage: str) -> BinaryIO | None:
        handle = self._stage_leases.get(stage)
        if handle is not None and handle.closed:
            self._stage_leases.pop(stage, None)
            return None
        return handle

    def _owned_dependency_lease(self, stage: str) -> _HeldDependencyLease | None:
        lease = self._held_dependency_leases.get(stage)
        if lease is not None and lease.handle.closed:
            if self._held_dependency_leases.get(stage) is lease:
                self._held_dependency_leases.pop(stage, None)
            return None
        return lease

    def _acquire_stage_lease(self, stage: str) -> None:
        if (
            self._owned_stage_lease(stage) is not None
            or self._owned_dependency_lease(stage) is not None
        ):
            raise self._manifest_conflict(stage, "stage execution is already active")
        self._stage_leases[stage] = self._open_stage_lease(stage)

    def _release_stage_lease(self, stage: str) -> None:
        handle = self._stage_leases.pop(stage, None)
        if handle is not None:
            self._release_stage_handle(handle)

    def _release_dependency_lease(
        self,
        stage: str,
        *,
        expected: _HeldDependencyLease | None = None,
    ) -> None:
        lease = self._held_dependency_leases.get(stage)
        if lease is None or (expected is not None and lease is not expected):
            return
        self._held_dependency_leases.pop(stage, None)
        self._release_stage_handle(lease.handle)

    def _temporary_stage_lease(self, stage: str) -> BinaryIO | None:
        if (
            self._owned_stage_lease(stage) is not None
            or self._owned_dependency_lease(stage) is not None
        ):
            return None
        return self._open_stage_lease(stage)

    def _invalidate_stage_manifest(self, stage: str) -> None:
        try:
            self._manifest_path(stage).unlink(missing_ok=True)
        except OSError:
            raise self._manifest_conflict(
                stage,
                "stage manifest could not be invalidated",
            ) from None

    @_synchronized
    def invalidate_stage(self, stage: str) -> None:
        """Remove any committed manifest and pending execution authorization."""

        if self._owned_dependency_lease(stage) is not None:
            raise self._manifest_conflict(
                stage,
                "held committed stage cannot be invalidated",
            )
        owned = self._owned_stage_lease(stage) is not None
        temporary = None if owned else self._temporary_stage_lease(stage)
        try:
            self._clear_stage_state(stage)
            self._invalidate_stage_manifest(stage)
        finally:
            if owned:
                self._release_stage_lease(stage)
            elif temporary is not None:
                self._release_stage_handle(temporary)

    def abort_stage(self, stage: str) -> None:
        """Abort one stage execution and release its lease after invalidation."""

        self.invalidate_stage(stage)

    @_synchronized
    def close(self) -> None:
        """Release every locally owned execution and dependency lease."""

        self._pending_snapshots.clear()
        self._sealed_outputs.clear()
        for stage in list(self._stage_leases):
            self._release_stage_lease(stage)
        for stage in list(self._held_dependency_leases):
            self._release_dependency_lease(stage)

    def _clear_stage_state(self, stage: str) -> None:
        self._pending_snapshots.pop(stage, None)
        self._sealed_outputs.pop(stage, None)

    @_synchronized
    def stage_is_active(self, stage: str) -> bool:
        """Return whether this store has an active execution for the stage."""

        return (
            stage in self._pending_snapshots
            or stage in self._sealed_outputs
            or self._owned_stage_lease(stage) is not None
        )

    def _reject_stage_record(self, stage: str, message: str) -> None:
        self.invalidate_stage(stage)
        raise self._manifest_conflict(stage, message)

    @staticmethod
    def _requires_output_seal(stage: str) -> bool:
        return stage.startswith(
            (
                "plan-generation-",
                "plan-provider-generation-",
                "import-generation-",
                "generate-provider-",
            )
        )

    def _stage_output_hashes(
        self,
        stage: str,
        outputs: Sequence[Path],
        relative_outputs: Sequence[str],
    ) -> dict[str, str]:
        try:
            output_sha256 = {
                relative_path: sha256_path(output)
                for relative_path, output in zip(
                    relative_outputs,
                    outputs,
                    strict=True,
                )
            }
        except (OSError, TypeError, ValueError):
            pass
        else:
            return output_sha256
        self._reject_stage_record(
            stage,
            "stage outputs could not be verified",
        )

    def stage_inputs(self, paths: Sequence[str | Path]) -> dict[str, str]:
        inputs: dict[str, str] = {}
        for path_value in paths:
            path = Path(path_value)
            try:
                relative_path = self._relative_path(path, kind="input", allow_outside=True)
            except SecAwareError:
                raise SecAwareError(
                    code=ErrorCode.CONTRACT,
                    stage="run_store",
                    message="required stage input path could not be resolved",
                ) from None
            if not path.exists():
                raise SecAwareError(
                    code=ErrorCode.CONTRACT,
                    stage="run_store",
                    message="required stage input is missing",
                    details={"path": relative_path},
                )
            try:
                inputs[relative_path] = sha256_path(path)
            except (OSError, ValueError):
                raise SecAwareError(
                    code=ErrorCode.CONTRACT,
                    stage="run_store",
                    message="required stage input could not be read",
                    details={"path": relative_path},
                ) from None
        return inputs

    def _fingerprint_from_inputs(
        self,
        stage: str,
        inputs: dict[str, str],
        config: dict[str, object] | None = None,
    ) -> str:
        return build_stage_fingerprint(
            stage,
            inputs,
            self.config.model_dump(mode="json") if config is None else config,
            policy_sha256=None,
            catalog_sha256=None,
            code_version=__version__,
        )

    def stage_fingerprint(self, stage: str, input_paths: Sequence[str | Path]) -> str:
        return self._fingerprint_from_inputs(stage, self.stage_inputs(input_paths))

    @_synchronized
    def _require_committed(
        self,
        stage: str,
        output_paths: Sequence[str | Path],
        *,
        input_paths: Sequence[str | Path] | None,
    ) -> dict[str, str]:
        temporary_lease = self._temporary_stage_lease(stage)
        valid = False
        committed_output_sha256: dict[str, str] = {}
        try:
            try:
                outputs = [Path(path) for path in output_paths]
                relative_outputs = [
                    self._relative_path(path, kind="output") for path in outputs
                ]
                manifest = read_stage_manifest(self._manifest_path(stage))
                config = self.config.model_dump(mode="json")
                inputs = (
                    manifest.inputs
                    if input_paths is None
                    else self.stage_inputs(input_paths)
                )
                current_output_sha256 = {
                    relative_path: sha256_path(output)
                    for relative_path, output in zip(
                        relative_outputs,
                        outputs,
                        strict=True,
                    )
                }
                valid = (
                    manifest.stage == stage
                    and manifest.inputs == inputs
                    and manifest.config_sha256 == canonical_sha256(config)
                    and manifest.code_version == __version__
                    and manifest.fingerprint
                    == self._fingerprint_from_inputs(stage, inputs, config)
                    and manifest.outputs == relative_outputs
                    and manifest.output_sha256 == current_output_sha256
                )
                committed_output_sha256 = dict(manifest.output_sha256)
            except (OSError, SecAwareError, TypeError, UnicodeError, ValueError):
                pass
        finally:
            if temporary_lease is not None:
                self._release_stage_handle(temporary_lease)
        if not valid:
            raise self._manifest_conflict(stage, "committed stage output verification failed")
        return dict(committed_output_sha256)

    def require_committed_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
    ) -> dict[str, str]:
        """Require a complete committed stage with current inputs and outputs."""

        return self._require_committed(stage, output_paths, input_paths=input_paths)

    def require_committed_output(
        self,
        stage: str,
        output_paths: Sequence[str | Path],
    ) -> dict[str, str]:
        """Require a committed output without re-reading producer inputs."""

        return self._require_committed(stage, output_paths, input_paths=None)

    @contextmanager
    def hold_committed_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
    ) -> Iterator[dict[str, str]]:
        """Hold a committed producer lease while a dependent stage consumes it."""

        with self._state_lock:
            if (
                self._owned_stage_lease(stage) is not None
                or self._owned_dependency_lease(stage) is not None
            ):
                raise self._manifest_conflict(
                    stage,
                    "stage lease is already owned by this run store",
                )
            lease = _HeldDependencyLease(handle=self._open_stage_lease(stage))
            self._held_dependency_leases[stage] = lease
        try:
            output_sha256 = self.require_committed_stage(
                stage,
                input_paths,
                output_paths,
            )
            yield dict(output_sha256)
        finally:
            with self._state_lock:
                self._release_dependency_lease(stage, expected=lease)

    @_synchronized
    def seal_stage_outputs(
        self,
        stage: str,
        output_paths: Sequence[str | Path],
    ) -> None:
        """Bind one output snapshot to the pending execution before validation."""

        snapshot = self._pending_snapshots.get(stage)
        if snapshot is None:
            self._reject_stage_record(
                stage,
                "stage outputs cannot be sealed without an execution snapshot",
            )
        if stage in self._sealed_outputs:
            self._reject_stage_record(stage, "stage outputs were already sealed")
        outputs = [Path(path) for path in output_paths]
        relative_outputs: list[str] | None = None
        try:
            relative_outputs = [self._relative_path(path, kind="output") for path in outputs]
        except SecAwareError:
            pass
        if relative_outputs is None or snapshot.outputs != tuple(relative_outputs):
            self._reject_stage_record(
                stage,
                "sealed stage outputs do not match the execution snapshot",
            )
        output_sha256 = self._stage_output_hashes(stage, outputs, relative_outputs)
        self._sealed_outputs[stage] = _StageOutputSeal(
            stage=stage,
            outputs=tuple(relative_outputs),
            output_sha256=tuple(sorted(output_sha256.items())),
        )

    @_synchronized
    def verify_sealed_outputs(
        self,
        stage: str,
        output_paths: Sequence[str | Path],
    ) -> None:
        """Verify the current outputs against a seal without consuming it."""

        snapshot = self._pending_snapshots.get(stage)
        output_seal = self._sealed_outputs.get(stage)
        if snapshot is None or output_seal is None or output_seal.stage != stage:
            self._reject_stage_record(stage, "stage output seal is unavailable")
        outputs = [Path(path) for path in output_paths]
        relative_outputs: list[str] | None = None
        try:
            relative_outputs = [self._relative_path(path, kind="output") for path in outputs]
        except SecAwareError:
            pass
        if (
            relative_outputs is None
            or snapshot.outputs != tuple(relative_outputs)
            or output_seal.outputs != tuple(relative_outputs)
        ):
            self._reject_stage_record(
                stage,
                "sealed stage outputs do not match the execution snapshot",
            )
        current_output_sha256 = self._stage_output_hashes(stage, outputs, relative_outputs)
        if current_output_sha256 != dict(output_seal.output_sha256):
            self._reject_stage_record(stage, "sealed stage outputs changed after sealing")

    @_synchronized
    def should_skip_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
        force: bool,
    ) -> bool:
        if (
            stage in self._pending_snapshots
            or stage in self._sealed_outputs
            or self._owned_stage_lease(stage) is not None
            or self._owned_dependency_lease(stage) is not None
        ):
            raise self._manifest_conflict(stage, "stage execution is already active")
        self._acquire_stage_lease(stage)
        try:
            outputs = [Path(path) for path in output_paths]
            relative_outputs = [self._relative_path(path, kind="output") for path in outputs]
            inputs = self.stage_inputs(input_paths)
            config = self.config.model_dump(mode="json")
            fingerprint = self._fingerprint_from_inputs(stage, inputs, config)
            self._pending_snapshots[stage] = _StageSnapshot(
                stage=stage,
                inputs=tuple(sorted(inputs.items())),
                config_sha256=canonical_sha256(config),
                fingerprint=fingerprint,
                code_version=__version__,
                outputs=tuple(relative_outputs),
            )
            allows_skip = manifest_allows_skip(
                self._manifest_path(stage),
                fingerprint,
                outputs,
                force=force,
                manifest_outputs=relative_outputs,
            )
            if allows_skip:
                self._clear_stage_state(stage)
                self._release_stage_lease(stage)
                return True
            self._invalidate_stage_manifest(stage)
        except BaseException:
            self._clear_stage_state(stage)
            self._release_stage_lease(stage)
            raise
        return False

    @_synchronized
    def record_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
    ) -> None:
        try:
            self._record_stage(stage, input_paths, output_paths)
        finally:
            self._release_stage_lease(stage)

    def _record_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
    ) -> None:
        if self._requires_output_seal(stage) or stage in self._sealed_outputs:
            self.verify_sealed_outputs(stage, output_paths)
        outputs = [Path(path) for path in output_paths]
        snapshot = self._pending_snapshots.pop(stage, None)
        output_seal = self._sealed_outputs.pop(stage, None)
        seal_required = self._requires_output_seal(stage) or output_seal is not None
        if seal_required and (snapshot is None or output_seal is None):
            self._reject_stage_record(
                stage,
                "stage output seal is missing",
            )
        if not outputs:
            if seal_required:
                self._reject_stage_record(stage, "sealed stage outputs are missing")
            raise self._contract_error("stage must declare at least one output", self.root)
        relative_outputs: list[str] | None = None
        try:
            relative_outputs = [self._relative_path(path, kind="output") for path in outputs]
        except SecAwareError:
            if not seal_required:
                raise
        if relative_outputs is None:
            self._reject_stage_record(stage, "sealed stage output paths are invalid")
        if output_seal is not None and output_seal.outputs != tuple(relative_outputs):
            self._reject_stage_record(
                stage,
                "sealed stage outputs changed before recording",
            )
        for output in outputs:
            if not output.exists():
                if seal_required:
                    self._reject_stage_record(
                        stage,
                        "sealed stage output is missing",
                    )
                raise self._stage_contract_error(stage, "declared stage output is missing")
        if snapshot is None:
            self._reject_stage_record(
                stage,
                "stage was not preceded by an execution snapshot",
            )
        try:
            inputs = self.stage_inputs(input_paths)
        except SecAwareError:
            self._reject_stage_record(
                stage,
                "stage inputs changed during execution",
            )
        config = self.config.model_dump(mode="json")
        current_config_sha256 = canonical_sha256(config)
        current_fingerprint = self._fingerprint_from_inputs(stage, inputs, config)
        if (
            snapshot.inputs != tuple(sorted(inputs.items()))
            or snapshot.config_sha256 != current_config_sha256
            or snapshot.fingerprint != current_fingerprint
            or snapshot.code_version != __version__
            or snapshot.outputs != tuple(relative_outputs)
        ):
            self._reject_stage_record(
                stage,
                "stage inputs or configuration changed during execution",
            )
        current_output_sha256 = self._stage_output_hashes(stage, outputs, relative_outputs)
        output_sha256 = (
            dict(output_seal.output_sha256)
            if output_seal is not None
            else current_output_sha256
        )
        if current_output_sha256 != output_sha256:
            self._reject_stage_record(
                stage,
                "sealed stage outputs changed before the manifest was committed",
            )
        manifest_path = self._manifest_path(stage)
        manifest_committed = False
        try:
            write_stage_manifest(
                manifest_path,
                StageManifest(
                    schema_version=SCHEMA_VERSION,
                    stage=snapshot.stage,
                    fingerprint=snapshot.fingerprint,
                    inputs=dict(snapshot.inputs),
                    config_sha256=snapshot.config_sha256,
                    code_version=snapshot.code_version,
                    outputs=list(snapshot.outputs),
                    output_sha256=output_sha256,
                ),
            )
        except Exception:
            pass
        else:
            manifest_committed = True
        if not manifest_committed:
            self._reject_stage_record(stage, "stage manifest could not be committed")
        verified_output_sha256 = self._stage_output_hashes(
            stage,
            outputs,
            relative_outputs,
        )
        if verified_output_sha256 != output_sha256:
            self._reject_stage_record(
                stage,
                "stage outputs changed while the manifest was committed",
            )
