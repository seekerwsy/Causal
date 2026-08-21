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
from secaware.pipeline.stage_contracts import (
    confirmation_oracle_stage_contract_sha256,
    confirmation_generation_stage_contract_sha256,
    discovery_stage_contract_sha256,
    effect_stage_contract_sha256,
    functional_outcome_import_stage_contract_sha256,
    functional_judge_stage_contract_sha256,
    jci_stage_contract_sha256,
    prompt_variant_stage_contract_sha256,
    randomization_stage_contract_sha256,
    report_stage_contract_sha256,
    rfci_stage_contract_sha256,
)
from secaware.schema.common import SCHEMA_VERSION
from secaware.tsg.contract import PROMPT_TSG_STAGE_CONTRACT_SHA256

_Result = TypeVar("_Result")
_PROMPT_EXTRACTION_OUTPUTS = (
    "tsg/prompt_extraction_proposals.jsonl",
    "tsg/prompt_tsg.jsonl",
)
_CAUSAL_TABLE_OUTPUTS = (
    "discovery/causal_tables.jsonl",
    "discovery/causal_observations.jsonl",
    "discovery/causal_exclusions.jsonl",
)
_CONFIRMATION_ORACLE_OUTPUTS = ("oracle/confirmation_oracle.jsonl",)
_FCI_DISCOVERY_OUTPUTS = (
    "discovery/background_knowledge.jsonl",
    "discovery/reference_pags.jsonl",
    "discovery/bootstrap_draws.jsonl",
    "discovery/bootstrap_pags.jsonl",
    "discovery/bootstrap_failures.jsonl",
    "discovery/path_support.jsonl",
    "discovery/hypotheses_frozen.jsonl",
    "discovery/discovery_failures.jsonl",
)
_PROMPT_VARIANT_OUTPUTS = (
    "interventions/target_specs.jsonl",
    "interventions/target_instances.jsonl",
    "interventions/confirmation_protocols.jsonl",
    "interventions/confirmation_protocol_instances.jsonl",
    "interventions/intended_patches.jsonl",
    "interventions/variant_extraction_proposals.jsonl",
    "interventions/variant_prompt_tsg.jsonl",
    "interventions/graph_deltas.jsonl",
    "interventions/prompt_variants.jsonl",
    "interventions/length_matches.jsonl",
    "interventions/pre_randomization_exclusions.jsonl",
)
_RANDOMIZATION_OUTPUTS = (
    "interventions/randomization_manifest.jsonl",
    "interventions/assignments.jsonl",
)
_CONFIRMATION_GENERATION_OUTPUTS = (
    "generation/confirmation_requests.jsonl",
    "generation/confirmation_execution.jsonl",
    "generation/confirmation_code.jsonl",
)
_FUNCTIONAL_OUTCOME_IMPORT_OUTPUTS = ("analysis/functional_outcomes.jsonl",)
_FUNCTIONAL_JUDGE_OUTPUTS = (
    "analysis/functional_judge_passes.jsonl",
    "analysis/program_functional_outcomes.jsonl",
)
_EFFECT_STAGE_OUTPUTS = (
    "analysis/assignment_outcomes.jsonl",
    "analysis/contrast_specs.jsonl",
    "analysis/effect_bootstrap_draws.jsonl",
    "analysis/itt_effects.jsonl",
    "analysis/effect_failures.jsonl",
)
_JCI_STAGE_OUTPUTS = (
    "analysis/jci_tables.jsonl",
    "analysis/jci_observations.jsonl",
    "analysis/jci_raw_pags.jsonl",
    "analysis/jci_background_knowledge.jsonl",
    "analysis/jci_constrained_pags.jsonl",
    "analysis/jci_orientation_deltas.jsonl",
    "analysis/jci_failures.jsonl",
)
_RFCI_STAGE_OUTPUTS = (
    "analysis/rfci_capability.jsonl",
    "analysis/rfci_pags.jsonl",
    "analysis/rfci_failures.jsonl",
)
_REPORT_STAGE_OUTPUTS = (
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
    policy_sha256: str | None
    catalog_sha256: str | None
    preserve_committed: bool
    outputs: tuple[str, ...]


@dataclass(frozen=True)
class _StageOutputSeal:
    stage: str
    outputs: tuple[str, ...]
    output_sha256: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _HeldDependencyLease:
    handle: BinaryIO


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class StageCommitLease:
    stage: str
    owner: object
    handle: BinaryIO
    released: bool = False


class RunStore:
    def __init__(self, config: AppConfig):
        self.config = config
        self.root = Path(config.run.output_dir)
        self._pending_snapshots: dict[str, _StageSnapshot] = {}
        self._sealed_outputs: dict[str, _StageOutputSeal] = {}
        self._stage_leases: dict[str, BinaryIO] = {}
        self._held_dependency_leases: dict[str, _HeldDependencyLease] = {}
        self._stage_commit_leases: dict[str, StageCommitLease] = {}
        self._recorded_stage_commits: set[str] = set()
        self._stage_commit_owner = object()
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
            normalized = Path(os.path.normcase(os.path.normpath(str(resolved)))).as_posix()
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
        handle = self._stage_leases.get(stage)
        if handle is not None:
            self._release_stage_handle(handle)
            if handle.closed and self._stage_leases.get(stage) is handle:
                self._stage_leases.pop(stage, None)

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

        if stage in self._stage_commit_leases:
            raise self._manifest_conflict(
                stage,
                "deferred stage commit must be finalized or aborted",
            )
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

        with self._state_lock:
            if stage in self._stage_commit_leases:
                self._clear_stage_state(stage)
                self._ensure_stage_commit_released(
                    self._stage_commit_leases[stage],
                    require_recorded=False,
                )
                return
            snapshot = self._pending_snapshots.get(stage)
            if snapshot is not None and snapshot.preserve_committed:
                self._clear_stage_state(stage)
                self._release_stage_lease(stage)
                return
        self.invalidate_stage(stage)

    @_synchronized
    def close(self) -> None:
        """Release every locally owned execution and dependency lease."""

        self._pending_snapshots.clear()
        self._sealed_outputs.clear()
        for stage in list(self._stage_leases):
            self._release_stage_lease(stage)
        for stage, lease in list(self._stage_commit_leases.items()):
            handle = self._stage_leases.get(stage)
            if handle is None or handle.closed:
                self._complete_stage_commit_release(lease)
        for stage in list(self._held_dependency_leases):
            self._release_dependency_lease(stage)

    def _clear_stage_state(self, stage: str) -> None:
        self._pending_snapshots.pop(stage, None)
        self._sealed_outputs.pop(stage, None)

    def _clear_stage_commit(self, stage: str) -> None:
        self._stage_commit_leases.pop(stage, None)
        self._recorded_stage_commits.discard(stage)

    @_synchronized
    def stage_is_active(self, stage: str) -> bool:
        """Return whether this store has an active execution for the stage."""

        return (
            stage in self._pending_snapshots
            or stage in self._sealed_outputs
            or self._owned_stage_lease(stage) is not None
        )

    def _reject_stage_record(self, stage: str, message: str) -> None:
        if stage in self._stage_commit_leases:
            raise self._manifest_conflict(stage, message)
        snapshot = self._pending_snapshots.get(stage)
        if snapshot is not None and snapshot.preserve_committed:
            raise self._manifest_conflict(stage, message)
        self.invalidate_stage(stage)
        raise self._manifest_conflict(stage, message)

    @staticmethod
    def _requires_output_seal(stage: str) -> bool:
        return stage in {
            "assemble-causal-tables",
            "fci-discovery",
            "build-confirmation-variants",
            "randomize-confirmation",
            "generate-confirmation",
            "generate-observed",
            "generate-counterfactual",
            "extract-prompt-tsg",
            "discover",
            "intervene",
            "confirm",
            "import-functional-outcomes",
            "estimate-confirmation-effects",
            "jci-confirmation",
            "rfci-confirmation",
            "report",
        } or stage.startswith(
            (
                "plan-generation-",
                "plan-provider-generation-",
                "import-generation-",
                "generate-provider-",
                "run-oracle-",
            )
        )

    def _policy_binding(self, stage: str, policy_sha256: str | None) -> str | None:
        valid_digest = (
            type(policy_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", policy_sha256) is not None
        )
        if stage.startswith("run-oracle-") or stage in {
            "extract-prompt-tsg",
            "build-confirmation-variants",
            "judge-functionality",
        }:
            if not valid_digest:
                raise self._manifest_conflict(stage, "stage policy binding is invalid")
            return policy_sha256
        if policy_sha256 is not None:
            raise self._manifest_conflict(stage, "stage policy binding is invalid")
        return None

    def _validate_stage_output_contract(
        self,
        stage: str,
        relative_outputs: Sequence[str],
    ) -> None:
        if stage == "extract-prompt-tsg" and tuple(relative_outputs) != _PROMPT_EXTRACTION_OUTPUTS:
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if stage == "assemble-causal-tables" and tuple(relative_outputs) != _CAUSAL_TABLE_OUTPUTS:
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if stage == "fci-discovery" and tuple(relative_outputs) != _FCI_DISCOVERY_OUTPUTS:
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if (
            stage == "build-confirmation-variants"
            and tuple(relative_outputs) != _PROMPT_VARIANT_OUTPUTS
        ):
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if stage == "randomize-confirmation" and tuple(relative_outputs) != _RANDOMIZATION_OUTPUTS:
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if (
            stage == "generate-confirmation"
            and tuple(relative_outputs) != _CONFIRMATION_GENERATION_OUTPUTS
        ):
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if (
            stage == "run-oracle-confirmation"
            and tuple(relative_outputs) != _CONFIRMATION_ORACLE_OUTPUTS
        ):
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if (
            stage == "import-functional-outcomes"
            and tuple(relative_outputs) != _FUNCTIONAL_OUTCOME_IMPORT_OUTPUTS
        ):
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if stage == "judge-functionality" and tuple(relative_outputs) != (
            _FUNCTIONAL_JUDGE_OUTPUTS
        ):
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if (
            stage == "estimate-confirmation-effects"
            and tuple(relative_outputs) != _EFFECT_STAGE_OUTPUTS
        ):
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if stage == "jci-confirmation" and tuple(relative_outputs) != _JCI_STAGE_OUTPUTS:
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if stage == "rfci-confirmation" and tuple(relative_outputs) != _RFCI_STAGE_OUTPUTS:
            raise self._manifest_conflict(stage, "stage output contract is invalid")
        if stage == "report" and tuple(relative_outputs) != _REPORT_STAGE_OUTPUTS:
            raise self._manifest_conflict(stage, "stage output contract is invalid")

    def _catalog_binding(self, stage: str, catalog_sha256: str | None) -> str | None:
        valid_digest = (
            type(catalog_sha256) is str
            and re.fullmatch(r"[0-9a-f]{64}", catalog_sha256) is not None
        )
        if stage in {"extract-prompt-tsg", "build-confirmation-variants"}:
            if not valid_digest:
                raise self._manifest_conflict(stage, "stage catalog binding is invalid")
            return catalog_sha256
        if catalog_sha256 is not None:
            raise self._manifest_conflict(stage, "stage catalog binding is invalid")
        return None

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

    def _stage_inputs_from_snapshot(
        self,
        paths: Sequence[str | Path],
        input_sha256: Sequence[str],
    ) -> dict[str, str]:
        try:
            digests = tuple(input_sha256)
        except (TypeError, ValueError):
            raise self._manifest_conflict(
                "run_store",
                "stage input snapshot is invalid",
            ) from None
        if len(digests) != len(paths):
            raise self._manifest_conflict(
                "run_store",
                "stage input snapshot is invalid",
            )
        inputs: dict[str, str] = {}
        for path_value, digest in zip(paths, digests, strict=True):
            try:
                relative_path = self._relative_path(
                    Path(path_value),
                    kind="input",
                    allow_outside=True,
                )
            except SecAwareError:
                raise self._manifest_conflict(
                    "run_store",
                    "stage input snapshot is invalid",
                ) from None
            if (
                relative_path in inputs
                or type(digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise self._manifest_conflict(
                    "run_store",
                    "stage input snapshot is invalid",
                )
            inputs[relative_path] = digest
        return inputs

    def _fingerprint_from_inputs(
        self,
        stage: str,
        inputs: dict[str, str],
        config: dict[str, object] | None = None,
        *,
        policy_sha256: str | None = None,
        catalog_sha256: str | None = None,
    ) -> str:
        policy_sha256 = self._policy_binding(stage, policy_sha256)
        catalog_sha256 = self._catalog_binding(stage, catalog_sha256)
        return build_stage_fingerprint(
            stage,
            inputs,
            self.config.model_dump(mode="json") if config is None else config,
            policy_sha256=policy_sha256,
            catalog_sha256=catalog_sha256,
            stage_contract_sha256=(
                PROMPT_TSG_STAGE_CONTRACT_SHA256
                if stage == "extract-prompt-tsg"
                else (
                    prompt_variant_stage_contract_sha256(stage)
                    or randomization_stage_contract_sha256(stage)
                    or confirmation_generation_stage_contract_sha256(stage, self.config.generation)
                    or confirmation_oracle_stage_contract_sha256(stage)
                    or functional_outcome_import_stage_contract_sha256(stage)
                    or functional_judge_stage_contract_sha256(stage)
                    or effect_stage_contract_sha256(stage)
                    or jci_stage_contract_sha256(stage)
                    or rfci_stage_contract_sha256(stage)
                    or report_stage_contract_sha256(stage)
                    or discovery_stage_contract_sha256(stage)
                )
            ),
            code_version=__version__,
        )

    def stage_fingerprint(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        *,
        policy_sha256: str | None = None,
        catalog_sha256: str | None = None,
    ) -> str:
        return self._fingerprint_from_inputs(
            stage,
            self.stage_inputs(input_paths),
            policy_sha256=policy_sha256,
            catalog_sha256=catalog_sha256,
        )

    @_synchronized
    def _require_committed(
        self,
        stage: str,
        output_paths: Sequence[str | Path],
        *,
        input_paths: Sequence[str | Path] | None,
        expected_catalog_sha256: str | None = None,
    ) -> dict[str, str]:
        temporary_lease = self._temporary_stage_lease(stage)
        valid = False
        committed_output_sha256: dict[str, str] = {}
        try:
            try:
                outputs = [Path(path) for path in output_paths]
                relative_outputs = [self._relative_path(path, kind="output") for path in outputs]
                self._validate_stage_output_contract(stage, relative_outputs)
                manifest = read_stage_manifest(self._manifest_path(stage))
                config = self.config.model_dump(mode="json")
                inputs = manifest.inputs if input_paths is None else self.stage_inputs(input_paths)
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
                    == self._fingerprint_from_inputs(
                        stage,
                        inputs,
                        config,
                        policy_sha256=manifest.policy_sha256,
                        catalog_sha256=manifest.catalog_sha256,
                    )
                    and manifest.catalog_sha256 == expected_catalog_sha256
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
        *,
        expected_catalog_sha256: str | None = None,
    ) -> dict[str, str]:
        """Require a complete committed stage with current inputs and outputs."""

        return self._require_committed(
            stage,
            output_paths,
            input_paths=input_paths,
            expected_catalog_sha256=expected_catalog_sha256,
        )

    def require_committed_output(
        self,
        stage: str,
        output_paths: Sequence[str | Path],
        *,
        expected_catalog_sha256: str | None = None,
    ) -> dict[str, str]:
        """Require a committed output without re-reading producer inputs."""

        return self._require_committed(
            stage,
            output_paths,
            input_paths=None,
            expected_catalog_sha256=expected_catalog_sha256,
        )

    @contextmanager
    def hold_dependency_stages(self, stages: Sequence[str]) -> Iterator[tuple[str, ...]]:
        """Hold a validated set of dependency stage leases in one total order."""

        if isinstance(stages, (str, bytes)):
            raise self._manifest_conflict(
                "dependency-stages",
                "dependency stage set failed validation",
            )
        try:
            requested = tuple(stages)
        except (TypeError, ValueError):
            raise self._manifest_conflict(
                "dependency-stages",
                "dependency stage set failed validation",
            ) from None
        if (
            not requested
            or len(requested) != len(set(requested))
            or any(
                type(stage) is not str or self._safe_stage_name(stage) != stage
                for stage in requested
            )
        ):
            raise self._manifest_conflict(
                "dependency-stages",
                "dependency stage set failed validation",
            )
        ordered = tuple(sorted(requested))
        leases: dict[str, _HeldDependencyLease] = {}
        with self._state_lock:
            for stage in ordered:
                if (
                    self._owned_stage_lease(stage) is not None
                    or self._owned_dependency_lease(stage) is not None
                ):
                    raise self._manifest_conflict(
                        stage,
                        "stage lease is already owned by this run store",
                    )
            try:
                for stage in ordered:
                    lease = _HeldDependencyLease(handle=self._open_stage_lease(stage))
                    self._held_dependency_leases[stage] = lease
                    leases[stage] = lease
            except BaseException:
                for acquired_stage in reversed(tuple(leases)):
                    self._release_dependency_lease(
                        acquired_stage,
                        expected=leases[acquired_stage],
                    )
                raise
        try:
            yield ordered
        finally:
            with self._state_lock:
                for stage in reversed(ordered):
                    self._release_dependency_lease(stage, expected=leases[stage])

    @contextmanager
    def hold_committed_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
        *,
        expected_catalog_sha256: str | None = None,
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
                expected_catalog_sha256=expected_catalog_sha256,
            )
            yield dict(output_sha256)
        finally:
            with self._state_lock:
                self._release_dependency_lease(stage, expected=lease)

    @contextmanager
    def hold_committed_output(
        self,
        stage: str,
        output_paths: Sequence[str | Path],
        *,
        expected_catalog_sha256: str | None = None,
    ) -> Iterator[dict[str, str]]:
        """Hold a producer lease while consuming its committed output snapshot."""

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
            output_sha256 = self.require_committed_output(
                stage,
                output_paths,
                expected_catalog_sha256=expected_catalog_sha256,
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
        *,
        policy_sha256: str | None = None,
        catalog_sha256: str | None = None,
        preserve_committed: bool = False,
        after_lease_acquired: Callable[[], None] | None = None,
        input_snapshot: Callable[[], Sequence[str]] | None = None,
        before_skip: Callable[[], None] | None = None,
    ) -> bool:
        policy_sha256 = self._policy_binding(stage, policy_sha256)
        catalog_sha256 = self._catalog_binding(stage, catalog_sha256)
        recovery_authorized = preserve_committed is True and callable(after_lease_acquired)
        transactional_stage = (
            recovery_authorized
            or stage.startswith("run-oracle-")
            or stage
            in {
                "discover",
                "assemble-causal-tables",
                "fci-discovery",
                "build-confirmation-variants",
                "randomize-confirmation",
                "generate-confirmation",
                "extract-prompt-tsg",
                "intervene",
                "confirm",
            }
        )
        if type(preserve_committed) is not bool or (preserve_committed and not transactional_stage):
            raise self._manifest_conflict(stage, "stage transaction mode is invalid")
        if after_lease_acquired is not None and not callable(after_lease_acquired):
            raise self._manifest_conflict(stage, "stage lease action is invalid")
        if input_snapshot is not None and not callable(input_snapshot):
            raise self._manifest_conflict(stage, "stage input snapshot is invalid")
        if before_skip is not None and not callable(before_skip):
            raise self._manifest_conflict(stage, "stage skip verification is invalid")
        if (
            stage in self._pending_snapshots
            or stage in self._sealed_outputs
            or self._owned_stage_lease(stage) is not None
            or self._owned_dependency_lease(stage) is not None
        ):
            raise self._manifest_conflict(stage, "stage execution is already active")
        self._acquire_stage_lease(stage)
        try:
            if after_lease_acquired is not None:
                after_lease_acquired()
            outputs = [Path(path) for path in output_paths]
            relative_outputs = [self._relative_path(path, kind="output") for path in outputs]
            self._validate_stage_output_contract(stage, relative_outputs)
            inputs = (
                self.stage_inputs(input_paths)
                if input_snapshot is None
                else self._stage_inputs_from_snapshot(input_paths, input_snapshot())
            )
            config = self.config.model_dump(mode="json")
            fingerprint = self._fingerprint_from_inputs(
                stage,
                inputs,
                config,
                policy_sha256=policy_sha256,
                catalog_sha256=catalog_sha256,
            )
            self._pending_snapshots[stage] = _StageSnapshot(
                stage=stage,
                inputs=tuple(sorted(inputs.items())),
                config_sha256=canonical_sha256(config),
                fingerprint=fingerprint,
                code_version=__version__,
                policy_sha256=policy_sha256,
                catalog_sha256=catalog_sha256,
                preserve_committed=preserve_committed,
                outputs=tuple(relative_outputs),
            )
            allows_skip = manifest_allows_skip(
                self._manifest_path(stage),
                fingerprint,
                outputs,
                force=force,
                policy_sha256=policy_sha256,
                catalog_sha256=catalog_sha256,
                manifest_outputs=relative_outputs,
            )
            if allows_skip:
                if before_skip is not None:
                    before_skip()
                self._clear_stage_state(stage)
                self._release_stage_lease(stage)
                return True
            if not preserve_committed:
                self._invalidate_stage_manifest(stage)
        except BaseException:
            self._clear_stage_state(stage)
            self._release_stage_lease(stage)
            raise
        return False

    @_synchronized
    def begin_stage_commit(self, stage: str) -> StageCommitLease:
        """Authorize manifest recording while retaining the owned execution lease."""

        snapshot = self._pending_snapshots.get(stage)
        handle = self._owned_stage_lease(stage)
        if (
            handle is None
            or snapshot is None
            or not snapshot.preserve_committed
            or stage in self._stage_commit_leases
            or stage in self._recorded_stage_commits
        ):
            raise self._manifest_conflict(stage, "deferred stage commit authorization is invalid")
        lease = StageCommitLease(
            stage=stage,
            owner=self._stage_commit_owner,
            handle=handle,
        )
        self._stage_commit_leases[stage] = lease
        return lease

    def _require_stage_commit_owner(self, lease: StageCommitLease) -> StageCommitLease:
        if type(lease) is not StageCommitLease or lease.owner is not self._stage_commit_owner:
            raise self._manifest_conflict("stage_commit", "stage commit lease is invalid")
        return lease

    def _require_stage_commit_lease(self, lease: StageCommitLease) -> StageCommitLease:
        trusted = self._require_stage_commit_owner(lease)
        if trusted.released:
            return trusted
        current_handle = self._stage_leases.get(trusted.stage)
        if self._stage_commit_leases.get(trusted.stage) is not trusted or (
            current_handle is not trusted.handle
            and not (current_handle is None and trusted.handle.closed)
        ):
            raise self._manifest_conflict("stage_commit", "stage commit lease is invalid")
        return trusted

    def _require_active_stage_commit_lease(
        self,
        lease: StageCommitLease,
    ) -> StageCommitLease:
        trusted = self._require_stage_commit_owner(lease)
        snapshot = self._pending_snapshots.get(trusted.stage)
        handle = self._stage_leases.get(trusted.stage)
        if (
            trusted.released
            or self._stage_commit_leases.get(trusted.stage) is not trusted
            or snapshot is None
            or snapshot.stage != trusted.stage
            or not snapshot.preserve_committed
            or handle is not trusted.handle
            or handle.closed
        ):
            raise self._manifest_conflict("stage_commit", "stage commit lease is invalid")
        return trusted

    def _complete_stage_commit_release(self, lease: StageCommitLease) -> None:
        current_handle = self._stage_leases.get(lease.stage)
        if current_handle is not None and current_handle is not lease.handle:
            raise self._manifest_conflict(
                lease.stage,
                "stage commit lease is invalid",
            )
        if not lease.handle.closed:
            raise self._manifest_conflict(
                lease.stage,
                "stage commit lease is still active",
            )
        if current_handle is lease.handle:
            self._stage_leases.pop(lease.stage, None)
        if self._stage_commit_leases.get(lease.stage) is lease:
            self._clear_stage_commit(lease.stage)
        object.__setattr__(lease, "released", True)

    def _ensure_stage_commit_released(
        self,
        lease: StageCommitLease,
        *,
        require_recorded: bool,
    ) -> None:
        trusted = self._require_stage_commit_lease(lease)
        if trusted.released:
            return
        if require_recorded and trusted.stage not in self._recorded_stage_commits:
            raise self._manifest_conflict(
                trusted.stage,
                "deferred stage commit was not recorded",
            )
        for _ in range(3):
            handle = self._stage_leases.get(trusted.stage)
            if handle is None or handle.closed:
                self._complete_stage_commit_release(trusted)
                return
            try:
                self._release_stage_handle(handle)
            except (MemoryError, KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                continue
            if handle.closed:
                self._complete_stage_commit_release(trusted)
                return
        raise self._manifest_conflict(
            trusted.stage,
            "stage commit lease could not be released",
        )

    @_synchronized
    def finalize_stage_commit(self, lease: StageCommitLease) -> None:
        """Release one recorded transactional stage only after its external commit point."""

        self._ensure_stage_commit_released(lease, require_recorded=True)

    @_synchronized
    def ensure_stage_commit_released(self, lease: StageCommitLease) -> None:
        """Idempotently finish a recorded commit release after interrupted finalization."""

        self._ensure_stage_commit_released(lease, require_recorded=True)

    @_synchronized
    def record_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
        *,
        policy_sha256: str | None = None,
        catalog_sha256: str | None = None,
        lease: StageCommitLease | None = None,
        input_snapshot_sha256: Sequence[str] | None = None,
    ) -> None:
        trusted_lease: StageCommitLease | None = None
        if lease is not None:
            trusted_lease = self._require_active_stage_commit_lease(lease)
            if trusted_lease.stage != stage:
                raise self._manifest_conflict(stage, "stage commit lease does not match")
        else:
            snapshot = self._pending_snapshots.get(stage)
            if stage in self._stage_commit_leases or (
                snapshot is not None and snapshot.preserve_committed
            ):
                raise self._manifest_conflict(
                    stage,
                    "transactional stage recording requires an owned commit lease",
                )
        recorded = False
        try:
            self._record_stage(
                stage,
                input_paths,
                output_paths,
                policy_sha256=policy_sha256,
                catalog_sha256=catalog_sha256,
                input_snapshot_sha256=input_snapshot_sha256,
            )
            recorded = True
            if trusted_lease is not None:
                self._recorded_stage_commits.add(stage)
        finally:
            if trusted_lease is None:
                if not recorded:
                    self._clear_stage_state(stage)
                self._release_stage_lease(stage)

    def _record_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
        *,
        policy_sha256: str | None,
        catalog_sha256: str | None,
        input_snapshot_sha256: Sequence[str] | None,
    ) -> None:
        policy_sha256 = self._policy_binding(stage, policy_sha256)
        catalog_sha256 = self._catalog_binding(stage, catalog_sha256)
        if self._requires_output_seal(stage) or stage in self._sealed_outputs:
            self.verify_sealed_outputs(stage, output_paths)
        outputs = [Path(path) for path in output_paths]
        snapshot = self._pending_snapshots.get(stage)
        output_seal = self._sealed_outputs.get(stage)
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
            inputs = (
                self.stage_inputs(input_paths)
                if input_snapshot_sha256 is None
                else self._stage_inputs_from_snapshot(input_paths, input_snapshot_sha256)
            )
        except SecAwareError:
            self._reject_stage_record(stage, "stage inputs changed during execution")
        config = self.config.model_dump(mode="json")
        current_config_sha256 = canonical_sha256(config)
        current_fingerprint = self._fingerprint_from_inputs(
            stage,
            inputs,
            config,
            policy_sha256=policy_sha256,
            catalog_sha256=catalog_sha256,
        )
        if (
            snapshot.inputs != tuple(sorted(inputs.items()))
            or snapshot.config_sha256 != current_config_sha256
            or snapshot.fingerprint != current_fingerprint
            or snapshot.code_version != __version__
            or snapshot.policy_sha256 != policy_sha256
            or snapshot.catalog_sha256 != catalog_sha256
            or snapshot.outputs != tuple(relative_outputs)
        ):
            self._reject_stage_record(
                stage,
                "stage inputs or configuration changed during execution",
            )
        current_output_sha256 = self._stage_output_hashes(stage, outputs, relative_outputs)
        output_sha256 = (
            dict(output_seal.output_sha256) if output_seal is not None else current_output_sha256
        )
        if current_output_sha256 != output_sha256:
            self._reject_stage_record(
                stage,
                "sealed stage outputs changed before the manifest was committed",
            )
        manifest_path = self._manifest_path(stage)
        expected_manifest = StageManifest(
            schema_version=SCHEMA_VERSION,
            stage=snapshot.stage,
            fingerprint=snapshot.fingerprint,
            inputs=dict(snapshot.inputs),
            config_sha256=snapshot.config_sha256,
            code_version=snapshot.code_version,
            policy_sha256=snapshot.policy_sha256,
            catalog_sha256=snapshot.catalog_sha256,
            outputs=list(snapshot.outputs),
            output_sha256=output_sha256,
        )
        manifest_committed = False
        try:
            write_stage_manifest(manifest_path, expected_manifest)
            if read_stage_manifest(manifest_path) != expected_manifest:
                raise ValueError("stage manifest readback mismatch")
        except (OSError, SecAwareError, TypeError, UnicodeError, ValueError):
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
        self._pending_snapshots.pop(stage, None)
        self._sealed_outputs.pop(stage, None)
