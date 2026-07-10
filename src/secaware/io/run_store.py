import os
import re
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from secaware import __version__
from secaware.config import AppConfig, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.manifest import (
    StageManifest,
    build_stage_fingerprint,
    manifest_allows_skip,
    write_stage_manifest,
)
from secaware.schema.common import SCHEMA_VERSION


@dataclass(frozen=True)
class _StageSnapshot:
    stage: str
    inputs: tuple[tuple[str, str], ...]
    config_sha256: str
    fingerprint: str
    code_version: str
    outputs: tuple[str, ...]


class RunStore:
    def __init__(self, config: AppConfig):
        self.config = config
        self.root = Path(config.run.output_dir)
        self._pending_snapshots: dict[str, _StageSnapshot] = {}

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
        self.mkdirs()
        prompts_src = Path(self.config.data.prompts_path)
        shutil.copyfile(prompts_src, self.path("inputs", "prompts.jsonl"))
        write_resolved_config(self.config, self.path("config.resolved.yaml"))

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
            if allow_outside:
                relative = Path(os.path.relpath(resolved, resolved_root))
            else:
                relative = resolved.relative_to(resolved_root)
        except (OSError, ValueError):
            raise self._contract_error(
                f"{kind} path must remain within the run directory",
                candidate,
            ) from None
        return relative.as_posix()

    def _manifest_path(self, stage: str) -> Path:
        safe_stage = re.sub(r"[^A-Za-z0-9._-]+", "-", stage).strip(".-_") or "stage"
        return self.path(".stages", f"{safe_stage}.json")

    def _invalidate_stage_manifest(self, stage: str) -> None:
        try:
            self._manifest_path(stage).unlink(missing_ok=True)
        except OSError:
            raise self._manifest_conflict(
                stage,
                "stage manifest could not be invalidated",
            ) from None

    def _reject_stage_record(self, stage: str, message: str) -> None:
        self._invalidate_stage_manifest(stage)
        raise self._manifest_conflict(stage, message)

    def stage_inputs(self, paths: Sequence[str | Path]) -> dict[str, str]:
        inputs: dict[str, str] = {}
        for path_value in paths:
            path = Path(path_value)
            if not path.exists():
                raise self._contract_error("required stage input is missing", path)
            relative_path = self._relative_path(path, kind="input", allow_outside=True)
            try:
                inputs[relative_path] = sha256_path(path)
            except (OSError, ValueError):
                raise self._contract_error("required stage input could not be read", path) from None
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

    def should_skip_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
        force: bool,
    ) -> bool:
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
            return True
        try:
            self._invalidate_stage_manifest(stage)
        except SecAwareError:
            self._pending_snapshots.pop(stage, None)
            raise
        return False

    def record_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
    ) -> None:
        outputs = [Path(path) for path in output_paths]
        if not outputs:
            raise self._contract_error("stage must declare at least one output", self.root)
        relative_outputs = [self._relative_path(path, kind="output") for path in outputs]
        for output in outputs:
            if not output.is_file():
                raise self._contract_error("declared stage output is missing", output)
        snapshot = self._pending_snapshots.pop(stage, None)
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
        write_stage_manifest(
            self._manifest_path(stage),
            StageManifest(
                schema_version=SCHEMA_VERSION,
                stage=snapshot.stage,
                fingerprint=snapshot.fingerprint,
                inputs=dict(snapshot.inputs),
                config_sha256=snapshot.config_sha256,
                code_version=snapshot.code_version,
                outputs=list(snapshot.outputs),
            ),
        )
