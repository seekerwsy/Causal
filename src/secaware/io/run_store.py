import re
import shutil
from collections.abc import Sequence
from pathlib import Path

from secaware import __version__
from secaware.config import AppConfig, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.pipeline.manifest import (
    StageManifest,
    build_stage_fingerprint,
    manifest_allows_skip,
    write_stage_manifest,
)
from secaware.schema.common import SCHEMA_VERSION


class RunStore:
    def __init__(self, config: AppConfig):
        self.config = config
        self.root = Path(config.run.output_dir)

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

    def _relative_path(self, path: str | Path, *, kind: str) -> str:
        candidate = Path(path)
        try:
            relative = candidate.resolve().relative_to(self.root.resolve())
        except (OSError, ValueError):
            raise self._contract_error(
                f"{kind} path must remain within the run directory",
                candidate,
            ) from None
        return relative.as_posix()

    def _manifest_path(self, stage: str) -> Path:
        safe_stage = re.sub(r"[^A-Za-z0-9._-]+", "-", stage).strip(".-_") or "stage"
        return self.path(".stages", f"{safe_stage}.json")

    def stage_inputs(self, paths: Sequence[str | Path]) -> dict[str, str]:
        inputs: dict[str, str] = {}
        for path_value in paths:
            path = Path(path_value)
            if not path.is_file():
                raise self._contract_error("required stage input is missing", path)
            relative_path = self._relative_path(path, kind="input")
            try:
                inputs[relative_path] = sha256_file(path)
            except OSError:
                raise self._contract_error("required stage input could not be read", path) from None
        return inputs

    def _fingerprint_from_inputs(self, stage: str, inputs: dict[str, str]) -> str:
        return build_stage_fingerprint(
            stage,
            inputs,
            self.config.model_dump(mode="json"),
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
        if force:
            return False
        outputs = [Path(path) for path in output_paths]
        relative_outputs = [self._relative_path(path, kind="output") for path in outputs]
        fingerprint = self.stage_fingerprint(stage, input_paths)
        return manifest_allows_skip(
            self._manifest_path(stage),
            fingerprint,
            outputs,
            manifest_outputs=relative_outputs,
        )

    def record_stage(
        self,
        stage: str,
        input_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
    ) -> None:
        inputs = self.stage_inputs(input_paths)
        outputs = [Path(path) for path in output_paths]
        if not outputs:
            raise self._contract_error("stage must declare at least one output", self.root)
        relative_outputs = [self._relative_path(path, kind="output") for path in outputs]
        for output in outputs:
            if not output.is_file():
                raise self._contract_error("declared stage output is missing", output)
        config = self.config.model_dump(mode="json")
        write_stage_manifest(
            self._manifest_path(stage),
            StageManifest(
                schema_version=SCHEMA_VERSION,
                stage=stage,
                fingerprint=self._fingerprint_from_inputs(stage, inputs),
                inputs=inputs,
                config_sha256=canonical_sha256(config),
                code_version=__version__,
                outputs=relative_outputs,
            ),
        )
