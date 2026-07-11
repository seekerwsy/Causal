import hashlib
import os
from pathlib import Path

from secaware.config import AppConfig, OpenAICompatibleConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.schema.common import StrictModel
from secaware.schema.records import PromptRecord


class PreflightReport(StrictModel):
    prompt_count: int
    discover_count: int
    confirm_count: int
    model_count: int
    seed_count: int
    output_dir: str


def _error(code: ErrorCode, message: str) -> SecAwareError:
    return SecAwareError(code=code, stage="preflight", message=message)


def _normalized_prompt_sha256(prompt: str) -> str:
    normalized = " ".join(prompt.strip().split()).lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def run_preflight(config: AppConfig) -> PreflightReport:
    if config.generation.provider == "openai_compatible":
        provider_config: OpenAICompatibleConfig | None = None
        try:
            provider_config = OpenAICompatibleConfig.model_validate(
                config.generation.openai_compatible
            )
        except Exception:
            pass
        if provider_config is None:
            raise _error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider configuration is unavailable",
            ) from None
        try:
            credential = os.environ.get(provider_config.api_key_env)
            credential_available = (
                type(credential) is str and bool(credential.strip())
            )
        except Exception:
            credential_available = False
        credential = None
        if not credential_available:
            raise _error(
                ErrorCode.API_AUTH,
                "provider authentication is unavailable",
            )

    prompts = read_jsonl(
        config.data.prompts_path,
        PromptRecord,
        required=True,
        allow_empty=False,
        stage="preflight",
    )
    prompt_ids = [prompt.prompt_id for prompt in prompts]
    if len(set(prompt_ids)) != len(prompt_ids):
        raise _error(ErrorCode.CONTRACT, "prompt_id values must be unique")

    discover_hashes = {
        _normalized_prompt_sha256(prompt.prompt)
        for prompt in prompts
        if prompt.split == "discover"
    }
    confirm_hashes = {
        _normalized_prompt_sha256(prompt.prompt)
        for prompt in prompts
        if prompt.split == "confirm"
    }
    if discover_hashes & confirm_hashes:
        raise _error(
            ErrorCode.CONTRACT,
            "discover and confirm prompts must not have identical normalized text",
        )

    models = config.generation.models
    if not models:
        raise _error(ErrorCode.CONFIG, "generation.models must not be empty")
    if len(set(models)) != len(models):
        raise _error(ErrorCode.CONFIG, "generation.models must not contain duplicates")

    seeds = config.generation.seeds
    if not seeds:
        raise _error(ErrorCode.CONFIG, "generation.seeds must not be empty")
    if len(set(seeds)) != len(seeds):
        raise _error(ErrorCode.CONFIG, "generation.seeds must not contain duplicates")

    if config.generation.provider == "file":
        provider_dir = config.generation.file_provider_dir
        if provider_dir is None or not provider_dir.strip():
            raise _error(
                ErrorCode.CONFIG,
                "generation.file_provider_dir is required for the file provider",
            )
        provider_path = Path(provider_dir)
        if not provider_path.is_dir():
            raise SecAwareError(
                code=ErrorCode.CONTRACT,
                stage="preflight",
                message="file provider directory is unavailable",
                details={"path": str(provider_path)},
            )

    return PreflightReport(
        prompt_count=len(prompts),
        discover_count=sum(prompt.split == "discover" for prompt in prompts),
        confirm_count=sum(prompt.split == "confirm" for prompt in prompts),
        model_count=len(models),
        seed_count=len(seeds),
        output_dir=config.run.output_dir,
    )
