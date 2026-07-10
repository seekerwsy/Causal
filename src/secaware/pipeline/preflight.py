import hashlib

from secaware.config import AppConfig
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

    return PreflightReport(
        prompt_count=len(prompts),
        discover_count=sum(prompt.split == "discover" for prompt in prompts),
        confirm_count=sum(prompt.split == "confirm" for prompt in prompts),
        model_count=len(models),
        seed_count=len(seeds),
        output_dir=config.run.output_dir,
    )
