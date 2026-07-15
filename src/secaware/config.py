from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal
from urllib.parse import SplitResult, urlsplit, urlunsplit
import unicodedata

import yaml
from pydantic import ConfigDict, Field, StrictInt, ValidationError, field_validator, model_validator

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.experiments import (
    InterventionExecutorKind,
    InterventionMode,
)
from secaware.schema.features import FeatureOperation
from secaware.schema.generation import GenerationParameters


MAX_SYSTEM_TEMPLATE_CHARS = 65_536


def _normalized_base_url(parsed: SplitResult) -> str:
    scheme = parsed.scheme.casefold()
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("base URL hostname is unavailable")
    normalized_host = hostname.casefold()
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    port = parsed.port
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        normalized_host = f"{normalized_host}:{port}"
    path = parsed.path.rstrip("/")
    return urlunsplit((scheme, normalized_host, path, "", ""))


class RunConfig(StrictModel):
    name: str = "demo"
    random_seed: int = Field(default=123, ge=-(2**63), le=2**63 - 1, strict=True)
    output_dir: str = "runs/demo"


class DataConfig(StrictModel):
    prompts_path: str
    prompt_attestations_path: str = Field(min_length=1)
    functional_outcome_contracts_path: str | None = Field(default=None, min_length=1)


class PromptExtractorLLMConfig(SafeValidationMixin, StrictModel):
    _safe_validation_message = "prompt extractor LLM configuration failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    provider: Literal["openai_compatible"] = "openai_compatible"
    model_id: str = Field(min_length=1, max_length=256)
    base_url: str = Field(min_length=1, max_length=2048, repr=False)
    api_key_env: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
        repr=False,
    )
    timeout_seconds: float = Field(gt=0.0, le=3600.0)
    max_attempts: int = Field(ge=1, le=10)
    max_response_bytes: int = Field(ge=1024, le=1_048_576)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    top_p: float = Field(default=1.0, gt=0.0, le=1.0)
    seed: int | None = Field(default=0, ge=-(2**63), le=2**63 - 1)

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str) -> str:
        try:
            if not value.strip() or value != value.strip():
                raise ValueError
            if any(unicodedata.category(character).startswith("C") for character in value):
                raise ValueError
            value.encode("utf-8")
        except Exception:
            raise ValueError(cls._safe_validation_message) from None
        return value

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        try:
            if value != value.strip() or "\\" in value or "?" in value or "#" in value:
                raise ValueError
            if any(
                character.isspace() or unicodedata.category(character).startswith("C")
                for character in value
            ):
                raise ValueError
            parsed = urlsplit(value)
            if parsed.scheme.casefold() not in {"http", "https"}:
                raise ValueError
            if not parsed.netloc or parsed.hostname is None:
                raise ValueError
            if parsed.username is not None or parsed.password is not None:
                raise ValueError
            if parsed.query or parsed.fragment:
                raise ValueError
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError
        except Exception:
            raise ValueError(cls._safe_validation_message) from None
        return _normalized_base_url(parsed)


class TSGConfig(StrictModel):
    prompt_extractor: PromptExtractorBackend = PromptExtractorBackend.LLM_FACTS_V1
    llm: PromptExtractorLLMConfig | None = None


class FCIDiscoveryConfig(SafeValidationMixin, StrictModel):
    _safe_validation_message = "FCI discovery configuration failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    backend: Literal["causal_learn_fci_v1"] = "causal_learn_fci_v1"
    backend_version: Literal["0.1.4.7"] = "0.1.4.7"
    ci_test: Literal["gsq"] = "gsq"
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0, allow_inf_nan=False)
    depth: int = Field(default=3, ge=0, le=8)
    max_path_length: int = Field(default=6, ge=1, le=16)
    timeout_seconds: float = Field(default=120.0, gt=0.0, le=3600.0, allow_inf_nan=False)
    max_variables: int = Field(default=64, ge=2, le=64)
    max_rows: int = Field(default=100_000, ge=2, le=100_000)
    bootstrap_samples: int = Field(default=200, ge=1, le=10_000)
    stability_threshold: float = Field(default=0.80, gt=0.0, le=1.0, allow_inf_nan=False)
    max_candidate_paths: int = Field(default=512, ge=1, le=4096)
    min_independent_tasks: int = Field(default=20, ge=2, le=100_000)
    max_failed_bootstrap_fraction: float = Field(
        default=0.10,
        ge=0.0,
        lt=1.0,
        allow_inf_nan=False,
    )


class InterventionLLMConfig(SafeValidationMixin, StrictModel):
    """Executor-only provider policy; never shared with Prompt extraction."""

    _safe_validation_message = "intervention LLM configuration failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    model_id: str = Field(min_length=1, max_length=256)
    base_url: str = Field(min_length=1, max_length=2048, repr=False)
    api_key_env: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
        repr=False,
    )
    timeout_seconds: float = Field(default=60.0, gt=0.0, le=3600.0)
    max_attempts: int = Field(default=3, ge=1, le=10)
    max_response_bytes: int = Field(default=262_144, ge=1024, le=1_048_576)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    top_p: float = Field(default=1.0, gt=0.0, le=1.0)
    seed: int | None = Field(default=0, ge=-(2**63), le=2**63 - 1)

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str) -> str:
        try:
            if not value.strip() or value != value.strip():
                raise ValueError
            if any(unicodedata.category(character).startswith("C") for character in value):
                raise ValueError
            value.encode("utf-8")
        except Exception:
            raise ValueError(cls._safe_validation_message) from None
        return value

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        try:
            if value != value.strip() or "\\" in value or "?" in value or "#" in value:
                raise ValueError
            if any(
                character.isspace() or unicodedata.category(character).startswith("C")
                for character in value
            ):
                raise ValueError
            parsed = urlsplit(value)
            if parsed.scheme.casefold() not in {"http", "https"}:
                raise ValueError
            if not parsed.netloc or parsed.hostname is None:
                raise ValueError
            if parsed.username is not None or parsed.password is not None:
                raise ValueError
            if parsed.query or parsed.fragment:
                raise ValueError
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError
        except Exception:
            raise ValueError(cls._safe_validation_message) from None
        return _normalized_base_url(parsed)


class InterventionConfig(StrictModel):
    """Run-wide, finite prompt-intervention executor coordinates."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    mode: InterventionMode = InterventionMode.TEXT_NATIVE
    # AppConfig validation is fail-closed: LLM requires a complete policy, while
    # deterministic execution must be selected explicitly.
    executor: InterventionExecutorKind = InterventionExecutorKind.LLM
    llm: InterventionLLMConfig | None = None
    operations: tuple[FeatureOperation, ...] = (
        FeatureOperation.ADD,
        FeatureOperation.REMOVE,
    )
    max_protocols: int = Field(default=64, ge=1, le=512)
    max_protocol_instances: int = Field(default=256, ge=1, le=4096)
    max_arm_executions: int = Field(default=2048, ge=1, le=32768)

    @field_validator("mode", mode="before")
    @classmethod
    def parse_mode(cls, value: object) -> object:
        if type(value) is str:
            for mode in InterventionMode:
                if value == mode.value:
                    return mode
        return value

    @field_validator("executor", mode="before")
    @classmethod
    def parse_executor(cls, value: object) -> object:
        if type(value) is str:
            for executor in InterventionExecutorKind:
                if value == executor.value:
                    return executor
        return value

    @field_validator("operations", mode="before")
    @classmethod
    def parse_operations(cls, value: object) -> object:
        if type(value) not in {list, tuple}:
            return value
        result: list[object] = []
        for item in value:
            if type(item) is str:
                matched = next(
                    (operation for operation in FeatureOperation if item == operation.value),
                    item,
                )
                result.append(matched)
            else:
                result.append(item)
        return tuple(result)

    @model_validator(mode="after")
    def validate_closed_coordinates(self) -> "InterventionConfig":
        if (
            not self.operations
            or len(self.operations) != len(set(self.operations))
            or any(
                operation not in {FeatureOperation.ADD, FeatureOperation.REMOVE}
                for operation in self.operations
            )
        ):
            raise ValueError("intervention configuration failed validation")
        return self

    # Temporary read-only bridges for direct legacy functions retained until M5 Task 8.
    @property
    def enabled_directions(self) -> tuple[str, ...]:
        return ("risk_down",)

    @property
    def max_hypotheses(self) -> int:
        return self.max_protocols

    @property
    def allow_side_effects_for_directional(self) -> bool:
        return True


class OpenAICompatibleConfig(SafeValidationMixin, StrictModel):
    _safe_validation_message = "OpenAI-compatible provider configuration failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    base_url: str = Field(min_length=1, max_length=2048, repr=False)
    api_key_env: str = Field(
        default="OPENAI_API_KEY",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
        repr=False,
    )
    timeout_seconds: float = Field(default=60.0, gt=0.0, le=3600.0)
    max_attempts: int = Field(default=3, ge=1, le=10)
    initial_backoff_seconds: float = Field(default=1.0, ge=0.0, le=300.0)
    max_backoff_seconds: float = Field(default=30.0, ge=0.0, le=3600.0)
    system_template: str = Field(
        default="",
        max_length=MAX_SYSTEM_TEMPLATE_CHARS,
        repr=False,
    )
    system_template_version: str = Field(
        default="none",
        min_length=1,
        max_length=128,
    )
    parameters: GenerationParameters = Field(default_factory=GenerationParameters)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        try:
            if value != value.strip() or "\\" in value or "?" in value or "#" in value:
                raise ValueError
            if any(
                character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
                for character in value
            ):
                raise ValueError
            parsed = urlsplit(value)
            if parsed.scheme.casefold() not in {"http", "https"}:
                raise ValueError
            if not parsed.netloc or parsed.hostname is None:
                raise ValueError
            if parsed.username is not None or parsed.password is not None:
                raise ValueError
            if parsed.query or parsed.fragment:
                raise ValueError
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError
        except Exception:
            raise ValueError(cls._safe_validation_message) from None
        return _normalized_base_url(parsed)

    @field_validator("system_template")
    @classmethod
    def validate_system_template(cls, value: str) -> str:
        try:
            if type(value) is not str:
                raise TypeError
        except Exception:
            raise ValueError(cls._safe_validation_message) from None
        return value

    @field_validator("system_template_version")
    @classmethod
    def validate_system_template_version(cls, value: str) -> str:
        try:
            if type(value) is not str or not value.strip() or value != value.strip():
                raise ValueError
        except Exception:
            raise ValueError(cls._safe_validation_message) from None
        return value

    @model_validator(mode="after")
    def validate_backoff_range(self) -> "OpenAICompatibleConfig":
        if self.max_backoff_seconds < self.initial_backoff_seconds:
            raise ValueError(self._safe_validation_message)
        return self


class GenerationConfig(StrictModel):
    provider: Literal["mock", "file", "api", "openai_compatible"] = "mock"
    models: list[str] = Field(default_factory=lambda: ["mock-secaware-v0"])
    seeds: list[int] = Field(default_factory=lambda: [1])
    confirmation_seeds: list[StrictInt] = Field(default_factory=lambda: list(range(101, 113)))
    file_provider_dir: str | None = None
    openai_compatible: OpenAICompatibleConfig | None = None
    confirmation_max_requests: StrictInt = Field(default=10_000, ge=1, le=100_000)
    confirmation_max_attempts_per_request: StrictInt = Field(default=3, ge=1, le=10)
    confirmation_max_total_provider_attempts: StrictInt = Field(default=30_000, ge=1, le=1_000_000)
    confirmation_max_tokens_per_request: StrictInt = Field(default=65_536, ge=1, le=262_144)
    confirmation_max_stop_items: StrictInt = Field(default=64, ge=1, le=1_024)
    confirmation_max_stop_item_chars: StrictInt = Field(default=4_096, ge=1, le=65_536)
    confirmation_max_stop_total_chars: StrictInt = Field(default=16_384, ge=1, le=262_144)
    confirmation_max_parameters_bytes: StrictInt = Field(default=65_536, ge=1, le=1_048_576)
    confirmation_max_total_prompt_bytes: StrictInt = Field(
        default=64 * 1024 * 1024, ge=1_024, le=240 * 1024 * 1024
    )
    confirmation_max_prompt_bytes_per_request: StrictInt = Field(
        default=4 * 1024 * 1024, ge=1, le=240 * 1024 * 1024
    )
    confirmation_max_code_bytes_per_result: StrictInt = Field(
        default=1_048_576, ge=1, le=3 * 1024 * 1024
    )
    confirmation_max_total_code_bytes: StrictInt = Field(
        default=32 * 1024 * 1024, ge=1, le=240 * 1024 * 1024
    )
    confirmation_max_projected_jsonl_bytes: StrictInt = Field(
        default=240 * 1024 * 1024, ge=1_024, le=240 * 1024 * 1024
    )
    confirmation_max_timeout_seconds_per_attempt: float = Field(default=300.0, gt=0, le=3600)
    confirmation_max_worst_case_wait_seconds: float = Field(default=86_400.0, gt=0, le=86_400)

    @field_validator("confirmation_seeds")
    @classmethod
    def validate_confirmation_seeds(cls, value: list[int]) -> list[int]:
        if (
            not value
            or len(value) > 100_000
            or len(value) != len(set(value))
            or any(type(seed) is not int or not -(2**63) <= seed <= 2**63 - 1 for seed in value)
        ):
            raise ValueError("confirmation seed configuration failed validation")
        return value

    @model_validator(mode="after")
    def validate_disjoint_seed_namespaces(self) -> "GenerationConfig":
        if set(self.seeds) & set(self.confirmation_seeds):
            raise ValueError("generation seed namespaces must be disjoint")
        if (
            self.confirmation_max_stop_total_chars < self.confirmation_max_stop_item_chars
            or self.confirmation_max_total_prompt_bytes
            < self.confirmation_max_prompt_bytes_per_request
            or self.confirmation_max_total_code_bytes < self.confirmation_max_code_bytes_per_result
        ):
            raise ValueError("confirmation generation resource configuration failed validation")
        provider = self.openai_compatible
        if provider is not None:
            worst_backoff = sum(
                min(
                    provider.initial_backoff_seconds * (2**index),
                    provider.max_backoff_seconds,
                )
                for index in range(max(0, provider.max_attempts - 1))
            )
            worst_wait = provider.max_attempts * provider.timeout_seconds + worst_backoff
            if (
                provider.max_attempts > self.confirmation_max_attempts_per_request
                or provider.timeout_seconds > self.confirmation_max_timeout_seconds_per_attempt
                or worst_wait > self.confirmation_max_worst_case_wait_seconds
            ):
                raise ValueError("confirmation generation resource configuration failed validation")
        return self


class RandomizationConfig(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    rng_version: Literal["sha256-rejection-fisher-yates-v1"] = "sha256-rejection-fisher-yates-v1"
    max_blocks: int = Field(default=10_000, ge=1, le=100_000, strict=True)
    min_independent_tasks_per_semantic_protocol: int = Field(
        default=20,
        ge=2,
        le=100_000,
        strict=True,
    )


class OracleConfig(SafeValidationMixin, StrictModel):
    _safe_validation_message = "oracle configuration failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    language: Literal["python"] = "python"
    policy_lock_path: str = Field(
        default="policies/oracle/python/policy.lock.json",
        min_length=1,
        max_length=4096,
        repr=False,
    )
    semgrep_executable: str = Field(
        default="semgrep",
        min_length=1,
        max_length=1024,
        repr=False,
    )
    bandit_executable: str = Field(
        default="bandit",
        min_length=1,
        max_length=1024,
        repr=False,
    )
    timeout_seconds: float = Field(default=120.0, gt=0.0, le=3600.0)
    max_stdout_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=1024,
        le=256 * 1024 * 1024,
    )
    max_stderr_bytes: int = Field(
        default=4 * 1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
    )

    @field_validator(
        "policy_lock_path",
        "semgrep_executable",
        "bandit_executable",
    )
    @classmethod
    def validate_nonempty_path(cls, value: str) -> str:
        try:
            if value != value.strip() or not value.strip():
                raise ValueError
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
                raise ValueError
        except Exception:
            raise ValueError(cls._safe_validation_message) from None
        return value


class AnalysisConfig(StrictModel):
    bootstrap_samples: int = 200
    ci_level: float = 0.95
    min_eligible_pairs: int = 2
    min_flip_rate: float = 0.05
    max_side_effect_rate_confirmed: float = 0.10


class AppConfig(StrictModel):
    run: RunConfig
    data: DataConfig
    tsg: TSGConfig = Field(default_factory=TSGConfig)
    discovery: FCIDiscoveryConfig = Field(default_factory=FCIDiscoveryConfig)
    intervention: InterventionConfig
    generation: GenerationConfig = Field(default_factory=GenerationConfig)
    randomization: RandomizationConfig = Field(default_factory=RandomizationConfig)
    oracle: OracleConfig = Field(default_factory=OracleConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)

    @model_validator(mode="after")
    def validate_prompt_extractor_coordinates(self) -> "AppConfig":
        llm_backend = self.tsg.prompt_extractor in {
            PromptExtractorBackend.LLM_FACTS_V1,
            PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
        }
        if llm_backend != (self.tsg.llm is not None):
            raise ValueError("prompt extractor configuration failed validation")
        llm_executor = self.intervention.executor is InterventionExecutorKind.LLM
        if llm_executor != (self.intervention.llm is not None):
            raise ValueError("intervention executor configuration failed validation")
        return self


def _config_error(path: Path) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONFIG,
        stage="config",
        message="configuration could not be loaded",
        details={"path": str(path)},
        retryable=False,
    )


def load_config(path: str | Path, *, run_dir: str | Path | None = None) -> AppConfig:
    config_path = Path(path)
    raw: Any = None
    load_failed = False
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except (OSError, UnicodeError, yaml.YAMLError):
        load_failed = True
    if load_failed:
        raise _config_error(config_path) from None
    if not isinstance(raw, Mapping):
        raise _config_error(config_path) from None
    config: AppConfig | None = None
    try:
        config = AppConfig.model_validate(dict(raw))
        if run_dir is not None:
            resolved = config.model_dump(mode="json")
            resolved["run"]["output_dir"] = str(run_dir)
            config = AppConfig.model_validate(resolved)
    except ValidationError:
        config = None
    if config is None:
        raw = None
        raise _config_error(config_path) from None
    return config


def write_resolved_config(config: AppConfig, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config.model_dump(mode="json"), handle, sort_keys=False)
