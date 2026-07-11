from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal
from urllib.parse import SplitResult, urlsplit, urlunsplit

import yaml
from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import SafeValidationMixin, StrictModel
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
    random_seed: int = 123
    output_dir: str = "runs/demo"


class DataConfig(StrictModel):
    prompts_path: str


class TSGConfig(StrictModel):
    prompt_extractor: str = "rule_based_v0"
    code_extractor: str = "python_ast_v0"


class DiscoveryConfig(StrictModel):
    min_support_total: int = 4
    min_support_each_side: int = 1
    top_k_per_scope: int = 2
    score_weights: dict[str, float] = Field(default_factory=dict)


class InterventionConfig(StrictModel):
    enabled_directions: list[str] = Field(default_factory=lambda: ["risk_down"])
    max_hypotheses: int = 5
    allow_side_effects_for_directional: bool = True


class OpenAICompatibleConfig(SafeValidationMixin, StrictModel):
    _safe_validation_message = (
        "OpenAI-compatible provider configuration failed validation"
    )

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
    file_provider_dir: str | None = None
    openai_compatible: OpenAICompatibleConfig | None = None


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
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    intervention: InterventionConfig = Field(default_factory=InterventionConfig)
    generation: GenerationConfig = Field(default_factory=GenerationConfig)
    oracle: OracleConfig = Field(default_factory=OracleConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)


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
