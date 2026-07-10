from pathlib import Path
from typing import Any

import yaml
from pydantic import Field

from secaware.schema.common import StrictModel


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


class GenerationConfig(StrictModel):
    provider: str = "mock"
    models: list[str] = Field(default_factory=lambda: ["mock-secaware-v0"])
    seeds: list[int] = Field(default_factory=lambda: [1])
    file_provider_dir: str | None = None


class OracleConfig(StrictModel):
    language: str = "python"
    policy_name: str = "python_static_v0"
    use_lightweight_rules: bool = True
    use_bandit: bool = False
    use_semgrep: bool = False
    fail_on_parse_error: bool = True


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


def load_config(path: str | Path, *, run_dir: str | Path | None = None) -> AppConfig:
    with Path(path).open("r", encoding="utf-8") as handle:
        raw: dict[str, Any] = yaml.safe_load(handle)
    if run_dir is not None:
        raw = dict(raw)
        raw["run"] = dict(raw.get("run", {}))
        raw["run"]["output_dir"] = str(run_dir)
    return AppConfig.model_validate(raw)


def write_resolved_config(config: AppConfig, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config.model_dump(mode="json"), handle, sort_keys=False)
