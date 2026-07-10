import shutil
from pathlib import Path

from secaware.config import AppConfig, write_resolved_config


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
        ]:
            self.path(part).mkdir(parents=True, exist_ok=True)

    def prepare(self) -> None:
        self.mkdirs()
        prompts_src = Path(self.config.data.prompts_path)
        shutil.copyfile(prompts_src, self.path("inputs", "prompts.jsonl"))
        write_resolved_config(self.config, self.path("config.resolved.yaml"))

    def should_skip(self, output: Path, force: bool) -> bool:
        return output.exists() and not force
