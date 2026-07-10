from pathlib import Path


class FileProvider:
    def __init__(self, root: Path):
        self.root = root

    def generate(self, prompt: str, *, model_id: str, seed: int, language: str) -> str:
        del prompt, language
        path = self.root / f"{model_id}_{seed}.py"
        if not path.exists():
            raise FileNotFoundError(f"Generated code file not found: {path}")
        return path.read_text(encoding="utf-8")
