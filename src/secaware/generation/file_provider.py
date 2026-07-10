from pathlib import Path

from secaware.errors import ErrorCode, SecAwareError


class FileProvider:
    def __init__(self, root: Path):
        self.root = root

    def generate(self, prompt: str, *, model_id: str, seed: int, language: str) -> str:
        del prompt, language
        path = self.root / f"{model_id}_{seed}.py"
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise SecAwareError(
                code=ErrorCode.CONTRACT,
                stage="generation",
                message="generated code input could not be read",
                details={"path": str(path)},
            ) from None
