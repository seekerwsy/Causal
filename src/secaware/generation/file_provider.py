from pathlib import Path

from secaware.errors import ErrorCode, SecAwareError


class FileProvider:
    def __init__(self, root: Path):
        try:
            self.root = root.resolve()
        except (OSError, RuntimeError):
            raise self._containment_error() from None

    @staticmethod
    def _containment_error() -> SecAwareError:
        return SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="generation",
            message="generated code path is outside the file provider directory",
        )

    def generate(self, prompt: str, *, model_id: str, seed: int, language: str) -> str:
        del prompt, language
        try:
            path = (self.root / f"{model_id}_{seed}.py").resolve()
            path.relative_to(self.root)
        except (OSError, RuntimeError, ValueError):
            raise self._containment_error() from None
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise SecAwareError(
                code=ErrorCode.CONTRACT,
                stage="generation",
                message="generated code input could not be read",
                details={"path": str(path)},
            ) from None
