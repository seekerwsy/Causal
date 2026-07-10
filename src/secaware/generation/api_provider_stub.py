from secaware.errors import ErrorCode, SecAwareError


class APIProviderStub:
    def generate(self, prompt: str, *, model_id: str, seed: int, language: str) -> str:
        del prompt, model_id, seed, language
        raise SecAwareError(
            code=ErrorCode.CONFIG,
            stage="generation",
            message="API generation provider is not configured",
        )
