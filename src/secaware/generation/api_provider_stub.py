class APIProviderStub:
    def generate(self, prompt: str, *, model_id: str, seed: int, language: str) -> str:
        del prompt, model_id, seed, language
        raise RuntimeError("API provider is not configured. Use provider=mock or provider=file.")
