# SecAware

SecAware is a reproducible Python CLI prototype for TSG-driven prompt-side
security mechanism discovery and confirmation.

The demo pipeline runs without external LLM APIs or external static analyzers:

```bash
pip install -e ".[dev]"
secaware run-all --config configs/demo.yaml --run-dir runs/demo --force
pytest
```
