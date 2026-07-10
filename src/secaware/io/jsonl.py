import json
from pathlib import Path
from typing import Iterable, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


def read_jsonl(path: str | Path, model: type[T] | None = None) -> list[T] | list[dict]:
    records: list[T] | list[dict] = []
    path = Path(path)
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            records.append(model.model_validate(data) if model else data)  # type: ignore[attr-defined]
    return records


def _dump_record(record: BaseModel | dict) -> str:
    if isinstance(record, BaseModel):
        return record.model_dump_json()
    return json.dumps(record, ensure_ascii=False, sort_keys=True)


def write_jsonl(path: str | Path, records: Iterable[BaseModel | dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(_dump_record(record))
            handle.write("\n")
