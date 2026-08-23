"""Compare lexical and frozen-embedding retrieval for semantic deduplication.

This script is deliberately outside the core package.  It consumes a closed
dataset-preparation bundle and writes a closed benchmark bundle; it never uses
generated-code outcomes or experimental arm labels.
"""

from __future__ import annotations

import argparse
import ast
import copy
import importlib.metadata
import platform
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.feature_extraction.text import TfidfVectorizer

from prompt_mechanism_study.artifact_io import read_json, verify_bundle, write_bundle

MODEL_ID = "BAAI/bge-base-en-v1.5"
MODEL_REVISION = "b4595376fce1812665312d0557400026cdeb7739"
TOP_K = 10
MINIMUM_RECALL_GAIN = 0.05


@dataclass(frozen=True)
class Query:
    query_id: str
    kind: str
    text: str
    language: str
    cwe: str
    excluded_record_id: str | None
    relevant_record_ids: tuple[str, ...]


def contract_view(prompt: str) -> str | None:
    """Return a deterministic signature-and-docstring view when one exists."""

    try:
        tree = ast.parse(prompt)
    except SyntaxError:
        return None
    parts: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        shell = copy.deepcopy(node)
        shell.decorator_list = []
        shell.body = [ast.Pass()]
        declaration = ast.unparse(shell).splitlines()[0].removesuffix(":")
        docstring = ast.get_docstring(node, clean=True)
        if docstring:
            parts.append(f"{declaration}\n{docstring}")
    value = "\n\n".join(parts).strip()
    return value or None


def lineage_key(record: dict[str, Any]) -> str | None:
    if record["source_lineage_family"] != "securityeval":
        return None
    return str(record["source_item_id"]).removeprefix("SecEvalBase:")


def build_queries(records: list[dict[str, Any]]) -> list[Query]:
    exact: dict[str, list[str]] = {}
    for record in records:
        exact.setdefault(record["prompt_sha256"], []).append(record["record_id"])

    queries: list[Query] = []
    for record in records:
        view = contract_view(record["prompt"])
        if view is None or view == record["prompt"].strip():
            continue
        queries.append(
            Query(
                query_id=f"contract:{record['record_id']}",
                kind="contract_view",
                text=view,
                language=record["language"],
                cwe=record["cwe"],
                excluded_record_id=None,
                relevant_record_ids=tuple(sorted(exact[record["prompt_sha256"]])),
            )
        )

    by_lineage: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        key = lineage_key(record)
        if key is not None:
            by_lineage.setdefault(key, []).append(record)
    for key, members in sorted(by_lineage.items()):
        if len(members) != 2:
            continue
        left, right = sorted(members, key=lambda item: item["record_id"])
        for source, target in ((left, right), (right, left)):
            queries.append(
                Query(
                    query_id=f"lineage:{key}:{source['record_id']}",
                    kind="known_lineage",
                    text=source["prompt"],
                    language=source["language"],
                    cwe=source["cwe"],
                    excluded_record_id=source["record_id"],
                    relevant_record_ids=(target["record_id"],),
                )
            )
    return sorted(queries, key=lambda item: item.query_id)


def _rank(
    scores: np.ndarray,
    candidate_indices: list[int],
    records: list[dict[str, Any]],
    excluded_record_id: str | None,
) -> list[str]:
    ranked = sorted(
        (
            (float(scores[index]), records[index]["record_id"])
            for index in candidate_indices
            if records[index]["record_id"] != excluded_record_id
        ),
        key=lambda item: (-item[0], item[1]),
    )
    return [record_id for _, record_id in ranked[:TOP_K]]


def _metrics(rows: list[dict[str, Any]], method: str, kind: str) -> dict[str, Any]:
    selected = [row for row in rows if row["kind"] == kind]
    hits = [row[f"{method}_rank"] for row in selected]
    return {
        "query_count": len(selected),
        "recall_at_10": sum(rank is not None for rank in hits) / len(hits),
        "mean_reciprocal_rank": sum(1.0 / rank for rank in hits if rank is not None) / len(hits),
    }


def run(prepared_root: Path, output: Path, *, batch_size: int) -> dict[str, Any]:
    verify_bundle(prepared_root)
    raw = read_json(prepared_root / "records.json")
    if not isinstance(raw, list) or not raw:
        raise ValueError("prepared records must be a non-empty JSON list")
    records = [dict(item) for item in raw]
    queries = build_queries(records)
    if not queries:
        raise ValueError("the prepared bundle produced no benchmark queries")

    corpus = [record["prompt"] for record in records]
    query_texts = [query.text for query in queries]
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
    lexical = vectorizer.fit_transform(corpus + query_texts)
    corpus_tfidf = lexical[: len(corpus)]
    query_tfidf = lexical[len(corpus) :]

    model = SentenceTransformer(
        MODEL_ID,
        revision=MODEL_REVISION,
        device="cpu",
        trust_remote_code=False,
    )
    corpus_embedding = model.encode(
        corpus,
        batch_size=batch_size,
        normalize_embeddings=True,
        show_progress_bar=True,
    )
    query_embedding = model.encode(
        query_texts,
        batch_size=batch_size,
        normalize_embeddings=True,
        show_progress_bar=True,
    )

    blocks: dict[tuple[str, str], list[int]] = {}
    for index, record in enumerate(records):
        blocks.setdefault((record["language"], record["cwe"]), []).append(index)

    results: list[dict[str, Any]] = []
    for query_index, query in enumerate(queries):
        candidates = blocks[(query.language, query.cwe)]
        tfidf_scores = (query_tfidf[query_index] @ corpus_tfidf.T).toarray()[0]
        embedding_scores = query_embedding[query_index] @ corpus_embedding.T
        row = asdict(query)
        for method, scores in (("tfidf", tfidf_scores), ("embedding", embedding_scores)):
            top = _rank(scores, candidates, records, query.excluded_record_id)
            ranks = [top.index(value) + 1 for value in query.relevant_record_ids if value in top]
            row[f"{method}_top_10"] = top
            row[f"{method}_rank"] = min(ranks) if ranks else None
        results.append(row)

    kinds = ("contract_view", "known_lineage")
    metrics = {
        method: {kind: _metrics(results, method, kind) for kind in kinds}
        for method in ("tfidf", "embedding")
    }
    gain = (
        metrics["embedding"]["contract_view"]["recall_at_10"]
        - metrics["tfidf"]["contract_view"]["recall_at_10"]
    )
    lineage_non_degraded = (
        metrics["embedding"]["known_lineage"]["recall_at_10"]
        >= metrics["tfidf"]["known_lineage"]["recall_at_10"]
    )
    admitted = gain >= MINIMUM_RECALL_GAIN and lineage_non_degraded
    report = {
        "schema_version": "1.0",
        "status": "DEDUP_RETRIEVAL_BENCHMARK_COMPLETE",
        "prepared_bundle": str(prepared_root.resolve()),
        "record_count": len(records),
        "query_count": len(queries),
        "model": {
            "model_id": MODEL_ID,
            "revision": MODEL_REVISION,
            "maximum_sequence_length": 512,
            "embedding_dimensions": 768,
            "normalization": "l2",
            "similarity": "cosine",
            "instruction_prefix": None,
        },
        "lexical_baseline": {
            "implementation": "sklearn.feature_extraction.text.TfidfVectorizer",
            "analyzer": "char_wb",
            "ngram_range": [3, 5],
        },
        "top_k": TOP_K,
        "admission_rule": {
            "minimum_contract_view_recall_gain": MINIMUM_RECALL_GAIN,
            "known_lineage_recall_must_not_decrease": True,
        },
        "metrics": metrics,
        "contract_view_recall_gain": gain,
        "embedding_admitted": admitted,
        "decision_scope": "candidate retrieval only; semantic adjudication remains required",
        "outcomes_or_arm_labels_used": False,
        "scientific_claim_allowed": False,
        "environment": {
            "python": platform.python_version(),
            "sentence_transformers": importlib.metadata.version("sentence-transformers"),
            "scikit_learn": importlib.metadata.version("scikit-learn"),
        },
    }
    write_bundle(output, {"query-results.json": results, "report.json": report})
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("prepared_root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--batch-size", type=int, default=16)
    args = parser.parse_args()
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be positive")
    print(run(args.prepared_root, args.output, batch_size=args.batch_size))


if __name__ == "__main__":
    main()
