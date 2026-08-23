# Deduplication retrieval benchmark

## Decision

Do not add embedding retrieval to the current artifact. Keep character
3--5-gram TF--IDF as the candidate retriever and retain blind semantic LLM
adjudication as a separate step.

## Frozen comparison

- Input: the closed seven-source preparation bundle with 2,283 records.
- Embedding model: `BAAI/bge-base-en-v1.5`.
- Model revision: `b4595376fce1812665312d0557400026cdeb7739`.
- Representation: 768 dimensions, L2 normalization, cosine similarity, no
  instruction prefix, CPU inference, maximum sequence length 512.
- Lexical baseline: character-boundary TF--IDF, 3--5 grams.
- Retrieval block: same language and CWE.
- Cutoff: Top-10.
- Admission rule fixed before inference: contract-view Recall@10 must improve
  by at least 0.05 and known-lineage Recall@10 must not decrease.
- No generated-code outcome, arm label, Functional Judge result, or Security
  Oracle result was used.

The model was selected because its official model card reports an MIT license,
English inputs, 512-token sequences, and 768-dimensional embeddings. The exact
revision is immutable. The smaller `all-MiniLM-L6-v2` was not selected because
its official card states that inputs longer than 256 word pieces are truncated;
E5-base-v2 was not selected because its prefix convention adds avoidable policy
complexity for symmetric task similarity.

## Queries

The benchmark contains 587 outcome-blind queries:

- 357 deterministic contract views extracted from parseable source prompts as
  function/class declarations plus their docstrings; and
- 230 directed queries covering 115 shared SecurityEval/CodeSecEval upstream
  task identities.

The lineage set is mostly exact text and is therefore a regression check, not
strong evidence about broad semantic generalization. Contract views test
surface-form and context reduction, but are also source-derived. The benchmark
is consequently an engineering admission gate, not a scientific comparison of
embedding models.

## Result

| Retriever | Contract Recall@10 | Contract MRR | Lineage Recall@10 | Lineage MRR |
|---|---:|---:|---:|---:|
| char 3--5-gram TF--IDF | 1.000 | 0.983 | 1.000 | 1.000 |
| BGE base English v1.5 | 1.000 | 0.950 | 1.000 | 1.000 |

Embedding Recall@10 gain was 0.000, below the required +0.050. It was therefore
not admitted.

## Reproduction and evidence

The executable comparison is
`scripts/benchmark_dedup_retrieval.py`. It pins the model revision and writes a
closed two-file result bundle. The local run is stored at
`.codex-runtime/dedup-retrieval-bge-v1-20260822-01`.

- `report.json` SHA-256:
  `26634f3131234cf28d0617b30fffc8e8eea5150ca207957c4132562e06568b6a`
- `query-results.json` SHA-256:
  `cbcf56f0c7d9841441c182eb772b69fd4012bc9beaf685086fb21e99dfb2bf1b`
- Runtime: Python 3.12.13, sentence-transformers 5.1.2, scikit-learn 1.9.0.

Model sources: [BGE model card](https://huggingface.co/BAAI/bge-base-en-v1.5),
[frozen BGE revision](https://huggingface.co/BAAI/bge-base-en-v1.5/tree/b4595376fce1812665312d0557400026cdeb7739),
[E5 paper](https://arxiv.org/abs/2212.03533), and
[MiniLM model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/main/README.md).
