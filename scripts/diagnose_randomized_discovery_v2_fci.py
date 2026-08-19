from __future__ import annotations

import argparse
import json
import traceback
from collections import Counter
from pathlib import Path

from secaware.discovery.causal_learn_backend import run_causal_learn_fci
from secaware.experiments.held_out_policy_analysis import _verify_directory_manifest
from secaware.exploratory.randomized_discovery_v2_fci import (
    _base_background,
    _config,
    _read_json,
    _table_and_matrix,
    _validated_analysis,
)
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.causal import PAGRunKind


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Diagnose one discovery-v2 FCI backend invocation in-process."
    )
    parser.add_argument("--table-dir", type=Path, required=True)
    parser.add_argument("--analysis-config", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    args = parser.parse_args()
    table_dir = args.table_dir.resolve()
    analysis_path = args.analysis_config.resolve()
    matrix_path = args.matrix.resolve()
    table_manifest_sha256 = _verify_directory_manifest(table_dir)
    analysis = _validated_analysis(analysis_path)
    payload = _read_json(matrix_path)
    producer_sha256 = canonical_sha256(
        {
            "policy": "five-cwe-randomized-discovery-v2-reference-fci-v1",
            "analysis_config_sha256": sha256_file(analysis_path),
            "table_manifest_sha256": table_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
        }
    )
    table, matrix, _bindings = _table_and_matrix(payload, producer_sha256=producer_sha256)
    knowledge = _base_background(table)
    config = _config(analysis)
    diagnostics = {
        "matrix_shape": list(matrix.shape),
        "variables": [item.variable_id for item in table.variables],
        "state_counts": {
            item.variable_id: dict(sorted(Counter(matrix[:, index].tolist()).items()))
            for index, item in enumerate(table.variables)
        },
    }
    print(json.dumps(diagnostics, sort_keys=True))
    try:
        pag = run_causal_learn_fci(
            matrix,
            table,
            knowledge,
            config,
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )
    except Exception:  # noqa: BLE001 - this script exists to preserve the hidden traceback.
        traceback.print_exc()
        return 1
    print(pag.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
