"""Replay one frozen workflow, including failed responses, with network replaced."""
import argparse
import json
import os
from pathlib import Path
import runpy
import sys
import tarfile
from tempfile import TemporaryDirectory


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch", type=Path, help="This directory or its recheck subdirectory")
    args = parser.parse_args()
    read = lambda path: json.loads(path.read_text(encoding="utf-8"))
    with TemporaryDirectory(prefix="atomic-wire-replay-") as temporary:
        root = Path(temporary)
        with tarfile.open(args.batch / "execution-source.tar.gz") as archive:
            archive.extractall(root / "source", filter="data")
        with tarfile.open(args.batch / "results.tar.gz") as archive:
            archive.extractall(root / "saved", filter="data")
        sys.path.insert(0, str(root / "source/src"))
        from prompt_mechanism_study import functional_judge

        saved = root / "saved/run"
        rows = [read(path) for path in sorted((saved / "calls").glob("*/call.json"))]
        calls = iter(rows)

        def retained_wire(request, *, timeout):
            row = next(calls)
            assert request.data.decode("utf-8") == row["trace"]["request"]
            assert timeout == row["evaluator"]["timeout_seconds"]
            raw = row["trace"]["response"].encode("utf-8")

            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def read(self, maximum): return raw[:maximum]

            return Response()

        # No real credential is read or transmitted. Every possible HTTP request
        # goes through the retained-wire assertion above; there is no fallback.
        os.environ["ALI_BAILIAN_API_KEY"] = "offline-replay-only"
        functional_judge.urlopen = retained_wire
        run = runpy.run_path(str(root / "source/scripts/run_tsg_development.py"))["run"]
        out = root / "replay"
        run(args.batch, out)
        assert next(calls, None) is None
        for name in ("results.json", "report.json", "reuse.json"):
            assert read(out / "summary" / name) == read(saved / "summary" / name), name
        assert read(out / "cases/01-single/result.json") == read(saved / "cases/01-single/result.json")
        print(f"Exact wire, result and cost replay: {len(rows)} calls; zero network requests.")
