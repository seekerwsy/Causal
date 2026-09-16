"""Reproduce the frozen three-scheme diagnostic offline, including exact HTTP bodies."""
import json
import os
from pathlib import Path
import runpy
import sys
import tarfile
from tempfile import TemporaryDirectory


if __name__ == '__main__':
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    read = lambda p: json.loads(p.read_text(encoding='utf-8'))
    with TemporaryDirectory(prefix='tsg-comparison-replay-') as directory:
        root = Path(directory)
        for name, target in [('execution-source.tar.gz', 'source'), ('results.tar.gz', 'saved')]:
            with tarfile.open(base / name) as archive:
                archive.extractall(root / target, filter='data')
        sys.path.insert(0, str(root / 'source/src'))
        from prompt_mechanism_study import functional_judge
        saved = root / 'saved/run'
        rows = [read(p) for p in sorted((saved / 'calls').glob('*/call.json'))]
        iterator = iter(rows)

        def retained_wire(request, *, timeout):
            row = next(iterator)
            assert request.data.decode('utf-8') == row['trace']['request']
            assert timeout == row['evaluator']['timeout_seconds']
            raw = row['trace']['response'].encode('utf-8')
            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def read(self, maximum): return raw[:maximum]
            return Response()

        os.environ['ALI_BAILIAN_API_KEY'] = 'offline-replay-only'
        functional_judge.urlopen = retained_wire
        frozen = root / 'source/data/method/tsg-extraction-comparison-v1'
        run = runpy.run_path(str(frozen / 'compare.py'))['run']
        output = root / 'replayed'
        run(frozen, output)
        assert next(iterator, None) is None
        for name in ('results.json', 'report.json'):
            assert read(output / 'summary' / name) == read(saved / 'summary' / name), name
        for row, path in zip(rows, sorted((output / 'calls').glob('*/call.json')), strict=True):
            repeated = read(path)
            row.pop('elapsed_seconds'); repeated.pop('elapsed_seconds')
            assert row == repeated
        print(f'Exact request, response, extraction and cost replay: {len(rows)} calls; zero network.')
