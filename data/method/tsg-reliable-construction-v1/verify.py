"""Offline replay of frozen development calls; never accesses a provider."""
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent
INVENTORY_REPLAY = r'''
import importlib.util, json, os
from pathlib import Path
from prompt_mechanism_study import functional_judge
from prompt_mechanism_study.artifact_io import read_json
saved, output, work = map(Path, __import__('sys').argv[1:])
calls = [read_json(p) for p in sorted((saved/'calls').glob('*/call.json'))]
position = 0
os.environ['ALI_BAILIAN_API_KEY'] = 'offline-replay-only'
def transport(request, *, timeout):
    global position
    row = calls[position]; position += 1
    assert request.data.decode() == row['trace']['request']
    assert timeout == row['evaluator']['timeout_seconds']
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, maximum): return row['trace']['response'].encode()[:maximum]
    return Response()
functional_judge.urlopen = transport
spec = importlib.util.spec_from_file_location('frozen_runner', work/'run_tsg_development.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module.run(work/'experiment', output)
assert position == len(calls)
for name in ('results.json', 'report.json', 'reuse.json'):
    assert read_json(output/'summary'/name) == read_json(saved/'summary'/name), name
'''


def verify(base):
    with tempfile.TemporaryDirectory(prefix='tsg-frozen-replay-') as directory:
        work = Path(directory)
        with tarfile.open(base/'execution-source.tar.gz') as archive:
            archive.extractall(work, filter='data')
        retained = work/'retained'
        with tarfile.open(base/'results.tar.gz') as archive:
            archive.extractall(retained, filter='data')
        saved = retained/'run'
        env = {**os.environ, 'PYTHONPATH': str(work/'src'), 'PYTHONUTF8': '1'}
        output = work/'replayed'
        if (work/'run_tsg_development.py').exists():
            code = work/'replay.py'; code.write_text(INVENTORY_REPLAY, encoding='utf-8')
            command = [sys.executable, str(code), str(saved), str(output), str(work)]
        else:
            runner, = work.rglob('propose.py')
            command = [sys.executable, str(runner), str(runner.parent), str(output), str(saved)]
        subprocess.run(command, cwd=work, env=env, check=True)
        report = json.loads((saved/'summary/report.json').read_text(encoding='utf-8'))
    return dict(experiment=base.name, exact_wire_and_results_replayed=True,
                provider_calls=report.get('actual_provider_calls', report.get('provider_calls')),
                conservative_cost_microunits=report['actual_conservative_cost_microunits'])


def verify_agent_graphs():
    base = ROOT/'agent-construction-pilot'
    with tempfile.TemporaryDirectory(prefix='tsg-agent-replay-') as directory:
        work = Path(directory)
        with tarfile.open(base/'execution-source.tar.gz') as archive:
            archive.extractall(work, filter='data')
        env = {**os.environ, 'PYTHONPATH': str(work/'src'), 'PYTHONUTF8': '1'}
        for name in ('firmware', 'pandoc', 'book'):
            shutil.copyfile(base/name/'attempt-1.json', work/name/'attempt-1.json')
            subprocess.run([sys.executable, str(work/'validate.py'), str(work/name), '1'],
                           cwd=work, env=env, check=True)
            for filename in ('result.json', 'contract.json', 'graph.json', 'structural-readback.json'):
                actual = json.loads((work/name/'checks/attempt-1'/filename).read_text(encoding='utf-8'))
                saved = json.loads((base/name/'checks/attempt-1'/filename).read_text(encoding='utf-8'))
                assert actual == saved, (name, filename)
    return dict(retained_agent_graphs_replayed=3, agent_sampling_repeated=False,
                semantic_correctness_not_certified=True)


if __name__ == '__main__':
    experiments = ('compact-candidate', 'compact-candidate-v2', 'inventory-pilot',
                   'inventory-v2-deepseek', 'inventory-v2-max')
    results = [verify(ROOT/name) for name in experiments]
    assert sum(row['provider_calls'] for row in results) == 11
    assert sum(row['conservative_cost_microunits'] for row in results) == 1676793
    print(json.dumps(dict(status='OFFLINE_REPLAY_PASSED', experiments=results,
                          agent_compilation=verify_agent_graphs(),
                          scientific_claim_allowed=False), indent=2))
