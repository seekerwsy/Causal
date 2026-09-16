"""One offline entry point for frozen wire replay, boundary controls and candidate probes."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,tarfile
from tempfile import TemporaryDirectory

base=Path(__file__).resolve().parent
repo=base.parents[2]
read=lambda p:json.loads(p.read_text(encoding='utf-8'))
summary=read(base/'analysis/summary.json')
worker=repo/'data/method/atomic-candidate-interface-development-v1/current-workflow/replay.py'
total=0
for version in ('baseline','revised'):
    saved=summary['variants'][version]
    for name,key in [('execution-source.tar.gz','execution_source_sha256'),('results.tar.gz','results_archive_sha256')]:
        assert hashlib.sha256((base/version/name).read_bytes()).hexdigest()==saved[key]
    subprocess.run([sys.executable,str(worker),str(base/version)],cwd=repo,check=True)
    with TemporaryDirectory(prefix='tsg-boundary-verify-') as directory:
        tmp=Path(directory)
        with tarfile.open(base/version/'execution-source.tar.gz') as archive:
            archive.extractall(tmp/'source',filter='data')
        subprocess.run([sys.executable,str(base/'controls.py'),str(base),version,str(tmp/'controls')],
            cwd=repo,env={**os.environ,'PYTHONPATH':str(tmp/'source/src')},check=True)
        assert read(tmp/'controls/results.json')==read(base/version/'controls/results.json')
    total+=saved['conservative_cost_microunits']
assert total==summary['total_conservative_cost_microunits']
assert 10000000-total==summary['remaining_authorized_microunits']
with TemporaryDirectory(prefix='tsg-candidate-probe-replay-') as directory:
    output=Path(directory)/'probes'
    subprocess.run([sys.executable,str(base/'candidate-probes.py'),str(base),str(output)],
        cwd=repo,env={**os.environ,'PYTHONPATH':str(repo/'src')},check=True)
    for original in (base/'candidate-probes').rglob('*.json'):
        assert read(original)==read(output/original.relative_to(base/'candidate-probes'))
print('Verified 10 frozen calls, both authored boundary controls per version, candidate rejection and budget. No network or semantic certification.')
