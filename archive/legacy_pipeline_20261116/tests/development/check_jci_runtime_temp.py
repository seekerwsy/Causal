import argparse
import json
import os
import subprocess
import time
from pathlib import Path

from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_json_new
from prompt_mechanism_study.discovery.jci_structure import StructureBackend


parser = argparse.ArgumentParser()
parser.add_argument('output',type=Path)
parser.add_argument('--reference',type=Path,required=True)
args = parser.parse_args()
root = args.output.resolve()
root.mkdir(parents=True,exist_ok=False)
backend = StructureBackend(Path('/usr/bin/Rscript'),root/'backend.log',Path('src/discovery/jci_context.R'))
temporary = root/'r-tmp'
observed = []
try:
    deadline = time.monotonic()+10
    while time.monotonic()<deadline:
        if backend.process.poll() is not None:
            raise RuntimeError('真实R后端在临时目录检查前终止')
        observed = [path.resolve() for path in temporary.glob('Rtmp*') if path.is_dir()]
        if observed:
            break
        time.sleep(.05)
    assert observed and all(path.is_relative_to(temporary.resolve()) for path in observed)
finally:
    backend.close()
environment = dict(os.environ,TMPDIR=str(temporary),TMP=str(temporary),TEMP=str(temporary))
replay = root/'native-r-replay.json'
subprocess.run(['/usr/bin/Rscript','src/verification/jci_trace.R',str(args.reference),str(replay),'1'],
    check=True,env=environment)
native = read_json(replay)
assert native['cells']==1 and len(native['traces'])==1
write_json_new(root/'result.json',dict(status='VERIFIED_PROJECT_SCOPED_R_TEMPORARY_DIRECTORIES',
    observed_temporary_directories=[str(path) for path in observed],backend_exit_code=backend.process.returncode,
    native_graphs_replayed=1,new_scientific_repetitions=0,
    backend_sha256=file_sha256(Path('src/discovery/jci_structure.py')),
    native_replay_sha256=file_sha256(replay)))
print(json.dumps(dict(status='VERIFIED_PROJECT_SCOPED_R_TEMPORARY_DIRECTORIES',native_graphs_replayed=1)),flush=True)
