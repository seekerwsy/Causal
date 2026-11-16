import argparse
from pathlib import Path

from prompt_mechanism_study.artifact_io import read_json,write_json_new,file_sha256
from prompt_mechanism_study.records import canonical_json
from prompt_mechanism_study.tsg.source_representation import check_source_representation,display_source_graph


parser = argparse.ArgumentParser()
parser.add_argument('output',type=Path)
args = parser.parse_args()
root = Path('data/method/kedro-representation-20261102')
source = read_json(root/'representation-source.json')
readback,compiled = check_source_representation(source,read_json(root/'representation-graph.json'),'graph')
shown,aliases = display_source_graph(readback)
flat,_ = check_source_representation(source,read_json(root/'representation-flat.json'),'flat')
assert flat==read_json(root/'representation-flat.json')
assert len(shown['nodes'])==len(readback['nodes'])==len(aliases)
write_json_new(args.output,dict(status='VERIFIED_REAL_SOURCE_GRAPH_DISPLAY',
    source_sha256=file_sha256(root/'representation-source.json'),graph_nodes=len(readback['nodes']),
    native_characters=len(canonical_json(readback)),display_characters=len(canonical_json(shown)),
    flat_records=len(flat['records']),code_generation_calls=0,new_scientific_repetitions=0,
    implementation_sha256=file_sha256(Path('src/tsg/source_representation.py'))))
print(dict(status='VERIFIED_REAL_SOURCE_GRAPH_DISPLAY',graph_nodes=len(aliases),new_scientific_repetitions=0))
