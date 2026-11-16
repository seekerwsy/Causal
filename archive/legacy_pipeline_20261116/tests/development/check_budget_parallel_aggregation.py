import argparse
from concurrent.futures import ProcessPoolExecutor
import importlib.util
from pathlib import Path
import sys

from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_json_new
from prompt_mechanism_study.records import canonical_json


def load_module(name,path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('results',type=Path)
    parser.add_argument('output',type=Path)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[2]
    directory = project/'data/method/jci-target-budget-curve-20261102'
    producer = load_module('budget_curve_producer',directory/'curve.py')
    verifier = load_module('budget_curve_verifier',directory/'verify.py')
    producer_items, verifier_items, identities = [], [], {}
    coordinate = ('downstream_signal',0,0)
    for size in (16,32,64):
        root = args.results/f'n{size}'
        row, = [item for item in read_json(root/'summary/result.json')['rows']
            if (item['scenario'],item['batch'],item['repetition']) == coordinate]
        producer_items.append((size,root,row))
        verifier_items.append((size,root,coordinate,row['risks']))
        verified = read_json(root/'verification/result.json')
        assert verified['status'] == 'VERIFIED' and verified['cells'] == verified['native_graphs_replayed'] == 96
        identities[str(size)] = dict(verification_sha256=file_sha256(root/'verification/result.json'),
            source_archive_sha256=verified['source_archive_sha256'])
    with ProcessPoolExecutor(max_workers=3) as pool:
        generated = list(pool.map(producer.inspect_cell,producer_items))
    with ProcessPoolExecutor(max_workers=3) as pool:
        checked = list(pool.map(verifier.inspect_cell,verifier_items))
    assert generated == checked
    assert len({item[1] for item in generated}) == 1
    canonical_json(dict(budget_inputs=identities,common_source_units=96))
    write_json_new(args.output,dict(status='VERIFIED_PARALLEL_BUDGET_CELL_READOUT',source_learning_units_replayed=1,
        budget_cells_replayed=3,scientific_repetitions_added=0,source_fingerprints=[item[1] for item in generated],
        producer_sha256=file_sha256(directory/'curve.py'),verifier_sha256=file_sha256(directory/'verify.py'),
        implementation_sha256=file_sha256(Path(__file__))))
    print(dict(status='VERIFIED_PARALLEL_BUDGET_CELL_READOUT',budget_cells_replayed=3,scientific_repetitions_added=0),flush=True)
