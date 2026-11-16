from pathlib import Path
import runpy

import numpy as np

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.discovery.controlled_transport import attribute_estimation_diagnostics


root = Path('.test-tmp/jci-robustness-preflight-20261103')
cell, plan = read_json(root / 'frozen-cell.json'), read_json(root / 'frozen-plan.json')
diagnostic = attribute_estimation_diagnostics(cell, plan)
independent = runpy.run_path('data/method/jci-robustness-round1-20261103/verify_aggregate.py')
independent['assert_equal'](diagnostic, independent['diagnostic'](cell, plan))
assert len(diagnostic['estimates']) == 11
for name, row in diagnostic['estimates'].items():
    selected = cell['selection']['choices'][name]
    saved = cell['selection']['candidates'][selected]
    np.testing.assert_allclose(row['estimate'], saved['effect'], atol=1e-12)
    np.testing.assert_allclose(row['squared_error'], (saved['effect'] - cell['integrated']['truth']) ** 2, atol=1e-15)
    assert row['coverage'] in {'covered', 'not_covered', 'integration_boundary_unknown'}
assert diagnostic['observed_graph_truth_available'] is True
assert diagnostic['tsg_accuracy_measured'] is False
assert diagnostic['definite_directed_edges'] >= diagnostic['disagreements_with_noiseless_mechanism'] >= 0
print(dict(status='VERIFIED_DIAGNOSTICS_ON_FROZEN_REAL_SIMULATION_UNIT', methods=11,
           independent_prospective_outcomes_read=0, new_data_generated=False))
