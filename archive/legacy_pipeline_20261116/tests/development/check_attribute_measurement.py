import argparse
import importlib.util
import json
from pathlib import Path

import numpy as np

from prompt_mechanism_study.discovery.controlled_transport import attribute_draw


parser = argparse.ArgumentParser()
parser.add_argument('frozen', type=Path)
args = parser.parse_args()
plan = json.loads((args.frozen / 'frozen-plan.json').read_text(encoding='utf-8'))
cell = json.loads((args.frozen / 'frozen-cell.json').read_text(encoding='utf-8'))
spec = importlib.util.spec_from_file_location('independent_attribute', 'data/method/jci-highdim-oracle-20261101/attribute_verify.py')
independent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(independent)
seed = lambda role: int(np.random.SeedSequence([*cell['coordinates'], role]).generate_state(1)[0])
roles = [('auxiliary', 512), ('source', 128), ('fit', 16), ('calibration', 16), ('ranking', 32)]
for role, (name, size) in enumerate(roles):
    actual = attribute_draw(np.random.default_rng(seed(role)), size, int(role > 1), cell['scenario'],
                            plan, cell['permutation'], outcomes=role != 0)
    for field, expected in cell['data'][name].items():
        np.testing.assert_array_equal(actual[field], expected)
checks = 0
maximum_identity_error = 0.
for scenario in plan['scenarios']:
    for context_strength, error in ((.3, 0.), (.1, 0.), (.3, .1)):
        altered = dict(plan, context_effect_strength=context_strength, attribute_measurement_flip_probability=error)
        for environment in (0, 1):
            for outcomes in (False, True):
                generated = attribute_draw(np.random.default_rng(seed(0)), 512, environment,
                                           scenario, altered, cell['permutation'], outcomes=outcomes)
                rebuilt = independent.replay(np.random.default_rng(seed(0)), 512, environment,
                                             scenario, altered, cell['permutation'], outcomes)
                if outcomes:
                    for field in ('x', 'a', 'y'):
                        np.testing.assert_array_equal(generated[field], rebuilt[field])
                else:
                    np.testing.assert_array_equal(generated['x'], rebuilt[0])
                    np.testing.assert_allclose(generated['average'], rebuilt[1], atol=1e-15)
                    np.testing.assert_allclose(generated['effect'], rebuilt[2], atol=1e-15)
                prediction = generated['x'][:, 2:].mean(axis=1)
                average, effect = generated['average'], generated['effect']
                expectation = (average + effect / 2 - prediction) - (average - effect / 2 - prediction)
                maximum_identity_error = max(maximum_identity_error, float(np.max(abs(expectation - effect))))
                checks += 1
assert maximum_identity_error < 1e-14
record = dict(status='VERIFIED_ATTRIBUTE_MEASUREMENT_AND_RANDOMIZED_SCORE',
              frozen_roles_replayed=5, independent_sampling_checks=checks,
              maximum_randomized_score_identity_error=maximum_identity_error,
              development_coordinates=cell['coordinates'], prospective_validation_samples_used=0,
              graph_measurement_accuracy_established=False, formal_claim_allowed=False)
with (args.frozen / 'measurement-check.json').open('x', encoding='utf-8', newline='\n') as stream:
    json.dump(record, stream, sort_keys=True, ensure_ascii=False, allow_nan=False)
    stream.write('\n')
print(json.dumps(record, sort_keys=True))
