from pathlib import Path

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.experiment.jci_reliability import run_reliability
from prompt_mechanism_study.verification.jci_reliability import verify_reliability


def test_real_fci_learning_summary_and_independent_verification(tmp_path, request):
    output = tmp_path/'reproduction'
    rscript = Path(request.config.getoption('--rscript'))
    result = run_reliability(Path('configs/jci-smoke.json'), output, rscript, workers=2)
    assert result['summary_completed'] and result['cells'] == result['planned_cells'] == 4
    summary = read_json(output/'summary/result.json')
    assert summary['evidence_role'] == 'NON_CLAIM_METHOD_REPRODUCTION'
    assert summary['structural_searches'] == 12 and summary['new_model_requests'] == 0
    for cell in (output/'cells').glob('*/result.json'):
        record = read_json(cell)
        assert record['learned']['coefficients_fixed_to_zero'] is False
        assert all(graph['conservative'] for graph in record['structure']['graphs'].values())
    verification = verify_reliability(output, workers=2)
    assert verification['complete'] and verification['status'] == 'VERIFIED'
    assert verification['independently_verified_effect_models'] > 400
    resumed = run_reliability(Path('configs/jci-smoke.json'), output, rscript, workers=2)
    assert resumed == result
