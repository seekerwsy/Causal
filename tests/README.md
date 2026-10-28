# JCI scientific checks

Install the project with Python 3.12 and `python -m pip install -e ".[dev]"`.
Set `OPENBLAS_NUM_THREADS=1` and `OMP_NUM_THREADS=1`. R must provide pcalg 2.7.12
and jsonlite. The complete default suite is:

```text
python -m pytest -q --rscript=PATH_TO_RSCRIPT
```

`RSCRIPT` can also supply the executable. Intermediate files stay under the
ignored `.test-tmp` directory. The default suite uses `tests/jci`:

- `test_numerics.py` checks mutually exclusive assignments, disjoint task roles,
  integer count outcomes, exact population cancellation, independent penalized
  least-squares solutions, baseline abstention and exact policy values.
- `test_contracts.py` rejects formal-claim identities, nonconservative structure,
  zero penalties, repeated batch seeds and invalid execution budgets before work.
- `test_workflow.py` executes the declared SCM with real R/pcalg FCI, fits the
  complete policy consumers, assembles simultaneous comparisons, independently
  verifies the saved result and resumes the identical execution.

The probability models are declared computational research mechanisms; their
results retain `NON_CLAIM_METHOD_REPRODUCTION`. They do not supply real-model,
natural-task or confirmatory evidence. Frozen real-outcome replay is checked with
`study verify-jci-replay SAVED_REPLAY` and its original required input artifacts.

Earlier default tests and `tests/development` retain their research context at
`main` commit `d304d4ec`; their old CLI and source hashes belong to that revision.

## Executed branch checks

On 2026-10-28, the isolated Python 3.12.13 environment passed all 13 default
checks with NumPy 2.5.1, SciPy 1.18.0, scikit-learn 1.9.0 and pcalg 2.7.12
under R 4.1.2. The command-line SCM reproduction completed four repetitions and
twelve FCI searches; its independent verification reconstructed 696 effect models,
2,365 CI statistics and sixteen direct randomization tests.

Frozen scientific-output reproduction reassembled all 3,072 saved reliability
repetitions, 48 conditions and 384 comparison intervals with matching results.
One original repetition was also rerun with real FCI; its graph, task data,
selected actions and values matched. This check did not generate 3,072 new repeats.

The real-outcome replay check refitted and independently checked all 24 saved
cells and 480 models, checked 12,097 CI records, and reproduced selection and
the six final descriptive intervals for 200 test task units. Twelve real FCI
searches reproduced the representative replay's four family graphs.

These checks made zero model requests. Validation records are retained in the
ignored `.test-tmp/validation` directory. The explicit command-line SCM result
is stored on the server at
`/home/wsy/work/prompt-mechanism-study/results/jci-framework-reproduction-20261028`.
