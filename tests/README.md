# Scientific test suite

Use Python 3.12 from the repository root:

```text
python -m pip install -e ".[dev,selectors,languages]"
python -m pytest -q
```

The default suite exercises current scientific stages and invariants. Its
seven-stage smoke measures bundled offline responses, runs real FCI and invokes
the independent saved-result verifier. All outputs retain a non-claim identity.

| Boundary | Checks |
| --- | --- |
| Source and task unit | Exact identity, deduplication, lineage, outcome-blind roles and protected-task separation |
| Representation and candidates | Source locations, requirement/target/condition/scope bindings, Atomic ADD/REMOVE and explicit uncertainty |
| Prioritization | Shared candidates/folds, FCI admission, fixed slots, unique dispatch, signed gain, threshold and baseline abstention |
| Assignment | Task/arm/seed binding, replay and complete accounting |
| Measurement | Validity, secure/insecure/unknown, blinded functionality and separate endpoints |
| Inference | Task-unit ITT, realization weights, bootstrap, multiplicity and non-evaluable effects |
| Artifact reconstruction | Exact fields/types, tamper rejection and independent result replay |

Mathematical fixtures test declared estimators and constraints. Offline response
fixtures test component execution and retain their synthetic identity. These
checks establish implemented behavior; scientific effects require executed,
independently verified research evidence.

Exposed-development regression checks have a separate command and dependency:

```text
python -m pip install -e ".[dev,analysis]"
python -m pytest tests/development/test_controlled_repair.py -q --basetemp=.tmp/NEW_DEVELOPMENT_TEST_DIRECTORY
```

These checks use saved complete preparation/review submissions and independently
reconstruct 168 real probes and 400 decisions. Their original observations stay
at `results/controlled-repair-20261007`; their inputs stay at
`data/method/controlled-repair-20261007`. The evidence remains
`POST_HOC_EXPOSED_METHOD_CHECK`.

Historical study tests use the matching implementation in the verified archive.
The [archive guide](../docs/archive-reproduction.md) gives the isolated
environment and frozen-report commands. Run focused current tests while editing;
validate an affected reviewer path in a clean supported environment and replay
the frozen scientific outputs it affects.

The JCI sharing development checks use the executed computational study:

```text
python -m pytest tests/development/test_jci_sharing.py -q --basetemp=.test-tmp/NEW_JCI_CHECK_DIRECTORY
python -m prompt_mechanism_study study verify-jci-sharing results/jci-sharing-20261014
```

They check complete task accounting, identical-input zero effects, independent
Ridge solutions, finite-state policy values, and calibration of the deployed
shared component. Set `OPENBLAS_NUM_THREADS=1` and `OMP_NUM_THREADS=1` for the
independent verifier's many small matrix operations.

The joint-context and constrained-estimation checks additionally use:

```text
python -m pytest tests/development/test_jci_policy.py tests/development/test_jci_refit.py -q --basetemp=.test-tmp/NEW_JCI_JOINT_CHECKS
python -m prompt_mechanism_study study verify-jci-sharing results/jci-joint-policy-20261014-ancestry --joint-policies
python -m prompt_mechanism_study study verify-jci-sharing results/jci-joint-policy-20261014-ancestry --joint-policies --zero-effect-refit
```

These checks run the real pcalg JCI methods and independently reconstruct the
randomized outcome fits, constrained coefficients, calibration decisions, exact
policy values, marginal estimation errors and pooled-baseline variances. Known
graphical information and observed-data results remain separate evidence.

The exposed direction comparison uses fixed physical requests across eight
outcome-blind training/CAL splits. Its dedicated checks are:

```text
python -m pytest tests/development/test_jci_direction.py -q --basetemp=.test-tmp/NEW_JCI_DIRECTION_CHECKS
python -m prompt_mechanism_study study verify-jci-sharing results/jci-direction-comparison-20261014 --joint-policies
```

These checks bind every split to the original requests and effects, independently
reconstruct the equal-budget consumers and replay the task-unit bootstrap.
All split descendants move with their evaluation task. The results retain
`POST_HOC_EXPOSED_DIRECTION_COMPARISON` identity.

The finite-regularization JCI consumer uses a separate real-FCI count-outcome
canary and independent numerical verification:

```text
python -m pytest tests/development/test_jci_reliability.py -q --basetemp=.test-tmp/NEW_JCI_RELIABILITY_CHECKS
python -m prompt_mechanism_study study verify-jci-reliability results/jci-reliability-20261014/experiment --workers 4
```

These checks protect integer count outcomes, mutually exclusive Atomic
assignments, exact cancellation examples, positive finite penalties, independent
effect solutions, separated CAL roles, policy values and simultaneous intervals.
The method study retains its bounded SCM evidence identity.

The exposed limited-budget candidate replay uses:

```text
python -m pytest tests/development/test_jci_replay.py -q --basetemp=.test-tmp/NEW_JCI_BUDGET_CHECKS
python -m prompt_mechanism_study study verify-jci-sharing results/jci-budget-replay-20261014 --joint-policies
```

These checks use real original request outcomes. They protect disjoint discovery,
confirmation and test task roles; nested physical-request budgets; task-weighted
cross-fitting and AIPW; requirement-ancestry prioritization; fixed selection slots;
confirmation costs; and independent final deployment values. Replay permutations
and nested budgets retain their shared task dependencies.
