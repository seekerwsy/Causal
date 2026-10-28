from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence


def _build_parser():
    parser = argparse.ArgumentParser(
        prog='prompt-mechanism-study',
        description='JCI requirement-policy learning, held-out evaluation and independent verification.',
    )
    groups = parser.add_subparsers(dest='group', required=True)
    study = groups.add_parser('study', help='run and verify the JCI method')
    actions = study.add_subparsers(dest='action', required=True)
    for name, help_text in (
        ('smoke', 'reproduce the JCI method with real conservative FCI on a declared SCM'),
        ('jci-reliability', 'run the frozen finite-regularization SCM comparison'),
        ('jci-replay', 'replay budgeted real model outcomes with separate confirmation and test roles'),
    ):
        action = actions.add_parser(name, help=help_text)
        action.add_argument('output', type=Path)
        action.add_argument('--rscript', type=Path, required=True)
        if name == 'smoke':
            action.set_defaults(plan=Path('configs/jci-smoke.json'))
        else:
            action.add_argument('--plan', type=Path, required=True)
            action.add_argument('--limit', type=int)
        if name != 'jci-replay':
            action.add_argument('--workers', type=int)
    for name in ('verify-jci-reliability', 'verify-jci-replay'):
        action = actions.add_parser(name, help='independently reconstruct the saved JCI results')
        action.add_argument('output', type=Path)
        if name == 'verify-jci-reliability':
            action.add_argument('--workers', type=int)
    population = actions.add_parser('diagnose-jci-population', help='query exact SCM independence with real FCI')
    population.add_argument('parent', type=Path)
    population.add_argument('output', type=Path)
    population.add_argument('--rscript', type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.action in ('smoke', 'jci-reliability'):
        from prompt_mechanism_study.experiment.jci_reliability import run_reliability
        result = run_reliability(args.plan, args.output, args.rscript,
                                 limit=getattr(args, 'limit', None), workers=args.workers)
    elif args.action == 'jci-replay':
        from prompt_mechanism_study.experiment.jci_replay import run_budget_replay
        result = run_budget_replay(args.plan, args.output, args.rscript, limit=args.limit)
    elif args.action == 'verify-jci-reliability':
        from prompt_mechanism_study.verification.jci_reliability import verify_reliability
        result = verify_reliability(args.output, args.workers)
    elif args.action == 'verify-jci-replay':
        from prompt_mechanism_study.verification.jci_replay import verify_budget_replay
        result = verify_budget_replay(args.output)
    else:
        from prompt_mechanism_study.verification.jci_reliability import diagnose_population_information
        result = diagnose_population_information(args.parent, args.output, args.rscript)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
