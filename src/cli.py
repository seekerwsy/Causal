"""Single active CLI entry point for Prompt TSG inspection and directional JCI learning."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence


def _build_parser():
    parser = argparse.ArgumentParser(
        prog='prompt-mechanism-study',
        description='Task-grounded Prompt TSG inspection and context-anchored directional JCI learning.',
    )
    groups = parser.add_subparsers(dest='group', required=True)
    study = groups.add_parser('study', help='run active Stage I/II inspection, learning, and verification')
    actions = study.add_subparsers(dest='action', required=True)

    smoke = actions.add_parser('smoke', help='run bounded 8-cell directional JCI cross-fitting smoke check (4 scenarios incl. negative control)')
    smoke.add_argument('output', type=Path)
    smoke.add_argument('--rscript', type=Path, default=None)
    smoke.add_argument('--workers', type=int, default=1)
    smoke.set_defaults(plan=Path('configs/jci-directional-grouped-smoke.json'))

    run = actions.add_parser('run', help='execute a directional JCI cross-fitting study plan')
    run.add_argument('output', type=Path)
    run.add_argument('--plan', type=Path, required=True)
    run.add_argument('--rscript', type=Path, default=None)
    run.add_argument('--workers', type=int, default=1)

    verify = actions.add_parser('verify', help='independently verify saved directional JCI results')
    verify.add_argument('output', type=Path)
    verify.add_argument('--workers', type=int, default=1)

    inspect_tsg = actions.add_parser(
        'inspect-tsg',
        help='compile source Prompt TSG and extract Stage I -> Stage II structural attributes',
    )
    inspect_tsg.add_argument('input', type=Path)
    inspect_tsg.add_argument('output', type=Path)
    return parser


def _run_inspect_tsg(input_path: Path, output_dir: Path) -> dict:
    from prompt_mechanism_study.artifact_io import read_json, write_bundle
    from prompt_mechanism_study.tsg.prompt_contract import compile_source_propositions
    from prompt_mechanism_study.tsg.prompt_tsg import source_requirement_inventory
    from prompt_mechanism_study.tsg.source_representation import extract_tsg_structural_attributes

    payload = read_json(input_path)
    task = payload['task']
    record = payload['record']
    target = payload.get('target', {})
    graph, compiled = compile_source_propositions(task, record, extractor_id='cli-inspect-tsg')
    ids = compiled['local_node_ids']
    op_id = ids.get(target.get('operation_local_id')) if target.get('operation_local_id') else None
    req_id = ids.get(target.get('requirement_local_id')) if target.get('requirement_local_id') else None
    inventory = source_requirement_inventory(graph, prompt=task['prompt'], catalog=compiled['catalog'])
    attributes = extract_tsg_structural_attributes(
        graph,
        operation_node_id=op_id,
        requirement_node_id=req_id,
        prompt=task['prompt'],
        catalog=compiled['catalog'],
    )
    output_payload = {
        'task_unit_id': task['task_unit_id'],
        'tsg_id': graph.tsg_id,
        'inventory_root_count': len(inventory['inventory_root_node_ids']),
        'unresolved_candidate_count': len(inventory['unresolved_candidate_node_ids']),
        'attributes': attributes,
    }
    write_bundle(output_dir, {'attributes.json': output_payload})
    return output_payload


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.action in ('smoke', 'run'):
        from prompt_mechanism_study.discovery.prognostic_learning import run_directional_study

        result = run_directional_study(args.plan, args.output, rscript=args.rscript, workers=args.workers)
    elif args.action == 'verify':
        from prompt_mechanism_study.verification.prognostic_learning import verify_directional_study

        result = verify_directional_study(args.output, workers=args.workers)
    elif args.action == 'inspect-tsg':
        result = _run_inspect_tsg(args.input, args.output)
    else:
        raise ValueError(f'Unknown action: {args.action}')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
