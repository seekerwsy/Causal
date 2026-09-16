"""Frozen extraction diagnostic; not an additional production TSG path."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from time import monotonic

from prompt_mechanism_study.artifact_io import json_object, read_json, write_bundle, bundle_digest
from prompt_mechanism_study.functional_judge import bailian_complete
from prompt_mechanism_study.source_records import _validate_shape, structural_readback


class BudgetStop(Exception):
    pass


def decode(request, response, scheme):
    """Use the existing decoder; omitted auxiliary relations remain explicitly unmeasured."""
    value = deepcopy(response)
    if scheme != 'full':
        for operation in value['operations']:
            operation.update(inputs=[], results=[], precedes=[], scope_conditions=[])
    result = structural_readback(request, value)
    if scheme != 'full':
        for operation in result['operations'].values():
            for name in ('inputs', 'results', 'precedes', 'non_gating_contexts'):
                operation.pop(name)
        result['omitted_auxiliary_relations'] = 'NOT_MEASURED, never evidence of absence'
    return result


def run(base, output):
    inputs = base / 'inputs'
    plan = read_json(inputs / 'plan.json')
    config = read_json(inputs / 'evaluator.json')
    variants = read_json(inputs / 'requests.json')
    instruction = read_json(inputs / 'instructions.json')['system_prompt']
    assert not output.exists()
    output.mkdir(parents=True)
    debit, calls, results = 0, [], []

    def deliver(spec, case, stage):
        nonlocal debit
        schema = spec['response_format']['json_schema']['schema']
        prompt = instruction + '\n\nReturn a JSON object conforming to this response schema. The schema describes output structure, not additional source facts:\n' + json.dumps(schema, ensure_ascii=False, separators=(',', ':'))
        evaluator = {**config, 'response_format': spec['response_format']}
        record = dict(ordinal=len(calls) + 1, case=case, stage=stage, request=spec['request'],
                      evaluator=evaluator, system_prompt=prompt, trace={}, response_text=None,
                      response=None, error=None, schema_error=None)
        reserve = None
        started = monotonic()

        def trace(kind, payload):
            nonlocal reserve
            if kind == 'request':
                # The shared client invokes this BEFORE urlopen. Byte count bounds
                # token count conservatively; the fixed guard covers chat framing.
                reserve = (len(payload) + 1024) * plan['input_microunits_per_token'] + config['maximum_completion_tokens'] * plan['output_microunits_per_token']
                if debit + reserve > plan['maximum_conservative_cost_microunits']:
                    raise BudgetStop('Cannot reserve the next request within the existing allowance.')
                assert len(calls) < plan['maximum_provider_calls']
            record['trace'][kind] = payload.decode('utf-8')

        try:
            raw = bailian_complete(spec['request'], evaluator, prompt, source_first_delivery=True, trace=trace)
            record['response_text'] = raw.decode('utf-8')
            record['response'] = json_object(raw)
        except BudgetStop:
            raise
        except Exception as error:
            record['error'] = dict(type=type(error).__name__, message=str(error))
        if 'request' not in record['trace']:
            raise RuntimeError('Local delivery failed before submission: ' + str(record['error']))
        charge = reserve
        try:
            envelope = json.loads(record['trace']['response'])
            usage = envelope['usage']
            pt, ct = usage['prompt_tokens'], usage['completion_tokens']
            amount = pt * plan['input_microunits_per_token'] + ct * plan['output_microunits_per_token']
            if (record['error'] is None and type(pt) is int and type(ct) is int
                    and 0 < pt <= len(record['trace']['request'].encode()) + 1024
                    and 0 < ct <= config['maximum_completion_tokens']
                    and envelope['model'] == config['model_id']
                    and envelope['choices'][0]['finish_reason'] == 'stop' and amount <= reserve):
                charge = amount
        except (KeyError, TypeError, ValueError, IndexError):
            pass
        if record['response'] is not None:
            try:
                _validate_shape(record['response'], schema)
            except Exception as error:
                record['schema_error'] = str(error)
        debit += charge
        record.update(conservative_cost_microunits=charge, reserve_microunits=reserve,
                      elapsed_seconds=round(monotonic() - started, 3))
        calls.append(record)
        write_bundle(output / 'calls' / f'{len(calls):02d}', {'call.json': record})
        print(f"{case} {stage}: {record['error'] or record['schema_error'] or 'retained'}; debit={debit / 1e6:.6f}", flush=True)
        return record

    stopped = False
    for item in plan['schedule']:
        scheme, repeat = item['scheme'], item['repeat']
        case = f'{scheme}-{repeat}'
        result = dict(case=case, scheme=scheme, repeat=repeat, call_ordinals=[], response=None,
                      readback=None, error=None, status='NOT_RUN_BUDGET' if stopped else 'PENDING')
        try:
            if not stopped:
                spec = deepcopy(variants['focused' if scheme == 'staged' else scheme])
                if scheme == 'staged':
                    draft = deliver(variants['inventory'], case, 'inventory')
                    result['call_ordinals'].append(draft['ordinal'])
                    if draft['error'] or draft['schema_error']:
                        raise ValueError('Inventory failed; dependent binding call was not run.')
                    spec['request'].update(draft_bindings=draft['response'],
                        stage_instruction='The draft is untrusted previous model output, not an answer key. Re-read the complete original source. Convert the complete meaning bindings to the requested records; independently recover omissions and correct unsupported draft claims. Do not preserve a draft error merely for consistency.')
                record = deliver(spec, case, 'records')
                result['call_ordinals'].append(record['ordinal'])
                result['response'] = record['response']
                if record['error'] or record['schema_error']:
                    raise ValueError(str(record['error'] or record['schema_error']))
                result['readback'] = decode(spec['request'], record['response'], scheme)
                result['status'] = 'EXTRACTED_NOT_SEMANTICALLY_CERTIFIED'
        except BudgetStop as error:
            stopped = True
            result.update(status='NOT_COMPLETED_BUDGET', error=str(error))
        except Exception as error:
            result.update(status='EXTRACTION_FAILED', error=str(error))
        results.append(result)
        write_bundle(output / 'cases' / case, {'result.json': result})
    report = dict(actual_provider_calls=len(calls), actual_conservative_cost_microunits=debit,
                  remaining_authorized_microunits=plan['maximum_conservative_cost_microunits'] - debit,
                  input_bundle_sha256=bundle_digest(inputs), planned_cases=len(plan['schedule']),
                  completed_extractions=sum(r['status'] == 'EXTRACTED_NOT_SEMANTICALLY_CERTIFIED' for r in results),
                  scientific_claim_allowed=False, review_calls=0, repair_calls=0, code_generation_calls=0)
    write_bundle(output / 'summary', {'results.json': results, 'report.json': report})
    return report


if __name__ == '__main__':
    run(Path(sys.argv[1]), Path(sys.argv[2]))
