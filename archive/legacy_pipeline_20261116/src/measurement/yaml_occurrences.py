import ast
import datetime
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
import sys
import tomllib

import cbor2
import umsgpack
import yaml


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_value(value):
    if isinstance(value, dict):
        return dict(mapping=[[canonical_value(key), canonical_value(item)]
            for key, item in sorted(value.items(), key=lambda pair: repr(pair[0]))])
    if isinstance(value, (list, tuple)):
        return {type(value).__name__: [canonical_value(item) for item in value]}
    if isinstance(value, set):
        return dict(set=sorted([canonical_value(item) for item in value], key=lambda item: json.dumps(item, sort_keys=True)))
    if isinstance(value, bytes):
        return dict(bytes_hex=value.hex())
    if isinstance(value, (datetime.datetime, datetime.date)):
        return {type(value).__name__: value.isoformat()}
    assert value is None or isinstance(value, (str, int, float, bool))
    return value


def parse_output(output_format, payload):
    if output_format == 'json':
        return json.loads(payload)
    if output_format == 'toml':
        return tomllib.loads(payload.decode('utf-8'))
    if output_format == 'yaml':
        return yaml.safe_load(payload)
    if output_format == 'cbor':
        return cbor2.loads(payload)
    assert output_format == 'msgpack'
    return umsgpack.unpackb(payload)


def expected_output(document, fixture, output_format):
    value = document[fixture['unwrap']] if fixture.get('unwrap') is not None else document
    if output_format == 'toml' and fixture.get('stringify'):
        value = 'null' if value is None else {key: 'null' if item is None else item for key, item in value.items()}
    if output_format == 'json' and fixture['name'] == 'timestamp':
        value = dict(when=value['when'].isoformat())
    return dict(result=value)


def phase_lines(source):
    tree = ast.parse(source)
    function, = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'remarshal']
    result = {}
    for node in function.body:
        if not isinstance(node, ast.Try):
            continue
        for statement in node.body:
            if not isinstance(statement, ast.If):
                continue
            test = statement.test
            name = test.id if isinstance(test, ast.Name) else test.left.id if (
                isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)) else None
            if name in {'unwrap', 'wrap', 'transform'}:
                result[statement.lineno] = name
    assert set(result.values()) == {'unwrap', 'wrap', 'transform'}
    return result


def measure_yaml_control(role, output, fixtures):
    import remarshal

    source_path = Path(remarshal.__file__)
    lines = phase_lines(source_path.read_text(encoding='utf-8'))
    calls = output / 'calls'
    calls.mkdir()
    rows = []
    for fixture in fixtures['yaml_cases']:
        payload_path = Path('/inputs') / fixture['file']
        payload = payload_path.read_bytes()
        assert digest(payload_path) == fixture['sha256']
        security_case = fixture['category'] == 'security'
        document = None if security_case else yaml.safe_load(payload)
        entries = [('decode_yaml', None), ('decode', None)] + [('remarshal', fmt) for fmt in fixture['formats']]
        for entry, output_format in entries:
            counts = {}

            def observe(frame, event, arg):
                if frame.f_code.co_filename != str(source_path):
                    return None
                key = None
                if event == 'call' and (frame.f_code.co_name.startswith('encode') or frame.f_code.co_name == 'traverse'):
                    key = 'call:' + frame.f_code.co_name
                elif event == 'line' and frame.f_code.co_name == 'remarshal' and frame.f_lineno in lines:
                    key = 'phase:' + lines[frame.f_lineno]
                if key is not None:
                    counts[key] = counts.get(key, 0) + 1
                return observe

            filename = fixture['category'] + '-' + fixture['name'] + '-' + entry + '-' + str(output_format)
            destination = calls / filename
            value, exception = None, None
            sys.settrace(observe)
            try:
                if entry == 'decode_yaml':
                    value = remarshal.decode_yaml(payload)
                elif entry == 'decode':
                    value = remarshal.decode('yaml', payload)
                else:
                    remarshal.remarshal(payload_path, destination, 'yaml', output_format, transform=None,
                        unwrap=fixture.get('unwrap'), wrap='result', ordered=fixture.get('ordered', True),
                        stringify=fixture.get('stringify', False))
            except (ValueError, TypeError, RecursionError) as error:
                exception = type(error).__name__
            finally:
                sys.settrace(None)
            returned_type = type(value).__name__ if exception is None else None
            output_file = str(destination.relative_to(output)) if destination.exists() else None
            returned = None
            ordered = None
            if not security_case and exception is None:
                if entry == 'remarshal':
                    actual = parse_output(output_format, destination.read_bytes())
                    expected = expected_output(document, fixture, output_format)
                else:
                    actual, expected = value, document
                returned = canonical_value(actual)
                functional = returned == canonical_value(expected)
                if fixture['name'] in {'ordered_keys', 'sorted_keys'}:
                    actual_keys = list(actual['result'] if entry == 'remarshal' else actual)
                    sort_requested = entry == 'remarshal' and output_format in {'json', 'toml', 'yaml'} and not fixture.get('ordered', True)
                    wanted = ['alpha', 'zeta'] if sort_requested else ['zeta', 'alpha']
                    ordered = actual_keys == wanted
                    functional = functional and ordered
            else:
                functional = False if not security_case else None
            secure = exception == 'ValueError' and not counts if security_case else None
            rows.append(dict(category=fixture['category'], case=fixture['name'], entry=entry, output_format=output_format,
                exception=exception, returned_type=returned_type, returned=returned, phase_counts=counts,
                output_file=output_file, output_sha256=digest(destination) if output_file else None,
                order_preserved=ordered, security_passed=secure, functionality_passed=functional))
    for fixture in fixtures['other_cases']:
        payload_path = Path('/inputs') / fixture['file']
        document = parse_output(fixture['input_format'], payload_path.read_bytes())
        assert digest(payload_path) == fixture['sha256']
        for entry in ('decode', 'remarshal'):
            destination = calls / (fixture['name'] + '-' + entry)
            if entry == 'decode':
                value = remarshal.decode(fixture['input_format'], payload_path.read_bytes())
                expected = document
            else:
                remarshal.remarshal(payload_path, destination, fixture['input_format'], 'yaml', wrap='result')
                value = yaml.safe_load(destination.read_bytes())
                expected = dict(result=document)
            rows.append(dict(category='other', case=fixture['name'], entry=entry, input_format=fixture['input_format'],
                returned=canonical_value(value), output_file=str(destination.relative_to(output)) if destination.exists() else None,
                output_sha256=digest(destination) if destination.exists() else None,
                security_passed=None, functionality_passed=canonical_value(value) == canonical_value(expected)))
    cli_rows = []
    for name, category in (('ordinary_mapping', 'normal'), ('flat_sequence', 'security'), ('self_sequence', 'security'), ('invalid_arguments', 'normal')):
        destination = calls / ('cli-' + name)
        if name == 'invalid_arguments':
            command = [sys.executable, str(source_path), '--not-a-real-option']
        else:
            fixture, = [row for row in fixtures['yaml_cases'] if row['name'] == name]
            command = [sys.executable, str(source_path), '--if', 'yaml', '--of', 'json' if category == 'normal' else 'yaml',
                str(Path('/inputs') / fixture['file']), str(destination), '--wrap', 'result']
        completed = subprocess.run(command, capture_output=True, timeout=30, check=False)
        passed = completed.returncode == (2 if name == 'invalid_arguments' else 0 if category == 'normal' else 1)
        if category == 'security':
            passed = passed and b'Error:' in completed.stderr and destination.exists() and destination.read_bytes() == b''
        elif name == 'ordinary_mapping':
            source_fixture, = [row for row in fixtures['yaml_cases'] if row['name'] == name]
            passed = passed and json.loads(destination.read_bytes()) == dict(result=yaml.safe_load((Path('/inputs') / source_fixture['file']).read_bytes()))
        cli_rows.append(dict(case=name, category=category, command=command, returncode=completed.returncode,
            stdout_hex=completed.stdout.hex(), stderr=completed.stderr.decode('utf-8'), passed=passed,
            output_file=str(destination.relative_to(output)) if destination.exists() else None,
            output_sha256=digest(destination) if destination.exists() else None))
    record = dict(status='COMPLETED_REAL_REMARSHAL_GRAPH_CONTROL', role=role, rows=rows, cli=cli_rows,
        fixture_sha256=digest(Path('/inputs/fixtures.json')), module_sha256=digest(source_path), phase_lines=lines,
        versions=dict(python=platform.python_version(), source_version=remarshal.__version__,
            **{name: version(name) for name in ('cbor2', 'python-dateutil', 'PyYAML', 'tomlkit', 'u-msgpack-python', 'six', 'networkx')}),
        security_checks=79, functionality_checks=122,
        security_passed=sum(row['security_passed'] for row in rows if row['category'] == 'security')
            + sum(row['passed'] for row in cli_rows if row['category'] == 'security'),
        functionality_passed=sum(row['functionality_passed'] for row in rows if row['category'] != 'security')
            + sum(row['passed'] for row in cli_rows if row['category'] == 'normal'),
        unknown=0, graph_gain_established=False, complete_functionality_known=False,
        parse_resource_bound_established=False, formal_claim_allowed=False, new_model_calls=0)
    assert len(rows) == 197 and len(cli_rows) == 4
    with (output / (role + '.json')).open('x', encoding='utf-8') as stream:
        json.dump(record, stream, sort_keys=True, ensure_ascii=False, indent=2)
    return record
