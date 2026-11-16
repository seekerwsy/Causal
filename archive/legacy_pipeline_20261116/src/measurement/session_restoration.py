import copy
from itertools import combinations
import os
import subprocess
import xml.etree.ElementTree as ET

from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_json_new
from prompt_mechanism_study.experiment.code_generation import verify_generation_plan


def measure_session_restoration(plan_path,output,source,dependencies):
    plan = verify_generation_plan(plan_path)
    project = plan_path.resolve().parents[3]
    calibration = project/plan['calibration_directory']
    target = plan['target_source_path']
    assert source.is_dir() and dependencies.is_dir()
    image = read_json(calibration/'plan.json')['image']
    extraction = read_json(output/'extraction.json')
    assert extraction['plan_sha256'] == file_sha256(plan_path)
    rows = {row['request_id']:row for row in extraction['rows']}
    destination = output/'measurement'
    destination.mkdir(exist_ok=False)
    for assigned in plan['requests']:
        key = assigned['request_id']
        row = rows[key]
        assert all(row[name] == value for name,value in assigned.items())
        directory = destination/key
        directory.mkdir()
        (directory/'probes').mkdir()
        if not row['usable']:
            write_json_new(directory/'case.json',dict(**assigned,status='no_valid_code',extraction_status=row['status']))
            continue
        code = output/f'{key}.py'
        assert file_sha256(code) == row['source_sha256']
        materials = copy.deepcopy(read_json(calibration/'materials.json'))
        materials['reference_sha256'] = row['source_sha256']
        write_json_new(directory/'materials.json',materials)
        uid, gid = os.getuid(), os.getgid()
        command = ['docker','run','--rm','--pull','never','--network','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--user',f'{uid}:{gid}','--cpus','1','--memory','2g','--pids-limit','128',
            '--tmpfs',f'/work:rw,nosuid,nodev,mode=0700,uid={uid},gid={gid}','--workdir','/work']
        for path, destination_path in ((source,'/case'),(source,'/measurement'),(calibration,'/harness'),(dependencies,'/deps')):
            command += ['--mount',f'type=bind,src={path.resolve()},dst={destination_path},readonly']
        command += ['--mount',f'type=bind,src={directory.resolve()},dst=/out',
            '--mount',f'type=bind,src={code.resolve()},dst=/case/{target},readonly',
            '--mount',f'type=bind,src={(directory/"materials.json").resolve()},dst=/harness/materials.json,readonly']
        for environment in ('PYTHONPATH=/case:/harness:/deps','PYTHONDONTWRITEBYTECODE=1','CONTROL_ROLE=reference',
                'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1','TMPDIR=/work','TMP=/work','TEMP=/work'):
            command += ['-e',environment]

        def execute(arguments,label):
            completed = subprocess.run(command+[image]+arguments,capture_output=True,text=True,timeout=120,check=False)
            (directory/f'{label}.stdout.txt').write_text(completed.stdout,encoding='utf-8',newline='\n')
            (directory/f'{label}.stderr.txt').write_text(completed.stderr,encoding='utf-8',newline='\n')
            return completed.returncode

        endpoint_exit = execute(['python','/harness/endpoint.py'],'endpoint')
        record = dict(**assigned,source_sha256=row['source_sha256'],endpoint_exit=endpoint_exit)
        if endpoint_exit != 0:
            write_json_new(directory/'case.json',dict(**record,status='endpoint_failed'))
            continue
        endpoint = read_json(directory/'endpoint.json')
        if endpoint['status'] == 'unknown':
            write_json_new(directory/'case.json',dict(**record,status='unsupported_interface',reason=endpoint['reason']))
            continue
        assert endpoint['status'] == 'available'
        arguments = ['python','-m','pytest','-q','-c','/harness/pytest.ini','--noconftest','-p','no:cacheprovider',
            '-p','binding_plugin','--import-mode=importlib','--basetemp=/work/pytest','--junitxml=/out/report.xml',*plan['test_paths']]
        status = execute(arguments,'pytest')
        write_json_new(directory/'case.json',dict(**record,status='tested' if status in (0,1) else 'measurement_failed',pytest_exit=status))
    print(dict(status='ASSIGNED_CODE_MEASUREMENT_FINISHED',assigned=plan['request_limit']),flush=True)


def summarize_session_restoration(plan_path,output):
    plan = verify_generation_plan(plan_path)
    calibration = plan_path.resolve().parents[3]/plan['calibration_directory']
    test_plan = read_json(calibration/'plan.json')
    original = read_json(calibration/'materials.json')['snapshots']['original']['files']
    target = plan['target_source_path']
    rows = []
    for assigned in plan['requests']:
        directory = output/'measurement'/assigned['request_id']
        case_record = read_json(directory/'case.json')
        assert all(case_record[name] == value for name,value in assigned.items())
        result = dict(**assigned,status=case_record['status'],policy_success=False,functionality_success=False,joint_success=False,
            policy_result='unknown',complete_functionality_known=False)
        if case_record['status'] == 'tested':
            runtime = read_json(directory/'runtime.json')
            assert sorted(runtime['selected_tests']) == sorted(test_plan['test_identities'])
            assert runtime['exit_code'] == case_record['pytest_exit']
            assert runtime['role'] == 'reference' and runtime['natural_task_units'] == 1
            assert runtime['code_generation_calls'] == runtime['assigned_experimental_samples'] == 0
            assert any(module['path'] == '/case/'+target for module in runtime['modules'].values())
            for module in runtime['modules'].values():
                assert module['path'].startswith('/case/')
                name = module['path'][6:]
                expected = case_record['source_sha256'] if name == target else original[name]['sha256']
                assert module['sha256'] == expected
            document = ET.parse(directory/'report.xml')
            cases = {}
            for case in document.findall('./testsuite/testcase'):
                owner = case.attrib['classname'].split('.')[-1]
                identity = (owner+'::' if owner in plan['test_classes'] else '')+case.attrib['name']
                assert identity not in cases
                cases[identity] = case
            assert set(cases) == set(test_plan['test_identities']) and len(cases) == len(test_plan['test_identities'])
            passed = {name:all(case.find(tag) is None for tag in ('failure','error','skipped')) for name,case in cases.items()}
            functional = sum(passed[name] for name in test_plan['functional_test_identities'])
            security = sum(passed[name] for name in test_plan['security_test_identities'])
            errors = sum(cases[name].find('error') is not None for name in test_plan['security_test_identities'])
            skips = sum(cases[name].find('skipped') is not None for name in test_plan['security_test_identities'])
            events = [read_json(path) for path in (directory/'probes').glob('*.json')]
            complete = len(events) == len(test_plan['security_test_identities']) and {row['test_id'] for row in events} == set(test_plan['security_test_identities'])
            if complete:
                markers = [row for row in events if row['kind'] != 'same_module_disallowed_name']
                assert len(markers) == 19
                assert all(row['marker_before'] is False and row['marker_path'].startswith('/work/pytest/') for row in markers)
                imported, = [row for row in events if row['kind'] == 'forbidden_import']
                assert imported['child_source_sha256'] == case_record['source_sha256']
            policy = security == len(test_plan['security_test_identities']) and complete
            functionality = functional == len(test_plan['functional_test_identities'])
            if policy:
                assert not any(row['marker_after'] for row in markers) and imported['rejected']
            result.update(policy_success=policy,functionality_success=functionality,joint_success=policy and functionality,
                policy_result='satisfied' if policy else 'not_satisfied' if complete and not errors and not skips else 'unknown',
                functional_passed=functional,policy_passed=security,complete_policy_probes=complete,policy_errors=errors,policy_skips=skips,
                report_sha256=file_sha256(directory/'report.xml'))
        rows.append(result)
    groups = []
    for arm in plan['arms']:
        group = [row for row in rows if row['arm'] == arm]
        assert len(group) == len(plan['generation_seeds'])
        groups.append(dict(arm=arm,assigned=len(group),policy_successes=sum(row['policy_success'] for row in group),
            functionality_successes=sum(row['functionality_success'] for row in group),joint_successes=sum(row['joint_success'] for row in group)))
    by_key = {(row['arm'],row['seed']):row for row in rows}
    comparisons = [dict(left=left,right=right,paired_differences={field:[int(by_key[left,seed][field])-int(by_key[right,seed][field])
        for seed in plan['generation_seeds']] for field in ('policy_success','functionality_success','joint_success')})
        for left,right in combinations(plan['arms'],2)]
    result = dict(status='MEASURED_ASSIGNED_CODE_CONTRACT',task_units=1,assigned=plan['request_limit'],rows=rows,groups=groups,
        comparisons=comparisons,graph_gain_established=False,jci_gain_established=False,formal_claim_allowed=False,
        complete_functionality_known=False,plan_sha256=file_sha256(plan_path))
    write_json_new(output/'result.json',result)
    print(dict(status=result['status'],groups=groups),flush=True)
