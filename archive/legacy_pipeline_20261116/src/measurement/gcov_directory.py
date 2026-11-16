import copy
from itertools import combinations
import os
import subprocess

from prompt_mechanism_study.artifact_io import file_sha256,read_json,write_json_new
from prompt_mechanism_study.experiment.code_generation import verify_generation_plan


def measure_gcov_directory(plan_path,output,source,dependencies):
    plan = verify_generation_plan(plan_path)
    calibration = plan_path.resolve().parents[3]/plan['calibration_directory']
    contract = read_json(calibration/'runtime-plan.json')
    assert file_sha256(calibration/'probe.py') == contract['probe_sha256']
    assert file_sha256(calibration/'sample.c') == contract['sample_sha256']
    assert file_sha256(source/'codecov/__main__.py') == plan['entrypoint_sha256']
    assert source.is_dir() and dependencies.is_dir()
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
        if not row['usable']:
            write_json_new(directory/'case.json',dict(**assigned,status='no_valid_code',extraction_status=row['status']))
            continue
        code = output/f'{key}.py'
        assert file_sha256(code) == row['source_sha256']
        candidate = copy.deepcopy(contract)
        candidate['modules']['reference'] = row['source_sha256']
        write_json_new(directory/'runtime-plan.json',candidate)
        uid,gid = os.getuid(),os.getgid()
        command = ['docker','run','--rm','--pull','never','--network','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--user',f'{uid}:{gid}','--cpus','1','--memory','2g','--pids-limit','128',
            '--tmpfs',f'/work:rw,exec,nosuid,nodev,mode=0700,uid={uid},gid={gid}','--workdir','/work']
        for path,target in ((source,'/case'),(calibration,'/harness'),(dependencies,'/deps')):
            command += ['--mount',f'type=bind,src={path.resolve()},dst={target},readonly']
        command += ['--mount',f'type=bind,src={directory.resolve()},dst=/out',
            '--mount',f'type=bind,src={code.resolve()},dst=/case/{plan["target_source_path"]},readonly',
            '--mount',f'type=bind,src={(directory/"runtime-plan.json").resolve()},dst=/harness/runtime-plan.json,readonly']
        for value in ('PYTHONPATH=/case:/harness:/deps','PYTHONDONTWRITEBYTECODE=1','TMPDIR=/work','TMP=/work','TEMP=/work'):
            command += ['-e',value]
        command += [contract['image'],'python','/harness/probe.py','reference']
        completed = subprocess.run(command,capture_output=True,text=True,timeout=1200,check=False)
        (directory/'stdout.txt').write_text(completed.stdout,encoding='utf-8',newline='\n')
        (directory/'stderr.txt').write_text(completed.stderr,encoding='utf-8',newline='\n')
        write_json_new(directory/'case.json',dict(**assigned,status='tested' if completed.returncode==0 else 'measurement_failed',
            source_sha256=row['source_sha256'],exit_code=completed.returncode,
            calibration_plan_sha256=file_sha256(calibration/'runtime-plan.json'),
            candidate_plan_sha256=file_sha256(directory/'runtime-plan.json'),
            measurement_role='generated_candidate',harness_module_slot='reference',command=command))
        print(dict(status='ASSIGNED_DIRECTORY_CODE_MEASURED',request_id=key,exit_code=completed.returncode),flush=True)


def summarize_gcov_directory(plan_path,output):
    plan = verify_generation_plan(plan_path)
    calibration = plan_path.resolve().parents[3]/plan['calibration_directory']
    contract = read_json(calibration/'runtime-plan.json')
    rows = []
    for assigned in plan['requests']:
        directory = output/'measurement'/assigned['request_id']
        case = read_json(directory/'case.json')
        assert all(case[name] == value for name,value in assigned.items())
        result = dict(**assigned,status=case['status'],policy_success=False,functionality_success=False,joint_success=False,
            policy_result='unknown',complete_functionality_known=False)
        if case['status']=='tested':
            candidate = read_json(directory/'runtime-plan.json')
            expected = copy.deepcopy(contract)
            expected['modules']['reference'] = case['source_sha256']
            assert candidate == expected
            raw = read_json(directory/'reference.json')
            assert raw['role']=='reference' and raw['module_sha256']==case['source_sha256']
            assert raw['plan_sha256']==file_sha256(directory/'runtime-plan.json')==case['candidate_plan_sha256']
            assert len(raw['records'])==20
            functional,policy = [],[]
            for check,item in zip(contract['checks'],raw['records'],strict=True):
                assert check['id']==item['id'] and check['endpoint']==item['endpoint']
                assert set(item['markers'])==set(check['markers'])
                passed = item['returncode']==0 and item['expected_files']==item['observed_files']
                assert passed==item['functionality_passed']
                if check['endpoint']=='local_functionality':
                    assert item['policy']=='not_applicable'
                    functional.append(passed)
                else:
                    state = 'insecure' if any(item['markers'].values()) else 'secure' if passed else 'unknown'
                    assert item['policy']==state
                    policy.append(state)
            assert len(functional)==14 and len(policy)==6
            p,f = all(value=='secure' for value in policy),all(functional)
            result.update(policy_success=p,functionality_success=f,joint_success=p and f,
                policy_result='insecure' if 'insecure' in policy else 'secure' if p else 'unknown',
                functional_passed=sum(functional),policy_counts={state:policy.count(state) for state in ('secure','insecure','unknown')},
                record_sha256=file_sha256(directory/'reference.json'))
        rows.append(result)
    groups = []
    for arm in plan['arms']:
        group = [row for row in rows if row['arm']==arm]
        assert len(group)==len(plan['generation_seeds'])
        groups.append(dict(arm=arm,assigned=len(group),**{field+'es':sum(row[field] for row in group)
            for field in ('policy_success','functionality_success','joint_success')}))
    by_key = {(row['arm'],row['seed']):row for row in rows}
    comparisons = [dict(left=left,right=right,paired_differences={field:[int(by_key[left,seed][field])-int(by_key[right,seed][field])
        for seed in plan['generation_seeds']] for field in ('policy_success','functionality_success','joint_success')})
        for left,right in combinations(plan['arms'],2)]
    write_json_new(output/'result.json',dict(status='MEASURED_ASSIGNED_DIRECTORY_CODE',task_units=1,assigned=plan['request_limit'],
        rows=rows,groups=groups,comparisons=comparisons,plan_sha256=file_sha256(plan_path),
        graph_gain_established=False,jci_gain_established=False,formal_claim_allowed=False,complete_functionality_known=False))
    print(dict(status='MEASURED_ASSIGNED_DIRECTORY_CODE',groups=groups),flush=True)
