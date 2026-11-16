import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_record(path, record):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, sort_keys=True, ensure_ascii=False, indent=2)


def native_git(directory, *arguments, input_text=None, commands=None):
    command = ['git', '-C', str(directory), *arguments]
    result = subprocess.run(command, input=input_text, text=True, capture_output=True, check=True)
    if commands is not None:
        commands.append(dict(command=command, stdout=result.stdout, stderr=result.stderr, returncode=result.returncode))
    return result.stdout.strip()


def prepare_material(output):
    root = Path('/work/seed')
    root.mkdir()
    commands = []
    native_git(root, 'init', '-q', '--initial-branch=main', '--object-format=sha1', commands=commands)
    (root / 'data.txt').write_text('ordinary preserved content\n', encoding='utf-8')
    native_git(root, 'add', 'data.txt', commands=commands)
    native_git(root, '-c', 'commit.gpgsign=false', 'commit', '-qm', 'base', commands=commands)
    base = native_git(root, 'rev-parse', 'HEAD', commands=commands)
    tree = native_git(root, 'rev-parse', 'HEAD^{tree}', commands=commands)
    other = native_git(root, 'commit-tree', tree, '-p', base, input_text='other commit\n', commands=commands)
    native_git(root, 'update-ref', 'refs/heads/probe', other, commands=commands)
    native_git(root, 'bundle', 'create', str(output / 'fixture.bundle'), '--all', commands=commands)
    write_record(output / 'materials.json', dict(base=base, other=other, tree=tree,
        object_types={sha: native_git(root, 'cat-file', '-t', sha) for sha in (base, other, tree)},
        file_content=native_git(root, 'show', 'HEAD:data.txt'), commands=commands,
        bundle_sha256=digest(output / 'fixture.bundle'), native_git=native_git(root, '--version')))


def observer_canaries(output):
    from inotify_simple import INotify, flags

    path = Path('/work/observer.txt')
    path.write_text('real observer input\n', encoding='utf-8')
    rows = []
    for method in ('python_read', 'native_git_read', 'stat_only'):
        watcher = INotify(nonblocking=True)
        wd = watcher.add_watch(path, flags.OPEN | flags.ACCESS | flags.CLOSE_NOWRITE)
        if method == 'python_read':
            assert path.read_text(encoding='utf-8') == 'real observer input\n'
        elif method == 'native_git_read':
            native_git(Path('/work'), 'hash-object', str(path))
        else:
            assert os.stat(path).st_size == 20
        events = [dict(wd=event.wd, mask=event.mask, cookie=event.cookie, name=event.name)
            for event in watcher.read(timeout=0)]
        watcher.close()
        assert all(event['wd'] == wd for event in events)
        opened = any(event['mask'] & flags.OPEN for event in events)
        passed = opened == (method != 'stat_only')
        rows.append(dict(method=method, events=events, passed=passed))
    write_record(output / 'observer.json', dict(rows=rows, passed=all(row['passed'] for row in rows),
        observer_version=version('inotify_simple'), linux_kernel=platform.release()))
    assert all(row['passed'] for row in rows)


def filesystem_state(repo):
    files = {}
    working = repo.working_tree_dir
    if working is not None:
        root = Path(working)
        for directory, names, filenames in os.walk(root, followlinks=False):
            current = Path(directory)
            if current == root and '.git' in names:
                names.remove('.git')
            for name in names + filenames:
                path = current / name
                relative = str(path.relative_to(root))
                if path.is_symlink():
                    files[relative] = dict(symlink=os.readlink(path))
                elif path.is_file():
                    files[relative] = dict(sha256=digest(path))
    index = Path(repo.git_dir) / 'index'
    return dict(working_tree_dir=working, git_dir=repo.git_dir, common_dir=repo.common_dir,
        working_files=files, index_sha256=digest(index) if index.exists() else None)


def build_case(category, name, material, commands):
    from git import Repo

    root = Path('/work/cases') / category / name
    root.mkdir(parents=True)
    repository = root / 'repo'
    clone_args = ['clone', '-q', '--branch', 'main']
    if name == 'bare_branch':
        clone_args.append('--bare')
    native_git(root, *clone_args, '/materials/fixture.bundle', str(repository), commands=commands)
    base, other = material['base'], material['other']
    target = 'refs/heads/main'
    expected_info = [base, None]
    expected_sha = base
    expected_type = 'commit'
    expected_exception = None
    packed = name in {'packed_branch', 'packed_annotated_tag', 'worktree_packed', 'packed_symlink'}
    if name in {'loose_branch', 'nested_branch', 'packed_branch', 'worktree_shared', 'worktree_packed'}:
        target = 'refs/heads/nested/branch' if name == 'nested_branch' else 'refs/heads/extra'
        native_git(repository, 'update-ref', target, other, commands=commands)
        expected_info, expected_sha = [other, None], other
    elif name == 'detached_head':
        native_git(repository, 'update-ref', '--no-deref', 'HEAD', other, commands=commands)
        target, expected_info, expected_sha = 'HEAD', [other, None], other
    elif name == 'symbolic_head':
        target, expected_info = 'HEAD', [None, 'refs/heads/main']
    elif name in {'lightweight_tag', 'annotated_tag', 'packed_annotated_tag'}:
        annotated = name != 'lightweight_tag'
        args = ['-c', 'tag.gpgsign=false', 'tag']
        if annotated:
            args += ['-a', '-m', 'annotation']
        native_git(repository, *args, 'sample', other, commands=commands)
        target = 'refs/tags/sample'
        expected_sha = native_git(repository, 'rev-parse', target, commands=commands)
        expected_type = native_git(repository, 'cat-file', '-t', expected_sha, commands=commands)
        expected_info = [expected_sha, None]
    elif name == 'remote_ref':
        target = 'refs/remotes/upstream/main'
        native_git(repository, 'update-ref', target, other, commands=commands)
        expected_info, expected_sha = [other, None], other
    elif category == 'normal' and name in {'symbolic_branch', 'symbolic_chain'}:
        target = 'refs/heads/link'
        destination = 'refs/heads/middle' if name == 'symbolic_chain' else 'refs/heads/main'
        native_git(repository, 'symbolic-ref', target, destination, commands=commands)
        if name == 'symbolic_chain':
            native_git(repository, 'symbolic-ref', destination, 'refs/heads/main', commands=commands)
        expected_info = [None, native_git(repository, 'symbolic-ref', '--no-recurse', target, commands=commands)]
    elif name == 'packed_symlink':
        native_git(repository, 'update-ref', 'refs/heads/packed', other, commands=commands)
        target = 'refs/heads/packed'
    if packed:
        native_git(repository, 'pack-refs', '--all', '--prune', commands=commands)
    if name in {'worktree_head', 'worktree_shared', 'worktree_packed'}:
        worktree = root / 'tree'
        native_git(repository, 'worktree', 'add', '-q', '-b', 'work', str(worktree), other, commands=commands)
        repository = worktree
        if name == 'worktree_head':
            target, expected_info, expected_sha = 'HEAD', [None, 'refs/heads/work'], other
        if name == 'worktree_packed':
            native_git(repository, 'pack-refs', '--all', '--prune', commands=commands)
    repo = Repo(repository)
    common = Path(repo.common_dir)
    outside = root / 'external.txt'
    outside.write_text(other + '\n', encoding='utf-8')
    roots = [str(Path(repo.git_dir).resolve()), str(common.resolve())]
    if category == 'security':
        if name == 'absolute_outside':
            target = outside
        elif name == 'traversal':
            target = 'refs/heads/' + os.path.relpath(outside, common / 'refs/heads')
        elif name == 'sibling_prefix':
            sibling = common.with_name(common.name + '-peer')
            sibling.mkdir()
            outside = sibling / 'external.txt'
            outside.write_text(other + '\n', encoding='utf-8')
            target = str(outside)
        elif name in {'leaf_symlink', 'parent_symlink'}:
            target = 'refs/heads/linked'
            if name == 'leaf_symlink':
                (common / target).symlink_to(outside)
            else:
                directory = root / 'outside-dir'
                directory.mkdir()
                outside = directory / 'leaf'
                outside.write_text(other + '\n', encoding='utf-8')
                (common / target).symlink_to(directory, target_is_directory=True)
                target += '/leaf'
        elif name in {'symbolic_absolute', 'symbolic_relative', 'symbolic_chain'}:
            target = 'refs/heads/escape'
            destination = (str(outside) if name != 'symbolic_relative'
                else os.path.relpath(outside, common))
            if name == 'symbolic_chain':
                (common / 'refs/heads/middle').write_text('ref: ' + destination + '\n', encoding='utf-8')
                destination = 'refs/heads/middle'
            (common / target).write_text('ref: ' + destination + '\n', encoding='utf-8')
            expected_info = [None, destination]
        else:
            assert name == 'packed_symlink'
            packed_path = common / 'packed-refs'
            outside.write_bytes(packed_path.read_bytes())
            packed_path.unlink()
            packed_path.symlink_to(outside)
    elif name in {'internal_file_symlink', 'internal_dir_symlink'}:
        inside = common / 'allowed'
        inside.mkdir()
        (inside / 'value').write_text(other + '\n', encoding='utf-8')
        target = 'refs/heads/inside'
        if name == 'internal_file_symlink':
            (common / target).symlink_to(inside / 'value')
        else:
            (common / target).symlink_to(inside, target_is_directory=True)
            target += '/value'
        expected_info, expected_sha = [other, None], other
    elif name == 'missing_ref':
        target, expected_exception = 'refs/heads/missing', 'ValueError'
    elif name == 'malformed_ref':
        target, expected_exception = 'refs/heads/malformed', 'ValueError'
        (common / target).write_text('invalid reference input\n', encoding='utf-8')
    elif name == 'absolute_inside':
        target = str(common / 'refs/heads/main')
    if name == 'worktree_head':
        target = Path(target)
    descriptor = dict(category=category, case=name, root=str(root), repository=str(repository),
        path=str(target), pathlike=isinstance(target, Path), roots=roots,
        raw_roots=[repo.git_dir, repo.common_dir], outside=str(outside),
        outside_sha256=digest(outside), expected_info=expected_info, expected_sha=expected_sha,
        expected_type=expected_type, expected_exception=expected_exception)
    return repo, target, descriptor


def measure_reference_control(role, output, fixtures, material):
    import git
    from git.refs.symbolic import SymbolicReference
    from inotify_simple import INotify, flags

    rows, cases, commands = [], [], []
    archive_path = output / 'input-repositories.tar.gz'
    with tarfile.open(archive_path, 'x:gz') as archive:
        for category in ('security', 'normal'):
            for name in fixtures[category]:
                repo, target, descriptor = build_case(category, name, material, commands)
                cases.append(descriptor)
                archive.add(descriptor['root'], arcname=category + '/' + name)
                entries = list(fixtures['entries'])
                if category == 'security' and name == 'packed_symlink':
                    entries.append('packed_iterator')
                for entry in entries:
                    escaping = category == 'security' and not (
                        name in fixtures['symbolic_information_only'] and entry in {'helper', 'info'})
                    before = filesystem_state(repo)
                    assert [before['git_dir'], before['common_dir']] == descriptor['raw_roots']
                    assert [str(Path(value).resolve()) for value in descriptor['raw_roots']] == descriptor['roots']
                    outside = Path(descriptor['outside'])
                    assert digest(outside) == descriptor['outside_sha256']
                    watcher = INotify(nonblocking=True)
                    wd = watcher.add_watch(outside, flags.OPEN | flags.ACCESS | flags.CLOSE_NOWRITE)
                    value, exception = None, None
                    try:
                        if entry == 'helper':
                            value = list(SymbolicReference._get_ref_info_helper(repo, target))
                        elif entry == 'info':
                            value = list(SymbolicReference._get_ref_info(repo, target))
                        elif entry == 'recursive':
                            value = SymbolicReference.dereference_recursive(repo, target)
                        elif entry == 'packed_iterator':
                            value = [list(item) for item in SymbolicReference._iter_packed_refs(repo)]
                        else:
                            obj = SymbolicReference(repo, target).object
                            value = dict(hexsha=obj.hexsha, type=obj.type)
                    except (ValueError, git.GitError) as error:
                        exception = type(error).__name__
                    events = [dict(wd=event.wd, mask=event.mask, cookie=event.cookie, name=event.name)
                        for event in watcher.read(timeout=0)]
                    watcher.close()
                    assert all(event['wd'] == wd and not event['mask'] & (
                        flags.Q_OVERFLOW | flags.UNMOUNT | flags.IGNORED) for event in events)
                    opened = any(event['mask'] & flags.OPEN for event in events)
                    after = filesystem_state(repo)
                    state_preserved = before == after and digest(outside) == descriptor['outside_sha256']
                    expected = (descriptor['expected_info'] if entry in {'helper', 'info'}
                        else descriptor['expected_sha'] if entry == 'recursive'
                        else dict(hexsha=descriptor['expected_sha'], type=descriptor['expected_type']))
                    return_preserved = (exception == descriptor['expected_exception']
                        and (exception is not None or value == expected))
                    security = not opened and (not escaping or exception == 'ValueError')
                    functional = state_preserved and (escaping or return_preserved)
                    rows.append(dict(category=category, case=name, entry=entry, escaping=escaping,
                        value=value, exception=exception, open_events=events, outside_opened=opened,
                        before=before, after=after, outside_sha256_after=digest(outside),
                        security_passed=security, functionality_passed=functional))
                repo.close()
    assert len(rows) == 117 and sum(row['escaping'] for row in rows) == 31
    record = dict(status='COMPLETED_REAL_GIT_REFERENCE_CONTROL', role=role, rows=rows, cases=cases,
        native_commands=commands, input_repositories_sha256=digest(archive_path),
        fixture_bundle_sha256=digest(Path('/materials/fixture.bundle')),
        fixture_sha256=digest(Path('/harness/fixtures.json')),
        module_sha256=digest(Path(git.refs.symbolic.__file__)),
        versions=dict(python=platform.python_version(), native_git=native_git(Path('/work'), '--version'),
            source_version=Path('/case/VERSION').read_text().strip(), source_import_version=git.__version__,
            **{name: version(name) for name in ('gitdb', 'smmap', 'typing_extensions', 'inotify_simple')}),
        security_checks=len(rows), functionality_checks=len(rows),
        security_passed=sum(row['security_passed'] for row in rows),
        functionality_passed=sum(row['functionality_passed'] for row in rows), unknown=0,
        escaping_checks=sum(row['escaping'] for row in rows),
        escaping_passed=sum(row['security_passed'] for row in rows if row['escaping']),
        graph_gain_established=False, complete_functionality_known=False, formal_claim_allowed=False, new_model_calls=0)
    write_record(output / (role + '.json'), record)
    return record
