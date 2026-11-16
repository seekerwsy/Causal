import hashlib
from pathlib import PurePosixPath
import subprocess
import tarfile


def verify_git_source_archive(path,*,tree,prefix):
    assert tree['truncated'] is False
    expected = {row['path']:row for row in tree['tree'] if row['type']=='blob'}
    observed = {}
    with tarfile.open(path,'r:gz') as archive:
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            assert not name.is_absolute() and '..' not in name.parts
            if member.isdir():
                assert member.name.rstrip('/')==prefix.rstrip('/') or member.name.startswith(prefix)
                continue
            assert member.name.startswith(prefix)
            relative = member.name[len(prefix):]
            assert relative in expected and relative not in observed
            item = expected[relative]
            if item['mode']=='120000':
                assert member.issym()
                payload = member.linkname.encode('utf-8')
                kind = 'symlink_metadata_only'
            else:
                assert item['mode'] in ('100644','100755') and member.isfile()
                assert bool(member.mode & 0o111)==(item['mode']=='100755')
                payload = archive.extractfile(member).read()
                kind = 'regular_file'
            assert len(payload)==item['size']
            actual = subprocess.run(['git','hash-object','--stdin'],input=payload,capture_output=True,check=True).stdout.decode().strip()
            assert actual==item['sha'],relative
            record = dict(git_blob=actual,git_mode=item['mode'],sha256=hashlib.sha256(payload).hexdigest(),
                bytes=len(payload),archive_member_kind=kind)
            if member.issym():
                record['link_target'] = member.linkname
            observed[relative] = record
    assert set(observed)==set(expected)
    return dict(files_verified=observed,
        gitlinks=[row for row in tree['tree'] if row['type']=='commit'],
        symlinks_created=False,source_files_extracted=False,source_executed=False)


def read_verified_source_texts(archive_path, snapshot, paths):
    digest = hashlib.sha256()
    with archive_path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    assert digest.hexdigest() == snapshot['archive_sha256']
    rows = []
    with tarfile.open(archive_path, 'r:gz') as archive:
        for path in paths:
            expected = snapshot['files_verified'][path]
            assert expected['archive_member_kind'] == 'regular_file'
            member = archive.getmember(snapshot['archive_prefix'] + path)
            assert member.isfile()
            payload = archive.extractfile(member).read()
            assert hashlib.sha256(payload).hexdigest() == expected['sha256']
            rows.append(dict(path=path, content=payload.decode('utf-8'), **expected))
    return rows
