import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def project_user(user):
    from octoprint.access.users import SessionUser

    if user is None:
        return None
    return dict(type=type(user).__name__, userid=user.get_id(), active=bool(user.is_active),
        session=user.session if isinstance(user, SessionUser) else None)


def user_state(manager):
    return dict(accounts={name: dict(public=user.as_dict(), password_hash=user._passwordHash)
            for name, user in sorted(manager._users.items())},
        sessions={key: project_user(user) for key, user in sorted(manager._session_users_by_session.items())},
        sessions_by_user={key: sorted(value) for key, value in sorted(manager._sessionids_by_userid.items())},
        file_sha256=digest(Path(manager._userfile)))


def measure_user_sessions(role, output, fixtures):
    import octoprint
    from octoprint.access.groups import FilebasedGroupManager
    from octoprint.access.users import FilebasedUserManager, UserManager
    from octoprint.settings import settings
    import yaml

    settings_root = Path('/work/settings')
    settings_root.mkdir()
    config_path = settings_root / 'config.yaml'
    config_path.write_text(yaml.safe_dump(dict(api=dict(key='RESEARCH_GLOBAL_API'),
        accessControl=dict(salt=fixtures['salt']))), encoding='utf-8')
    config = settings(init=True, basedir=str(settings_root), configfile=str(config_path))
    groups = FilebasedGroupManager(path=str(settings_root / 'groups.yaml'))
    rows, inputs = [], []
    input_dir = output / 'input-users'
    input_dir.mkdir()
    for category in ('security', 'normal'):
        for fixture in fixtures[category]:
            key = category + '-' + fixture['name']
            root = Path('/work') / key
            root.mkdir()
            userfile = root / 'users.yaml'
            manager = FilebasedUserManager(groups, path=str(userfile), settings=config)
            for account in fixtures['accounts']:
                manager.add_user(account['name'], fixtures['password'], account['active'], [], ['users'], apikey=account['apikey'])
            assert all(manager.check_password(row['name'], fixtures['password']) for row in fixtures['accounts'])
            actual = dict(alice1=manager.login_user(manager.find_user(userid='alice')),
                alice2=manager.login_user(manager.find_user(userid='alice')),
                bob1=manager.login_user(manager.find_user(userid='bob')))
            sessions = {name: user.session for name, user in actual.items()}
            assert len(set(sessions.values())) == 3
            symbols = dict(sessions, UNKNOWN='unknown-session-identifier', EMPTY='')
            query = dict(fixture['query'])
            if query.get('session') is not None:
                query['session'] = symbols[query['session']]
            action = fixture.get('action')
            if action == 'logout_alice1':
                manager.logout_user(actual['alice1'])
            elif action == 'logout_bob1':
                manager.logout_user(actual['bob1'])
            elif action == 'remove_alice_sessions':
                UserManager.remove_user(manager, 'alice')
            else:
                assert action is None
            input_path = input_dir / (key + '.yaml')
            input_path.write_bytes(userfile.read_bytes())
            entries = ['file'] + (['base'] if fixture['base'] else [])
            for entry in entries:
                before = user_state(manager)
                user = manager.find_user(**query) if entry == 'file' else UserManager.find_user(manager, **query)
                returned = project_user(user)
                after = user_state(manager)
                expected = None
                if category == 'normal' and fixture['expected_user'] is not None:
                    session_name = fixture['expected_session']
                    expected = dict(type='SessionUser' if session_name else 'User',
                        userid=fixture['expected_user'], active=fixture['expected_user'] != 'inactive',
                        session=sessions[session_name] if session_name else None)
                secure = returned is None if category == 'security' else None
                functional = before == after and (category == 'security' or returned == expected)
                rows.append(dict(category=category, case=fixture['name'], entry=entry, query=query,
                    sessions=sessions, returned=returned, expected=expected, before=before, after=after,
                    file_sha256_after=digest(userfile), security_passed=secure, functionality_passed=functional))
            inputs.append(dict(category=category, case=fixture['name'], file=str(input_path.relative_to(output)),
                sha256=digest(input_path), yaml_data=yaml.safe_load(input_path.read_text(encoding='utf-8'))))
    assert len(rows) == 33
    import octoprint.access.users as users_module

    record = dict(status='COMPLETED_REAL_OCTOPRINT_SESSION_CONTROL', role=role, rows=rows, inputs=inputs,
        fixture_sha256=digest(Path('/harness/fixtures.json')), module_sha256=digest(Path(users_module.__file__)),
        versions=dict(python=platform.python_version(), source_version=octoprint.__version__,
            source_revision=octoprint.__revision__, libyaml=bool(yaml.__with_libyaml__),
            **{name: version(name) for name in ('Flask', 'Werkzeug', 'Flask-Login', 'Flask-Babel', 'wrapt', 'PyYAML', 'netifaces')}),
        security_checks=15, functionality_checks=33,
        security_passed=sum(row['security_passed'] for row in rows if row['category'] == 'security'),
        functionality_passed=sum(row['functionality_passed'] for row in rows), unknown=0,
        graph_gain_established=False, complete_functionality_known=False, cookie_revocation_established=False,
        formal_claim_allowed=False, new_model_calls=0)
    with (output / (role + '.json')).open('x', encoding='utf-8') as stream:
        json.dump(record, stream, sort_keys=True, ensure_ascii=False, indent=2)
    return record
