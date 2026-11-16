import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import ssl
from urllib.parse import urlsplit

from prompt_mechanism_study.measurement.proxy_credentials import Transport, basic, digest, header_values


def redirect_cases(fixtures, transport):
    rows = []
    for route in fixtures['cross_routes']:
        for form in fixtures['header_forms']:
            for retry in fixtures['retry_modes']:
                for entry in fixtures['entries']:
                    rows.append(dict(category='security', profile='default', route=route, form=form, retry=retry, entry=entry))
    for route in fixtures['same_routes']:
        for form in fixtures['header_forms']:
            for entry in fixtures['entries']:
                rows.append(dict(category='normal', profile='same', route=route, form=form, retry='omitted', entry=entry))
    for custom in fixtures['custom_sets']:
        for form in fixtures['header_forms']:
            for entry in fixtures['entries']:
                rows.append(dict(category='normal', profile='custom', route='http_to_https', form=form,
                    retry='custom', custom=custom, entry=entry))
    for profile in fixtures['extra_normal']:
        entries = ['urlopen'] if profile in {'manager_headers', 'independent_followup'} else fixtures['entries']
        for entry in entries:
            rows.append(dict(category='normal', profile=profile, route='http_to_https', form='canonical', retry='omitted', entry=entry))
    for index, row in enumerate(rows):
        row['case'] = 'urllib-' + str(index).zfill(3)
        route, profile = row['route'], row['profile']
        first = 'http' if route in {'http_to_https', 'http_same_origin'} else 'tls1'
        final = {'http_to_https': 'tls1', 'https_other_origin': 'tls2', 'https_to_http': 'http',
            'http_same_origin': 'http', 'https_same_origin': 'tls1'}[route]
        if profile.startswith('proxy_'):
            first, final = 'tls1', 'tls2' if profile == 'proxy_redirect' else 'tls1'
        row.update(first=first, final=final, redirect=profile != 'proxy_direct',
            follow=profile != 'no_redirect', proxy=profile.startswith('proxy_'),
            method='POST' if profile == 'post_303' else 'GET',
            body_hex=fixtures['post_body_hex'] if profile == 'post_303' else '',
            redirect_status=303 if profile == 'post_303' else 302)
        row['start_url'] = transport.url(first, ('/redirect' if row['redirect'] else '/final') + '?case=' + row['case'])
        row['redirect_url'] = transport.url(final, '/final?case=' + row['case'])
        row['followup_url'] = transport.url(first, '/final?case=' + row['case'])
    assert len(rows) == fixtures['functionality_checks_per_control'] == 100
    assert sum(row['category'] == 'security' for row in rows) == fixtures['security_checks_per_control'] == 54
    return rows


def requested_headers(case, fixtures, header_dict):
    values = [('X-Study-Case', case['case']), ('X-Preserve', fixtures['preserved_header'])]
    if not case['proxy']:
        values += [('Authorization', fixtures['ordinary_authorization']), ('Cookie', fixtures['ordinary_cookie']),
            ('Proxy-Authorization', basic(fixtures['ordinary_proxy_credentials']))]
    if case['method'] == 'POST':
        values.append(('Content-Type', 'application/octet-stream'))
    if case['form'] == 'mixed':
        return {name.swapcase(): value for name, value in values}
    if case['form'] == 'header_dict':
        return header_dict((name.upper(), value) for name, value in values)
    return dict(values)


def evaluate_case(case, fixtures, events, responses, manager_unchanged):
    applications = [row for row in events if row['kind'] == 'origin']
    proxies = [row for row in events if row['kind'] == 'proxy']
    followed = case['redirect'] and case['follow']
    origins = [case['first']] + ([case['final']] if followed else [])
    paths = [urlsplit(case['start_url']).path + '?' + urlsplit(case['start_url']).query]
    methods, bodies = [case['method']], [case['body_hex']]
    if followed:
        paths.append(urlsplit(case['redirect_url']).path + '?' + urlsplit(case['redirect_url']).query)
        methods.append('GET' if case['profile'] == 'post_303' else case['method'])
        bodies.append('' if case['profile'] == 'post_303' else case['body_hex'])
    if case['profile'] == 'independent_followup':
        origins.append(case['first'])
        paths.append(urlsplit(case['followup_url']).path + '?' + urlsplit(case['followup_url']).query)
        methods.append('GET')
        bodies.append('')
    checks = dict(origins=[row['origin'] for row in applications] == origins,
        paths=[row['path'] for row in applications] == paths,
        methods=[row['method'] for row in applications] == methods,
        bodies=[row['body_hex'] for row in applications] == bodies,
        tls=all(row['tls_version'] for row in applications if row['origin'].startswith('tls')),
        nonsensitive=all(header_values(row, 'X-Preserve') == [fixtures['preserved_header']]
            and header_values(row, 'X-Study-Case') == [case['case']] for row in applications),
        manager_headers=manager_unchanged)
    expected_status = case['redirect_status'] if not case['follow'] else 200
    checks['responses'] = len(responses) == (2 if case['profile'] == 'independent_followup' else 1)
    checks['responses'] &= responses[0]['status'] == expected_status
    checks['history'] = [row['status'] for row in responses[0]['history']] == ([case['redirect_status']] if followed else [])
    for response_index, response in enumerate(responses):
        if response['status'] == 200:
            event_index = len(origins) - 1 if response_index else (1 if followed else 0)
            expected = dict(case=case['case'], origin=origins[event_index], method=methods[event_index],
                path=paths[event_index], body_sha256=hashlib.sha256(bytes.fromhex(bodies[event_index])).hexdigest())
            checks['responses'] &= json.loads(response['body']) == expected
        else:
            checks['responses'] &= response['body'] == 'redirect response'
        if response_index:
            checks['history'] &= response['history'] == []
    sensitive = {'Authorization': fixtures['ordinary_authorization'], 'Cookie': fixtures['ordinary_cookie'],
        'Proxy-Authorization': basic(fixtures['ordinary_proxy_credentials'])}
    removal = ({name.lower() for name in fixtures['custom_sets'][case['custom']]} if case['profile'] == 'custom'
        else {'authorization', 'cookie'})
    checks['sensitive_headers'] = True
    for index, event in enumerate(applications):
        for name, value in sensitive.items():
            if case['proxy']:
                expected = []
            elif index == 1 and followed and case['route'] not in fixtures['same_routes']:
                if name == 'Proxy-Authorization' and case['profile'] != 'custom':
                    continue
                expected = [] if name.lower() in removal else [value]
            else:
                expected = [value]
            checks['sensitive_headers'] &= header_values(event, name) == expected
    checks['post_303'] = case['profile'] != 'post_303' or (len(applications) == 2
        and header_values(applications[0], 'Content-Type') == ['application/octet-stream']
        and not header_values(applications[1], 'Content-Type'))
    checks['proxy_route'] = ([row['method'] for row in proxies] == ['CONNECT'] * len(origins)
        and all(row['proxy'] == 'p1' and header_values(row, 'Proxy-Authorization') == [basic(fixtures['proxy_credentials']['p1'])]
            and row['target'] == urlsplit(case['start_url'] if index == 0 else case['redirect_url']).netloc
            for index, row in enumerate(proxies))) if case['proxy'] else proxies == []
    secure = (responses[0]['status'] == 200 and len(applications) == 2
        and applications[-1]['origin'] == case['final'] and not header_values(applications[-1], 'Proxy-Authorization'))
    return checks, bool(secure) if case['category'] == 'security' else None


def measure_urllib_control(role, output, fixtures, materials):
    import urllib3
    import urllib3.util.retry

    rows = []
    with Transport(fixtures, materials) as transport:
        for case in redirect_cases(fixtures, transport):
            transport.begin(case)
            headers = requested_headers(case, fixtures, urllib3._collections.HTTPHeaderDict)
            manager_options = dict(cert_reqs='CERT_REQUIRED', ca_certs=str(materials / 'ca.pem'),
                timeout=urllib3.Timeout(connect=3, read=3))
            if case['proxy']:
                manager = urllib3.ProxyManager('http://127.0.0.1:' + str(transport.proxies['p1'].server_port),
                    proxy_headers={'Proxy-Authorization': basic(fixtures['proxy_credentials']['p1'])}, **manager_options)
            else:
                manager = urllib3.PoolManager(**manager_options)
            options = dict(body=bytes.fromhex(case['body_hex']), redirect=case['follow'])
            if case['profile'] in {'manager_headers', 'independent_followup'}:
                manager.headers = headers
            else:
                options['headers'] = headers
            if case['retry'] == 'integer':
                options['retries'] = 3
            elif case['retry'] in {'retry_default', 'custom'}:
                retry_options = dict(total=3)
                if case['retry'] == 'custom':
                    retry_options['remove_headers_on_redirect'] = fixtures['custom_sets'][case['custom']]
                options['retries'] = urllib3.Retry(**retry_options)
            before = list(manager.headers.items())
            responses = []
            try:
                calls = [(case['method'], case['start_url'], options)]
                if case['profile'] == 'independent_followup':
                    calls.append(('GET', case['followup_url'], {}))
                for method, url, kwargs in calls:
                    response = getattr(manager, case['entry'])(method, url, **kwargs)
                    responses.append(dict(status=response.status, body=response.data.decode('utf-8'),
                        history=[dict(status=item.status, method=item.method, redirect_location=item.redirect_location)
                            for item in response.retries.history]))
                    response.release_conn()
                manager_unchanged = before == list(manager.headers.items())
            finally:
                manager.clear()
            assert transport.errors == []
            events = [row for row in transport.events if row['case'] == case['case']]
            checks, secure = evaluate_case(case, fixtures, events, responses, manager_unchanged)
            rows.append(dict(**case, events=events, responses=responses, checks=checks,
                manager_headers_unchanged=manager_unchanged, security_passed=secure, functionality_passed=all(checks.values())))
        ports = {name: server.server_port for name, server in dict(transport.origins, **transport.proxies).items()}
    record = dict(status='COMPLETED_REAL_URLLIB3_REDIRECT_CONTROL', role=role, rows=rows, ports=ports,
        module_sha256=digest(Path(urllib3.util.retry.__file__)), fixture_sha256=digest(Path('/harness/fixtures.json')),
        materials_sha256=digest(materials / 'materials.json'), backend_errors=transport.errors,
        versions=dict(python=platform.python_version(), source_version=urllib3.__version__, openssl=ssl.OPENSSL_VERSION,
            **{name: version(name) for name in ('cryptography', 'cffi', 'pycparser')}),
        security_checks=54, functionality_checks=100, customer_calls=101,
        security_passed=sum(row['security_passed'] for row in rows if row['category'] == 'security'),
        functionality_passed=sum(row['functionality_passed'] for row in rows), unknown=0,
        graph_gain_established=False, complete_functionality_known=False, formal_claim_allowed=False, new_model_calls=0)
    with (output / (role + '.json')).open('x', encoding='utf-8') as stream:
        json.dump(record, stream, sort_keys=True, ensure_ascii=False, indent=2)
    return record
