import base64
import hashlib
import http.client
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
import json
from pathlib import Path
import platform
import selectors
import socket
import ssl
import sys
import threading
from urllib.parse import urlsplit


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def basic(credentials):
    return 'Basic ' + base64.b64encode(':'.join(credentials).encode('utf-8')).decode('ascii')


def header_values(event, name):
    return [value for key, value in event['headers'] if key.lower() == name.lower()]


class NativeServer(ThreadingHTTPServer):
    daemon_threads = False

    def handle_error(self, request, client_address):
        error = sys.exception()
        self.transport.errors.append(dict(type=type(error).__name__, message=str(error)))
        raise RuntimeError('Native transport fixture failed') from error


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        transport = self.server.transport
        case_id = self.headers['X-Study-Case']
        assert case_id == transport.active and self.headers.get('Transfer-Encoding') is None
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        event = dict(case=case_id, kind='origin', origin=self.server.study_name, method=self.command,
            path=self.path, headers=list(map(list, self.headers.raw_items())), body_hex=body.hex(),
            tls_version=self.connection.version() if isinstance(self.connection, ssl.SSLSocket) else None)
        transport.record(event)
        case = transport.cases[case_id]
        if urlsplit(self.path).path == '/redirect':
            status = case.get('redirect_status', 302)
            payload = b'redirect response'
        else:
            status = 200
            payload = json.dumps(dict(case=case_id, origin=self.server.study_name, method=self.command,
                path=self.path, body_sha256=hashlib.sha256(body).hexdigest()), sort_keys=True).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        if status != 200:
            self.send_header('Location', case['redirect_url'])
            if case.get('cookie'):
                self.send_header('Set-Cookie', 'route_cookie=' + case_id + '; Path=/')
        self.end_headers()
        self.wfile.write(payload)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        pass

    def authenticated(self, method):
        transport = self.server.transport
        case_id = transport.active if method == 'CONNECT' else self.headers['X-Study-Case']
        assert case_id == transport.active
        event = dict(case=case_id, kind='proxy', proxy=self.server.study_name, method=method,
            target=self.path, headers=list(map(list, self.headers.raw_items())))
        transport.record(event)
        accepted = self.headers.get('Proxy-Authorization') == basic(transport.fixtures['proxy_credentials'][self.server.study_name])
        if not accepted:
            self.send_response(407)
            self.send_header('Proxy-Authenticate', 'Basic realm="research"')
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
        return accepted

    def do_CONNECT(self):
        if not self.authenticated('CONNECT'):
            return
        parsed = urlsplit('//' + self.path)
        allowed = {self.server.transport.origins[name].server_port for name in ('tls1', 'tls2')}
        assert parsed.hostname == '127.0.0.1' and parsed.port in allowed
        with socket.create_connection((parsed.hostname, parsed.port), timeout=10) as upstream:
            self.send_response(200, 'Connection established')
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True
            with selectors.DefaultSelector() as selector:
                selector.register(self.connection, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, self.connection)
                while True:
                    ready = selector.select(timeout=10)
                    assert ready, 'CONNECT forwarding timed out'
                    for key, _ in ready:
                        try:
                            data = key.fileobj.recv(65536)
                            if not data:
                                return
                            key.data.sendall(data)
                        except (ConnectionResetError, BrokenPipeError):
                            return

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def forward(self):
        if not self.authenticated(self.command):
            return
        parsed = urlsplit(self.path)
        assert parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
        assert parsed.port == self.server.transport.origins['http'].server_port
        assert self.headers.get('Transfer-Encoding') is None
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        headers = {name: value for name, value in self.headers.items()
            if name.lower() not in {'proxy-authorization', 'proxy-connection', 'connection'}}
        headers['Connection'] = 'close'
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
        try:
            path = parsed.path + ('?' + parsed.query if parsed.query else '')
            connection.request(self.command, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            self.send_response(response.status, response.reason)
            for name, value in response.getheaders():
                if name.lower() not in {'connection', 'transfer-encoding', 'content-length'}:
                    self.send_header(name, value)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(payload)
        finally:
            connection.close()


class Transport:
    def __init__(self, fixtures, materials):
        self.fixtures, self.materials = fixtures, materials
        self.events, self.errors, self.cases = [], [], {}
        self.active = None
        self.lock = threading.Lock()
        self.origins, self.proxies, self.threads = {}, {}, []

    def record(self, event):
        with self.lock:
            self.events.append(dict(sequence=len(self.events), **event))

    def __enter__(self):
        for name in ('http', 'tls1', 'tls2', 'p1', 'p2'):
            server = NativeServer(('127.0.0.1', 0), ProxyHandler if name.startswith('p') else OriginHandler)
            server.transport, server.study_name = self, name
            if name.startswith('tls'):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(self.materials / 'origin.pem'), str(self.materials / 'origin.key'))
                server.socket = context.wrap_socket(server.socket, server_side=True)
            (self.proxies if name.startswith('p') else self.origins)[name] = server
            thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=0.02))
            thread.start()
            self.threads.append(thread)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for server in list(self.proxies.values()) + list(self.origins.values()):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join()
        if exc_type is None:
            assert self.errors == []

    def url(self, origin, path):
        return ('http' if origin == 'http' else 'https') + '://127.0.0.1:' + str(self.origins[origin].server_port) + path

    def proxy_url(self, proxy):
        credentials = self.fixtures['proxy_credentials'][proxy]
        return 'http://' + ':'.join(credentials) + '@127.0.0.1:' + str(self.proxies[proxy].server_port)

    def begin(self, case):
        self.active = case['case']
        self.cases[self.active] = case


def native_transport_checks(output, fixtures, materials):
    rows = []
    with Transport(fixtures, materials) as transport:
        for method in ('http_forward', 'https_connect', 'wrong_ca'):
            case = dict(case='canary-' + method)
            transport.begin(case)
            proxy = transport.proxies['p1']
            headers = {'X-Study-Case': case['case']}
            if method == 'http_forward':
                client = http.client.HTTPConnection('127.0.0.1', proxy.server_port, timeout=5)
                headers['Proxy-Authorization'] = basic(fixtures['proxy_credentials']['p1'])
                target = transport.url('http', '/final')
            else:
                context = ssl.create_default_context(cafile=str(materials / ('wrong_ca.pem' if method == 'wrong_ca' else 'ca.pem')))
                client = http.client.HTTPSConnection('127.0.0.1', proxy.server_port, timeout=5, context=context)
                client.set_tunnel('127.0.0.1', transport.origins['tls1'].server_port,
                    headers={'Proxy-Authorization': basic(fixtures['proxy_credentials']['p1'])})
                target = '/final'
            certificate_rejected = False
            try:
                client.request('GET', target, headers=headers)
                response = client.getresponse()
                payload = response.read()
                assert response.status == 200 and json.loads(payload)['case'] == case['case']
            except ssl.SSLCertVerificationError:
                assert method == 'wrong_ca'
                certificate_rejected = True
            finally:
                client.close()
            events = [row for row in transport.events if row['case'] == case['case']]
            proxies = [row for row in events if row['kind'] == 'proxy']
            origins = [row for row in events if row['kind'] == 'origin']
            passed = (len(proxies) == 1 and header_values(proxies[0], 'Proxy-Authorization') == [basic(fixtures['proxy_credentials']['p1'])]
                and all(not header_values(row, 'Proxy-Authorization') for row in origins)
                and (certificate_rejected and not origins if method == 'wrong_ca' else len(origins) == 1))
            rows.append(dict(method=method, events=events, certificate_rejected=certificate_rejected, passed=passed))
    record = dict(rows=rows, passed=all(row['passed'] for row in rows), errors=transport.errors)
    with (output / 'observer.json').open('x', encoding='utf-8') as stream:
        json.dump(record, stream, sort_keys=True, indent=2)
    assert record['passed']


def request_cases(fixtures, transport):
    rows = []
    for route in fixtures['routes']:
        for selector in fixtures['selectors']:
            for entry in fixtures['entries']:
                key = route + '-' + selector + '-' + entry
                first = 'http' if route == 'http_to_https' else 'tls1'
                final = 'tls2' if route == 'https_other_origin' else 'tls1'
                rows.append(dict(case=key, category='security', entry=entry, selector=selector, proxy='p1',
                    first=first, final=final, redirect=True, redirect_status=302, method='GET', body_hex=''))
    for name in fixtures['normal']:
        for entry in fixtures['entries']:
            first = 'http' if name in {'direct_http', 'proxy_http'} else 'tls1'
            rows.append(dict(case=name + '-' + entry, category='normal', entry=entry, selector='scheme',
                proxy=None if name.startswith('direct_') else 'p2' if name == 'proxy_https' else 'p1',
                first=first, final=first, redirect=name in {'origin_auth_redirect', 'post_307', 'cookie_redirect'},
                redirect_status=307 if name == 'post_307' else 302, method='POST' if name == 'post_307' else 'GET',
                body_hex=fixtures['post_body_hex'] if name == 'post_307' else '',
                origin_auth=name == 'origin_auth_redirect', cookie=name == 'cookie_redirect', wrong_ca=name == 'wrong_ca'))
    for row in rows:
        row['final_url'] = transport.url(row['final'], '/final?case=' + row['case'])
        row['start_url'] = transport.url(row['first'], ('/redirect' if row['redirect'] else '/final') + '?case=' + row['case'])
        row['redirect_url'] = row['final_url']
    assert len(rows) == 51
    return rows


def measure_requests_control(role, output, fixtures, materials):
    import requests
    import requests.sessions

    rows = []
    with Transport(fixtures, materials) as transport:
        cases = request_cases(fixtures, transport)
        for case in cases:
            transport.begin(case)
            if case['proxy'] is None:
                proxies = {}
            elif case['selector'] == 'all':
                proxies = dict(all=transport.proxy_url('p1'))
            elif case['selector'] == 'host':
                proxies = {'http': transport.proxy_url('p2'), 'https': transport.proxy_url('p2'),
                    'http://127.0.0.1': transport.proxy_url('p1'), 'https://127.0.0.1': transport.proxy_url('p1')}
            else:
                proxies = {scheme: transport.proxy_url(case['proxy']) for scheme in ('http', 'https')}
            kwargs = dict(headers={'X-Study-Case': case['case']}, data=bytes.fromhex(case['body_hex']),
                auth=tuple(fixtures['origin_credentials']) if case.get('origin_auth') else None)
            options = dict(proxies=proxies, verify=str(materials / ('wrong_ca.pem' if case.get('wrong_ca') else 'ca.pem')),
                timeout=5, allow_redirects=True)
            response, exception = None, None
            try:
                if case['entry'] == 'top_level':
                    response = requests.request(case['method'], case['start_url'], **kwargs, **options)
                else:
                    with requests.Session() as session:
                        session.trust_env = False
                        if case['entry'] == 'session_request':
                            response = session.request(case['method'], case['start_url'], **kwargs, **options)
                        else:
                            prepared = session.prepare_request(requests.Request(case['method'], case['start_url'], **kwargs))
                            response = session.send(prepared, **options)
            except requests.exceptions.SSLError as error:
                assert case.get('wrong_ca')
                exception = type(error).__name__
            assert transport.errors == []
            events = [row for row in transport.events if row['case'] == case['case']]
            applications = [row for row in events if row['kind'] == 'origin']
            proxy_events = [row for row in events if row['kind'] == 'proxy']
            returned = None if response is None else dict(status=response.status_code, url=response.url,
                body=response.content.decode('utf-8'), history=[row.status_code for row in response.history])
            if response is not None:
                response.close()
            expected_methods = [] if case.get('wrong_ca') else [case['method']] * (2 if case['redirect'] else 1)
            expected_origins = [] if case.get('wrong_ca') else [case['first']] + ([case['final']] if case['redirect'] else [])
            wanted_proxy_methods = ([] if case['proxy'] is None else
                ['GET' if origin == 'http' else 'CONNECT' for origin in [case['first']] + ([case['final']] if case['redirect'] else [])])
            if case['method'] == 'POST':
                wanted_proxy_methods = ['POST' if value == 'GET' else value for value in wanted_proxy_methods]
            routing = ([row['method'] for row in proxy_events] == wanted_proxy_methods
                and all(row['proxy'] == case['proxy'] and header_values(row, 'Proxy-Authorization') == [basic(fixtures['proxy_credentials'][row['proxy']])]
                    for row in proxy_events))
            functional = routing and [row['origin'] for row in applications] == expected_origins and [row['method'] for row in applications] == expected_methods
            if case.get('wrong_ca'):
                functional = functional and exception == 'SSLError' and returned is None
            else:
                wanted_paths = [urlsplit(case['start_url']).path + '?' + urlsplit(case['start_url']).query]
                if case['redirect']:
                    wanted_paths.append(urlsplit(case['final_url']).path + '?' + urlsplit(case['final_url']).query)
                functional = (functional and exception is None and returned['status'] == 200 and returned['url'] == case['final_url']
                    and returned['history'] == ([case['redirect_status']] if case['redirect'] else [])
                    and [row['path'] for row in applications] == wanted_paths
                    and all(row['body_hex'] == case['body_hex'] for row in applications)
                    and all(row['tls_version'] is not None for row in applications if row['origin'].startswith('tls')))
                expected_body = dict(case=case['case'], origin=case['final'], method=case['method'],
                    path=wanted_paths[-1], body_sha256=hashlib.sha256(bytes.fromhex(case['body_hex'])).hexdigest())
                functional = functional and json.loads(returned['body']) == expected_body
                if case.get('origin_auth'):
                    functional = functional and all(header_values(row, 'Authorization') == [basic(fixtures['origin_credentials'])] for row in applications)
                if case.get('cookie'):
                    cookies = SimpleCookie()
                    for value in header_values(applications[-1], 'Cookie'):
                        cookies.load(value)
                    functional = functional and 'route_cookie' in cookies and cookies['route_cookie'].value == case['case']
            secure = bool(returned and returned['status'] == 200 and applications
                and all(not header_values(row, 'Proxy-Authorization') for row in applications)) if case['category'] == 'security' else None
            rows.append(dict(**case, proxies=proxies, events=events, returned=returned, exception=exception,
                security_passed=secure, functionality_passed=bool(functional)))
        ports = {name: server.server_port for name, server in dict(transport.origins, **transport.proxies).items()}
    record = dict(status='COMPLETED_REAL_REQUESTS_PROXY_CONTROL', role=role, rows=rows, ports=ports,
        module_sha256=digest(Path(requests.sessions.__file__)), fixture_sha256=digest(Path('/harness/fixtures.json')),
        materials_sha256=digest(materials / 'materials.json'), backend_errors=transport.errors,
        versions=dict(python=platform.python_version(), source_version=requests.__version__, openssl=ssl.OPENSSL_VERSION,
            **{name: version(name) for name in ('urllib3', 'charset-normalizer', 'idna', 'certifi', 'cryptography', 'cffi', 'pycparser')}),
        security_checks=27, functionality_checks=51,
        security_passed=sum(row['security_passed'] for row in rows if row['category'] == 'security'),
        functionality_passed=sum(row['functionality_passed'] for row in rows), unknown=0,
        graph_gain_established=False, complete_functionality_known=False, formal_claim_allowed=False, new_model_calls=0)
    with (output / (role + '.json')).open('x', encoding='utf-8') as stream:
        json.dump(record, stream, sort_keys=True, ensure_ascii=False, indent=2)
    return record
