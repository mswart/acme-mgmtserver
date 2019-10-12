import json
import os
from urllib.request import urlopen
from threading import Thread
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend


parent = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if os.path.isdir(os.path.join(parent, 'acmems')):
    sys.path.insert(0, parent)

from tests.helpers import M, MA
from acmems import server, challenges


class ACMEBackend():
    def __init__(self, name, endpoint, tos_prefix):
        self.name = name
        self.endpoint = endpoint
        self.tos_prefix = tos_prefix

    def __repr__(self):
        return 'ACMEBackend<{}>'.format(self.name)

    @property
    def challtestapi(self):
        port = os.getenv('CHALLTEST_PORT_' + self.name.upper(), 8055)
        return 'http://127.0.0.1:' + str(port)

    def register_account(self, tmpdir_factory):
        account_dir = tmpdir_factory.mktemp('account-' + self.name)
        conf = '''[account]
            dir = {}
            acme-server = {}
            [mgmt]\n'''.format(account_dir, self.endpoint)
        m = M(conf)
        m.create_private_key()
        m.init_client()
        m.register(emails=['acme-{}-permanent@example.test'.format(os.getpid())],
                   tos_agreement=True)
        self.registered_account = conf

    def registered_manager(self, validator=None):
        manager = MA(self.registered_account, validator=validator)
        server.ACMEAbstractHandler.manager = manager
        return manager

    def set_default_ipv4(self):
        ''' Configure the challengetest server to return the
            FAKE_DNS address if not otherwise specifed'''
        ip = os.getenv('FAKE_DNS')
        if not ip:
            return
        task = json.dumps({'ip': ip}).encode('utf-8')
        urlopen(self.challtestapi + '/set-default-ipv4', task)


test_backends = [
    ACMEBackend('boulder', 'http://127.0.0.1:4001/directory', 'https:'),
    ACMEBackend('pebble', 'https://127.0.0.1:14000/dir', 'data:')
]


@pytest.fixture(scope='session', name='backend',
                ids=[b.name for b in test_backends], params=test_backends)
def acme_backend(request, tmpdir_factory):
    backend = request.param
    backend.register_account(tmpdir_factory)
    backend.set_default_ipv4()
    return backend


@pytest.fixture(scope='session', params=['rsa', 'ec'])
def ckey(request):
    if request.param == 'rsa':
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    if request.param == 'ec':
        return ec.generate_private_key(ec.SECP384R1(), default_backend())


@pytest.fixture(scope='session')
def http_server(request):
    validator = challenges.setup('http01', 'http',
        (('listener', os.getenv('FAKE_DNS', '127.0.0.1') + ':5002'),)
    )
    services = validator.start()

    def fin():
        for service, thread in services:
            service.shutdown()
            thread.join()
    request.addfinalizer(fin)
    return validator


@pytest.fixture(scope='session')
def dnsboulder_validator(backend):
    validator = challenges.setup('dns01-boulder', 'dns',
                                 (('set-txt_url', backend.challtestapi + '/set-txt'), ))
    validator.start()
    return validator


@pytest.fixture(scope='session')
def dnslib_validator(request):
    validator = challenges.setup('dns01-server', 'dns', (('listener', os.getenv('FAKE_DNS', '127.0.0.1') + ':5053'),))
    validator.start()
    return validator


@pytest.fixture(scope='session')
def mgmt_server(request):
    mgmt_service = server.ThreadedACMEServerInet4(('127.0.0.1', 0), server.ACMEMgmtHandler)
    thread = Thread(target=mgmt_service.serve_forever,
                    daemon=True,
                    name='http service to server validation request')
    thread.start()

    def fin():
        mgmt_service.shutdown()
        thread.join()
    request.addfinalizer(fin)
    return mgmt_service
