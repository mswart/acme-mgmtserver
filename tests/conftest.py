import os
from threading import Thread

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import sys
import os.path

parent = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if os.path.isdir(os.path.join(parent, 'acmems')):
    sys.path.insert(0, parent)

from tests.helpers import M
from acmems import server, challenges


@pytest.fixture(scope='session')
def registered_account_dir(tmpdir_factory):
    account_dir = tmpdir_factory.mktemp('account')
    m = M('''[account]
        dir = {}
        acme-server = http://127.0.0.1:4000/directory
        [mgmt]'''.format(account_dir))
    m.create_private_key()
    m.init_client()
    m.register(emails=['acme-{}-permanent@example.org'.format(os.getpid())])
    if m.tos_agreement_required():
        m.accept_terms_of_service(m.tos_agreement_required())
    return account_dir


@pytest.fixture(scope='session')
def ckey():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    return key


@pytest.fixture(scope='session')
def http_server(request):
    validator = challenges.setup('http01', (('listener', '127.0.0.1:5002'),))
    services = validator.start()

    def fin():
        for service, thread in services:
            service.shutdown()
            thread.join()
    request.addfinalizer(fin)
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
