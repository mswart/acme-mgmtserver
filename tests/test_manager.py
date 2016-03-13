import os
import shutil

import pytest
import acme.jose

from acmems import exceptions, server
from tests.helpers import M, MA, gencsr


### load private key

def test_key_load():
    m = M('''[account]
        dir = tests/support/valid
        [listeners]''')
    m.load_private_key()
    assert type(m.key) is acme.jose.JWKRSA
    assert m.key.thumbprint() == b'\xfe\xb1\xaa\xf8\xc8&\xb6v\x1f\xd3Jc\xbc\x80\xb0ie\xf6\xf6\xb9x$\x14\xf9\x1b\x99{\xe6\x91L\x89\x9e'


def test_no_key_file():
    m = M('''[account]
        dir = tests/support/notexisting
        [listeners]''')
    with pytest.raises(exceptions.AccountError) as e:
        m.load_private_key()
    assert 'account.pem not found' in str(e)


### create private key

def test_create_key(tmpdir):
    m = M('''[account]
        dir = {}
        [listeners]'''.format(tmpdir))
    m.create_private_key()
    assert type(m.key) is acme.jose.JWKRSA


def test_override_key(tmpdir):
    m = M('''[account]
        dir = {}
        [listeners]'''.format(tmpdir))
    shutil.copyfile('tests/support/valid/account.pem', str(tmpdir.join('account.pem')))
    with pytest.raises(exceptions.AccountError) as e:
        m.create_private_key()
    assert 'force' in str(e)
    assert 'Existing key is only override if I am forced to' in str(e)
    m.create_private_key(force=True)
    assert type(m.key) is acme.jose.JWKRSA
    assert m.key.thumbprint() != b'\xfe\xb1\xaa\xf8\xc8&\xb6v\x1f\xd3Jc\xbc\x80\xb0ie\xf6\xf6\xb9x$\x14\xf9\x1b\x99{\xe6\x91L\x89\x9e'


### register

@pytest.mark.boulder
def test_register(tmpdir):
    m = M('''[account]
        dir = {}
        acme-server = http://127.0.0.1:4000/directory
        [listeners]'''.format(tmpdir))
    m.create_private_key()
    m.init_client()
    m.register(emails=['acme-{}@example.org'.format(os.getpid())])
    tos = m.tos_agreement_required()
    with pytest.raises(exceptions.NeedToAgreeToTOS) as e:
        m.refresh_registration()
    assert e.value.url == tos
    assert m.tos_agreement_required() == tos
    m.accept_terms_of_service(tos)


### refresh registration

@pytest.mark.boulder
def test_refresh_registration_for_unknown_key():
    m = M('''[account]
        dir = tests/support/valid
        acme-server = http://127.0.0.1:4000/directory
        [listeners]''')
    m.load_private_key()
    assert type(m.key) is acme.jose.JWKRSA
    m.init_client()
    assert type(m.client) is acme.client.Client
    with pytest.raises(exceptions.AccountError) as e:
        m.refresh_registration()
    assert 'Key is not yet registered' in str(e)


### domain verificateion

@pytest.mark.boulder
def test_auto_domain_verification(registered_account_dir, http_server):
    server.ACMEAbstractHandler.manager = MA(registered_account_dir)
    authzrs = server.ACMEAbstractHandler.manager.acquire_domain_validations(['www.example.com', 'mail.example.com'])
    assert len(authzrs) is 2
    assert authzrs[0].body.status.name == 'valid'
    assert authzrs[1].body.status.name == 'valid'
    assert authzrs[0].body.identifier.value == 'www.example.com'
    assert authzrs[1].body.identifier.value == 'mail.example.com'


@pytest.mark.boulder
def test_invalid_domain_verification(registered_account_dir, http_server):
    m = server.ACMEAbstractHandler.manager = MA(registered_account_dir)
    with pytest.raises(exceptions.InvalidDomainName) as e:
        m.acquire_domain_validations(['test.invalid'])
    assert 'test.invalid' in str(e)


### certificate creation

@pytest.mark.boulder
def test_certificate_creation(registered_account_dir, http_server, ckey):
    domains = ['www.example{}.org'.format(os.getpid()), 'mail.example{}.org'.format(os.getpid())]
    csr = gencsr(domains, ckey)
    m = server.ACMEAbstractHandler.manager = MA(registered_account_dir)
    authzrs = m.acquire_domain_validations(domains)
    assert len(authzrs) is 2
    certs = m.issue_certificate(csr, authzrs)
    assert len(certs) == 2


@pytest.mark.boulder
def test_rate_limit_on_certificate_creation(registered_account_dir, http_server, ckey):
    domains = ['example-rate{}.org'.format(os.getpid())]
    csr = gencsr(domains, ckey)
    m = server.ACMEAbstractHandler.manager = MA(registered_account_dir)
    authzrs = m.acquire_domain_validations(domains)
    assert len(authzrs) is 1
    for i in range(2):
        certs = m.issue_certificate(csr, authzrs)
        assert len(certs) == 2
    with pytest.raises(exceptions.RateLimited) as e:
        m.issue_certificate(csr, authzrs)
    assert domains[0] in str(e)
