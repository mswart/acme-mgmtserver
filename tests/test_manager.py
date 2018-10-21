import os
import shutil

import pytest
import acme
import josepy.jwk

from acmems import exceptions, server
from tests.helpers import M, MA, gencsrpem


### load private key

def test_key_load():
    m = M('''[account]
        dir = tests/support/valid
        [mgmt]''')
    m.load_private_key()
    assert type(m.key) is josepy.jwk.JWKRSA
    assert m.key.thumbprint() == b'\xfe\xb1\xaa\xf8\xc8&\xb6v\x1f\xd3Jc\xbc\x80\xb0ie\xf6\xf6\xb9x$\x14\xf9\x1b\x99{\xe6\x91L\x89\x9e'


def test_no_key_file():
    m = M('''[account]
        dir = tests/support/notexisting
        [mgmt]''')
    with pytest.raises(exceptions.AccountError) as e:
        m.load_private_key()
    assert 'account.pem not found' in str(e)


### create private key

def test_create_key(tmpdir):
    m = M('''[account]
        dir = {}
        [mgmt]'''.format(tmpdir))
    m.create_private_key()
    assert type(m.key) is josepy.jwk.JWKRSA


def test_override_key(tmpdir):
    m = M('''[account]
        dir = {}
        [mgmt]'''.format(tmpdir))
    shutil.copyfile('tests/support/valid/account.pem', str(tmpdir.join('account.pem')))
    with pytest.raises(exceptions.AccountError) as e:
        m.create_private_key()
    assert 'force' in str(e)
    assert 'Existing key is only override if I am forced to' in str(e)
    m.create_private_key(force=True)
    assert type(m.key) is josepy.jwk.JWKRSA
    assert m.key.thumbprint() != b'\xfe\xb1\xaa\xf8\xc8&\xb6v\x1f\xd3Jc\xbc\x80\xb0ie\xf6\xf6\xb9x$\x14\xf9\x1b\x99{\xe6\x91L\x89\x9e'


### register

def test_register_with_general_tos(backend, tmpdir):
    m = M('''[account]
        dir = {}
        acme-server = {}
        [mgmt]'''.format(tmpdir, backend.endpoint))
    m.create_private_key()
    m.init_client()
    assert m.tos_agreement_required().startswith(backend.tos_prefix)
    m.register(emails=['acme-{}@example.test'.format(os.getpid())], tos_agreement=True)
    assert not m.tos_agreement_required()


def test_register_with_specific_tos(backend, tmpdir):
    m = M('''[account]
        dir = {}
        acme-server = {}
        [mgmt]'''.format(tmpdir, backend.endpoint))
    m.create_private_key()
    m.init_client()
    assert m.tos_agreement_required().startswith(backend.tos_prefix)
    m.register(emails=['acme-{}@example.test'.format(os.getpid())], tos_agreement=m.tos_agreement_required())
    assert not m.tos_agreement_required()


def test_register_without_tos_agreement(backend, tmpdir):
    m = M('''[account]
        dir = {}
        acme-server = {}
        [mgmt]'''.format(tmpdir, backend.endpoint))
    m.create_private_key()
    m.init_client()
    assert m.tos_agreement_required()
    with pytest.raises(exceptions.NeedToAgreeToTOS) as e:
        m.register(emails=['acme-{}@example.test'.format(os.getpid())], tos_agreement=False)


def test_register_ignoring_tos_agreement(backend, tmpdir):
    m = M('''[account]
        dir = {}
        acme-server = {}
        [mgmt]'''.format(tmpdir, backend.endpoint))
    m.create_private_key()
    m.init_client()
    assert m.tos_agreement_required()
    with pytest.raises(exceptions.NeedToAgreeToTOS) as e:
        m.register(emails=['acme-{}@example.test'.format(os.getpid())], tos_agreement=None)


### refresh registration

def test_refresh_registration_for_unknown_key(backend):
    m = M('''[account]
        dir = tests/support/valid
        acme-server = {}
        [mgmt]'''.format(backend.endpoint))
    m.load_private_key()
    assert type(m.key) is josepy.jwk.JWKRSA
    m.init_client()
    assert type(m.client) is acme.client.ClientV2
    with pytest.raises(exceptions.AccountError) as e:
        m.refresh_registration()
    assert 'Key is not yet registered' in str(e)


### domain verificateion

def test_auto_domain_verification(backend, http_server, ckey):
    m = backend.registered_manager(validator=http_server)
    csr = gencsrpem(['www.example.com', 'mail.example.com'], ckey)
    orderr = m.acquire_domain_validations(http_server, csr)
    assert len(orderr.authorizations) is 2
    assert orderr.authorizations[0].body.status.name == 'valid'
    assert orderr.authorizations[1].body.status.name == 'valid'
    assert sorted(map(lambda v: v.body.identifier.value, orderr.authorizations)) \
        == ['mail.example.com', 'www.example.com']


def test_invalid_domain_verification(backend, http_server, ckey):
    if backend.name == 'pebble':
        return pytest.skip('Rate limiting is not implemented in pebble!')
    m = backend.registered_manager(validator=http_server)
    csr = gencsrpem(['test.invalid'], ckey)
    with pytest.raises(exceptions.InvalidDomainName) as e:
        m.acquire_domain_validations(http_server, csr)
    # todo: with v2 it is not possible to extract with domain is the issue
    # assert 'test.invalid' in str(e)


### certificate creation

def test_certificate_creation(backend, http_server, ckey):
    domains = ['www.example{}.org'.format(os.getpid()), 'mail.example{}.org'.format(os.getpid())]
    csr = gencsrpem(domains, ckey)
    m = backend.registered_manager(validator=http_server)
    orderr = m.acquire_domain_validations(http_server, csr)
    assert len(orderr.authorizations) is 2
    certs = m.issue_certificate(orderr)
    assert len(certs.split('\n\n')) == 2


def test_rate_limit_on_certificate_creation(backend, http_server, ckey):
    if backend.name == 'pebble':
        return pytest.skip('Rate limiting is not implemented in pebble!')
    domains = ['httpexample-rate{}.org'.format(os.getpid())]
    csr = gencsrpem(domains, ckey)
    m = backend.registered_manager(validator=http_server)
    for i in range(5):
        orderr = m.acquire_domain_validations(http_server, csr)
        assert len(orderr.authorizations) is 1
        certs = m.issue_certificate(orderr)
        assert '-----BEGIN CERTIFICATE-----' in certs
        assert '-----END CERTIFICATE-----' in certs
    orderr = m.acquire_domain_validations(http_server, csr)
    assert len(orderr.authorizations) is 1
    with pytest.raises(exceptions.RateLimited) as e:
        m.issue_certificate(orderr)
    assert domains[0] in str(e)
