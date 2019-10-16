import os
import urllib.request
import urllib.error
import http.client
import hmac
import hashlib

import pytest
from OpenSSL import crypto

from tests.helpers import M, MA, gencsrpem, extract_alt_names, randomize_domains
from acmems import server, auth


class BindingHTTPHandler(urllib.request.AbstractHTTPHandler):
    # must be in front
    handler_order = 10

    def __init__(self, source_address, **kwargs):
        super().__init__(**kwargs)
        self.source_address = source_address

    def http_open(self, req):
        return self.do_open(http.client.HTTPConnection, req,
                            source_address=self.source_address)

    http_request = urllib.request.AbstractHTTPHandler.do_request_

open127801 = urllib.request.build_opener(BindingHTTPHandler(('127.8.0.1', 0)))
open127001 = urllib.request.build_opener(BindingHTTPHandler(('127.0.0.1', 0)))


#### http server


def test_for_404_for_unknown_requests(http_server):
    server.ACMEAbstractHandler.manager = M('''[account]
        dir = tests/support/valid/
        [mgmt]''', connect=False)
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen('http://{}:5002/file_not_found'.format(os.getenv('FAKE_DNS', '127.0.0.1')))
    assert e.value.code == 404


#### mgmt server

def test_mgmt_for_404_for_unknown_requests(mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''[account]
        dir = tests/support/valid/
        [mgmt]''', connect=False)
    csr = gencsrpem(['test.example.org'], ckey)
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen('http://127.0.0.1:{}/signing'.format(mgmt_server.server_port), csr)
    assert e.value.code == 404


def test_mgmt_reject_sign_with_wrong_ip(http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''
        [account]
        dir = tests/support/valid
        acme-server = http://127.0.0.1:4001/directory
        [mgmt]
        [auth "localhost"]
        ip = 127.0.0.0/24
        domain=*
        ''')
    csr = gencsrpem(['test.example.org'], ckey)
    with pytest.raises(urllib.error.HTTPError) as e:
        open127801.open('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    assert e.value.code == 403


def test_mgmt_reject_correct_ip_but_missing_sign(http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''
        [account]
        dir = tests/support/valid
        acme-server = http://127.0.0.1:4001/directory
        [mgmt]
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        ''')
    csr = gencsrpem(['test.example.org'], ckey)
    with pytest.raises(urllib.error.HTTPError) as e:
        open127001.open('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    assert e.value.code == 403


def test_mgmt_reject_correct_ip_but_wrong_hmac_key(http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''
        [account]
        dir = tests/support/valid
        acme-server = http://127.0.0.1:4001/directory
        [mgmt]
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        ''')
    csr = gencsrpem(['test.example.org'], ckey)
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'tXEuu1TEpg6Q31oJDMuGNQKVm', csr, digestmod=hashlib.sha256).hexdigest()
    request.add_header('Authentication', 'hmac name=sha256, hash={}'.format(hash))
    with pytest.raises(urllib.error.HTTPError) as e:
        open127001.open(request)
    assert e.value.code == 403


def test_mgmt_reject_correct_ip_but_wrong_hmac_type(http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''
        [account]
        dir = tests/support/valid
        acme-server = http://127.0.0.1:4001/directory
        [mgmt]
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        ''')
    csr = gencsrpem(['test.example.org'], ckey)
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'oiFDiu1uEM7xSzdUnQdTbyYAr', csr, digestmod=hashlib.sha384).hexdigest()
    request.add_header('Authentication', 'hmac name=sha384, hash={}'.format(hash))
    with pytest.raises(urllib.error.HTTPError) as e:
        open127001.open(request)
    assert e.value.code == 403


def test_mgmt_reject_too_long_csr(backend, http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M(backend.registered_account + '''
        max-size = 512
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        ''', connect=True)
    domains = randomize_domains('www', 'mail', suffix='.fullexample{}.org')
    csr = gencsrpem(domains, ckey)
    assert len(csr) > 512
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'oiFDiu1uEM7xSzdUnQdTbyYAr', csr, digestmod=hashlib.sha256).hexdigest()
    request.add_header('Authentication', 'hmac name=sha256, hash={}'.format(hash))
    with pytest.raises(urllib.error.HTTPError) as e:
        open127001.open(request)
    assert e.value.code == 413


def test_mgmt_reject_invalid_csr(backend, http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M(backend.registered_account + '''
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        ''', connect=True)
    domains = randomize_domains('www', 'mail', suffix='.fullexample{}.org')
    csr = gencsrpem(domains, ckey)
    csr = csr[340:] + csr[:340]
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'oiFDiu1uEM7xSzdUnQdTbyYAr', csr, digestmod=hashlib.sha256).hexdigest()
    request.add_header('Authentication', 'hmac name=sha256, hash={}'.format(hash))
    with pytest.raises(urllib.error.HTTPError) as e:
        open127001.open(request)
    assert e.value.code == 415


def test_mgmt_complete_multiple_domains(backend, http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M(backend.registered_account + '''
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        ''', connect=True, validator=http_server)
    domains = randomize_domains('www', 'mail', suffix='.fullexample{}.org')
    csr = gencsrpem(domains, ckey)
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'oiFDiu1uEM7xSzdUnQdTbyYAr', csr, digestmod=hashlib.sha256).hexdigest()
    request.add_header('Authentication', 'hmac name=sha256, hash={}'.format(hash))
    response = urllib.request.urlopen(request)
    certs = response.read().split(b'\n\n')
    assert len(certs) == 2
    x509 = [crypto.load_certificate(crypto.FILETYPE_PEM, cert) for cert in certs]
    assert x509[0].get_subject().CN == domains[0]
    #assert x509[0].get_issuer() == x509[1].get_subject()
    assert x509[0].has_expired() is False
    assert x509[1].has_expired() is False
    assert sorted(extract_alt_names(x509[0])) == sorted(domains)


def test_mgmt_complete_one_domain(backend, http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = MA(backend.registered_account, validator=http_server)
    domains = randomize_domains('debug.fullexample{}.org')
    csr = gencsrpem(domains, ckey)
    response = urllib.request.urlopen('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    certs = response.read().split(b'\n\n')
    assert len(certs) == 2
    x509 = [crypto.load_certificate(crypto.FILETYPE_PEM, cert) for cert in certs]
    assert x509[0].get_subject().CN == domains[0]
    #assert x509[0].get_issuer() == x509[1].get_subject()
    assert x509[0].has_expired() is False
    assert x509[1].has_expired() is False
    assert sorted(extract_alt_names(x509[0])) == sorted(domains)


def test_mgmt_complete_one_domain_by_dns(backend, dnsboulder_validator, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M(backend.registered_account + '''
        [verification "boulder"]
        type = dns01-boulder
        [auth "localhost"]
        ip = 127.0.0.0/24
        domain=*
        ''', connect=True, validator=dnsboulder_validator)
    domains = randomize_domains('debug.fullexample{}.org')
    csr = gencsrpem(domains, ckey)
    response = urllib.request.urlopen('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    certs = response.read().split(b'\n\n')
    assert len(certs) == 2
    x509 = [crypto.load_certificate(crypto.FILETYPE_PEM, cert) for cert in certs]
    assert x509[0].get_subject().CN == domains[0]
    #assert x509[0].get_issuer() == x509[1].get_subject()
    assert x509[0].has_expired() is False
    assert x509[1].has_expired() is False
    assert sorted(extract_alt_names(x509[0])) == sorted(domains)


def test_mgmt_complete_wildcard_domain(backend, dnsboulder_validator, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M(backend.registered_account + '''
        [verification "boulder"]
        type = dns01-boulder
        [auth "localhost"]
        ip = 127.0.0.0/24
        domain=*
        ''', connect=True, validator=dnsboulder_validator)
    domains = randomize_domains('fullexample{}.org', '*.fullexample{}.org')
    csr = gencsrpem(domains, ckey)
    response = urllib.request.urlopen('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    certs = response.read().split(b'\n\n')
    assert len(certs) == 2
    x509 = [crypto.load_certificate(crypto.FILETYPE_PEM, cert) for cert in certs]
    assert x509[0].get_subject().CN == domains[0]
    #assert x509[0].get_issuer() == x509[1].get_subject()
    assert x509[0].has_expired() is False
    assert x509[1].has_expired() is False
    assert sorted(extract_alt_names(x509[0])) == sorted(domains)


def test_mgmt_for_certificate_error(backend, http_server, mgmt_server, ckey):
    backend.registered_manager(validator=http_server)
    domains = randomize_domains('error.fullexample{}.org')
    csr = gencsrpem(domains, ckey)
    backend.add_servfail_response(domains[0])
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    assert e.value.code == 421


def test_complete_rate_limit_on_certificate_creation(backend, http_server, mgmt_server, ckey):
    if backend.name == 'pebble':
        return pytest.skip('Rate limiting is not implemented in pebble!')
    backend.registered_manager(validator=http_server)
    domains = randomize_domains('debug.fullexample{}.org')
    csr = gencsrpem(domains, ckey)
    for i in range(5):
        response = urllib.request.urlopen('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
        certs = response.read()
        assert b'-----BEGIN CERTIFICATE-----' in certs
        assert b'-----END CERTIFICATE-----' in certs
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    assert e.value.code == 429
