import os
import urllib.request
import urllib.error
import http.client
import hmac

import pytest
from pyasn1.codec.der import decoder
from OpenSSL import crypto

from tests.helpers import M, MA, gencsrpem
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
    server.ACMEAbstractHandler.manager = MA('tests/support/valid/', connect=False)
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen('http://127.0.0.1:5002/file_not_found')
    assert e.value.code == 404


#### mgmt server

def test_mgmt_for_404_for_unknown_requests(mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = MA('tests/support/valid/', connect=False)
    csr = gencsrpem(['test.example.org'], ckey)
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen('http://127.0.0.1:{}/signing'.format(mgmt_server.server_port), csr)
    assert e.value.code == 404


def test_mgmt_reject_sign_with_wrong_ip(http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''
        [account]
        dir = tests/support/valid
        acme-server = http://127.0.0.1:4000/directory
        [listeners]
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
        acme-server = http://127.0.0.1:4000/directory
        [listeners]
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
        acme-server = http://127.0.0.1:4000/directory
        [listeners]
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        ''')
    csr = gencsrpem(['test.example.org'], ckey)
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'tXEuu1TEpg6Q31oJDMuGNQKVm', csr, digestmod='sha256').hexdigest()
    request.add_header('Authentication', 'hmac name=sha256, hash={}'.format(hash))
    with pytest.raises(urllib.error.HTTPError) as e:
        open127001.open(request)
    assert e.value.code == 403


def test_mgmt_reject_correct_ip_but_wrong_hmac_type(http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''
        [account]
        dir = tests/support/valid
        acme-server = http://127.0.0.1:4000/directory
        [listeners]
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        ''')
    csr = gencsrpem(['test.example.org'], ckey)
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'oiFDiu1uEM7xSzdUnQdTbyYAr', csr, digestmod='sha384').hexdigest()
    request.add_header('Authentication', 'hmac name=sha384, hash={}'.format(hash))
    with pytest.raises(urllib.error.HTTPError) as e:
        open127001.open(request)
    assert e.value.code == 403


@pytest.mark.boulder
def test_mgmt_reject_to_long_csr(registered_account_dir, http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''
        [account]
        dir = {}
        acme-server = http://127.0.0.1:4000/directory
        [listeners]
        max-size = 512
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        '''.format(registered_account_dir), connect=True)
    domains = ['www.fullexample{}.org'.format(os.getpid()), 'mail.fullexample{}.org'.format(os.getpid())]
    csr = gencsrpem(domains, ckey)
    assert len(csr) > 512
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'oiFDiu1uEM7xSzdUnQdTbyYAr', csr, digestmod='sha256').hexdigest()
    request.add_header('Authentication', 'hmac name=sha256, hash={}'.format(hash))
    with pytest.raises(urllib.error.HTTPError) as e:
        open127001.open(request)
    assert e.value.code == 413


@pytest.mark.boulder
def test_mgmt_reject_invalid_csr(registered_account_dir, http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''
        [account]
        dir = {}
        acme-server = http://127.0.0.1:4000/directory
        [listeners]
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        '''.format(registered_account_dir), connect=True)
    domains = ['www.fullexample{}.org'.format(os.getpid()), 'mail.fullexample{}.org'.format(os.getpid())]
    csr = gencsrpem(domains, ckey)
    csr = csr[340:] + csr[:340]
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'oiFDiu1uEM7xSzdUnQdTbyYAr', csr, digestmod='sha256').hexdigest()
    request.add_header('Authentication', 'hmac name=sha256, hash={}'.format(hash))
    with pytest.raises(urllib.error.HTTPError) as e:
        open127001.open(request)
    assert e.value.code == 415


@pytest.mark.boulder
def test_mgmt_complete_multiple_domains(registered_account_dir, http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = M('''
        [account]
        dir = {}
        acme-server = http://127.0.0.1:4000/directory
        [listeners]
        [auth "localhost"]
        ip = 127.0.0.0/24
        hmac_type = sha256
        hmac_key = oiFDiu1uEM7xSzdUnQdTbyYAr
        domain=*
        '''.format(registered_account_dir), connect=True)
    domains = ['www.fullexample{}.org'.format(os.getpid()), 'mail.fullexample{}.org'.format(os.getpid())]
    csr = gencsrpem(domains, ckey)
    request = urllib.request.Request('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    hash = hmac.new(b'oiFDiu1uEM7xSzdUnQdTbyYAr', csr, digestmod='sha256').hexdigest()
    request.add_header('Authentication', 'hmac name=sha256, hash={}'.format(hash))
    response = urllib.request.urlopen(request)
    certs = response.read().split(b'\n\n')
    assert len(certs) == 2
    x509 = [crypto.load_certificate(crypto.FILETYPE_PEM, cert) for cert in certs]
    assert x509[0].get_subject().CN == domains[0]
    assert x509[0].get_issuer() == x509[1].get_subject()
    assert x509[0].has_expired() is False
    assert x509[1].has_expired() is False
    for i in range(x509[0].get_extension_count()):
        ext = x509[0].get_extension(i)
        if ext.get_short_name() != b'subjectAltName':
            continue
        general_names = auth.SubjectAltName()
        data = ext.get_data()
        dns_names = []
        decoded_dat = decoder.decode(data, asn1Spec=general_names)
        for name in decoded_dat:
            if not isinstance(name, auth.SubjectAltName):
                continue
            for entry in range(len(name)):
                component = name.getComponentByPosition(entry)
                if component.getName() != 'dNSName':
                    continue
                dns_names.append(str(component.getComponent()))
        assert sorted(dns_names) == sorted(domains)


@pytest.mark.boulder
def test_mgmt_complete_one_domain(registered_account_dir, http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = MA(registered_account_dir)
    domains = ['debug.fullexample{}.org'.format(os.getpid())]
    csr = gencsrpem(domains, ckey)
    response = urllib.request.urlopen('http://127.0.0.1:{}/sign'.format(mgmt_server.server_port), csr)
    certs = response.read().split(b'\n\n')
    assert len(certs) == 2
    x509 = [crypto.load_certificate(crypto.FILETYPE_PEM, cert) for cert in certs]
    assert x509[0].get_subject().CN == domains[0]
    assert x509[0].get_issuer() == x509[1].get_subject()
    assert x509[0].has_expired() is False
    assert x509[1].has_expired() is False
    for i in range(x509[0].get_extension_count()):
        ext = x509[0].get_extension(i)
        if ext.get_short_name() != b'subjectAltName':
            continue
        general_names = auth.SubjectAltName()
        data = ext.get_data()
        dns_names = []
        decoded_dat = decoder.decode(data, asn1Spec=general_names)
        for name in decoded_dat:
            if not isinstance(name, auth.SubjectAltName):
                continue
            for entry in range(len(name)):
                component = name.getComponentByPosition(entry)
                if component.getName() != 'dNSName':
                    continue
                dns_names.append(str(component.getComponent()))
        assert sorted(dns_names) == sorted(domains)
