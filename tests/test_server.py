import os
import urllib.request
import urllib.error

import pytest
from pyasn1.codec.der import decoder
from OpenSSL import crypto

from tests.helpers import MA, gencsrpem
from acmems import server, auth


#### http server


def test_for_404_for_unknown_requests(http_server):
    server.ACMEAbstractHandler.manager = MA('tests/support/valid/', connect=False)
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen('http://127.0.0.1:5002/file_not_found')


#### mgmt server

def test_mgmt_for_404_for_unknown_requests(mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = MA('tests/support/valid/', connect=False)
    csr = gencsrpem(['test.example.org'], ckey)
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen('http://127.0.0.1:{}/signing'.format(mgmt_server.server_port), csr)


@pytest.mark.boulder
def test_mgmt_complete_multiple_domains(registered_account_dir, http_server, mgmt_server, ckey):
    server.ACMEAbstractHandler.manager = MA(registered_account_dir)
    domains = ['www.fullexample{}.org'.format(os.getpid()), 'mail.fullexample{}.org'.format(os.getpid())]
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
