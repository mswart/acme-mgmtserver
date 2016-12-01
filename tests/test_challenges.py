import os

import pytest

from acmems import exceptions, server
from tests.helpers import MA, gencsr


### domain verificateion

@pytest.mark.boulder
def test_auto_domain_verification_by_dns(registered_account_dir, dnsboulder_validator):
    server.ACMEAbstractHandler.manager = MA(registered_account_dir, validator=dnsboulder_validator)
    authzrs = server.ACMEAbstractHandler.manager.acquire_domain_validations(dnsboulder_validator, ['www.example.com', 'mail.example.com'])
    assert len(authzrs) is 2
    assert authzrs[0].body.status.name == 'valid'
    assert authzrs[1].body.status.name == 'valid'
    assert authzrs[0].body.identifier.value == 'www.example.com'
    assert authzrs[1].body.identifier.value == 'mail.example.com'


### certificate creation

@pytest.mark.boulder
def test_certificate_creation_by_dns(registered_account_dir, dnsboulder_validator, ckey):
    domains = ['www.example{}.org'.format(os.getpid()), 'mail.example{}.org'.format(os.getpid())]
    csr = gencsr(domains, ckey)
    m = server.ACMEAbstractHandler.manager = MA(registered_account_dir, validator=dnsboulder_validator)
    authzrs = m.acquire_domain_validations(dnsboulder_validator, domains)
    assert len(authzrs) is 2
    certs = m.issue_certificate(csr, authzrs)
    assert len(certs) == 2


@pytest.mark.boulder
def test_rate_limit_on_certificate_creation_by_dns(registered_account_dir, dnsboulder_validator, ckey):
    domains = ['dnsexample-rate{}.org'.format(os.getpid())]
    csr = gencsr(domains, ckey)
    m = server.ACMEAbstractHandler.manager = MA(registered_account_dir, validator=dnsboulder_validator)
    authzrs = m.acquire_domain_validations(dnsboulder_validator, domains)
    assert len(authzrs) is 1
    for i in range(6):
        certs = m.issue_certificate(csr, authzrs)
        assert len(certs) == 2
    with pytest.raises(exceptions.RateLimited) as e:
        m.issue_certificate(csr, authzrs)
    assert domains[0] in str(e)
