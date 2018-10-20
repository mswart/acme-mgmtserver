import os

import pytest

from acmems import exceptions, server
from tests.helpers import MA, gencsrpem


### domain verificateion

@pytest.mark.boulder
def test_auto_domain_verification_by_dns(registered_account_dir, dnsboulder_validator, ckey):
    server.ACMEAbstractHandler.manager = MA(registered_account_dir, validator=dnsboulder_validator)
    csr = gencsrpem(['www.example.com', 'mail.example.com'], ckey)
    orderr = server.ACMEAbstractHandler.manager.acquire_domain_validations(dnsboulder_validator, csr)
    assert len(orderr.authorizations) is 2
    assert orderr.authorizations[0].body.status.name == 'valid'
    assert orderr.authorizations[1].body.status.name == 'valid'
    assert sorted(a.body.identifier.value for a in orderr.authorizations) == ['mail.example.com', 'www.example.com']


### certificate creation

@pytest.mark.boulder
def test_certificate_creation_by_dns(registered_account_dir, dnsboulder_validator, ckey):
    domains = ['www.example{}.org'.format(os.getpid()), 'mail.example{}.org'.format(os.getpid())]
    csr = gencsrpem(domains, ckey)
    m = server.ACMEAbstractHandler.manager = MA(registered_account_dir, validator=dnsboulder_validator)
    orderr = m.acquire_domain_validations(dnsboulder_validator, csr)
    assert len(orderr.authorizations) is 2
    certs = m.issue_certificate(orderr)
    assert '-----BEGIN CERTIFICATE-----' in certs
    assert '-----END CERTIFICATE-----' in certs


@pytest.mark.boulder
def test_rate_limit_on_certificate_creation_by_dns(registered_account_dir, dnsboulder_validator, ckey):
    domains = ['dnsexample-rate{}.org'.format(os.getpid())]
    csr = gencsrpem(domains, ckey)
    m = server.ACMEAbstractHandler.manager = MA(registered_account_dir, validator=dnsboulder_validator)
    for i in range(5):
        orderr = m.acquire_domain_validations(dnsboulder_validator, csr)
        assert len(orderr.authorizations) is 1
        certs = m.issue_certificate(orderr)
        assert '-----BEGIN CERTIFICATE-----' in certs
        assert '-----END CERTIFICATE-----' in certs

    orderr = m.acquire_domain_validations(dnsboulder_validator, csr)
    assert len(orderr.authorizations) is 1
    with pytest.raises(exceptions.RateLimited) as e:
        m.issue_certificate(orderr)
    assert domains[0] in str(e)
