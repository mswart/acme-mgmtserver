import os

import pytest

from acmems import exceptions, server
from tests.helpers import MA, gencsrpem, randomize_domains


### domain verificateion


def test_auto_domain_verification_by_dns(backend, dnsboulder_validator, ckey):
    m = backend.registered_manager(validator=dnsboulder_validator)
    domains = randomize_domains("www", "mail", suffix=".example{}.com")
    csr = gencsrpem(domains, ckey)
    orderr = m.acquire_domain_validations(dnsboulder_validator, csr)
    assert len(orderr.authorizations) is 2
    assert orderr.authorizations[0].body.status.name == "valid"
    assert orderr.authorizations[1].body.status.name == "valid"
    assert sorted(a.body.identifier.value for a in orderr.authorizations) == sorted(domains)


### certificate creation


def test_certificate_creation_by_dns(backend, dnsboulder_validator, ckey):
    domains = randomize_domains("www", "mail", suffix=".example{}.org")
    csr = gencsrpem(domains, ckey)
    m = backend.registered_manager(validator=dnsboulder_validator)
    orderr = m.acquire_domain_validations(dnsboulder_validator, csr)
    assert len(orderr.authorizations) is 2
    certs = m.issue_certificate(orderr)
    assert "-----BEGIN CERTIFICATE-----" in certs
    assert "-----END CERTIFICATE-----" in certs


def test_rate_limit_on_certificate_creation_by_dns(backend, dnsboulder_validator, ckey):
    if backend.name == "pebble":
        return pytest.skip("Rate limiting is not implemented in pebble!")
    domains = randomize_domains("dnsexample-rate{}.org")
    csr = gencsrpem(domains, ckey)
    m = backend.registered_manager(validator=dnsboulder_validator)
    for i in range(5):
        orderr = m.acquire_domain_validations(dnsboulder_validator, csr)
        assert len(orderr.authorizations) is 1
        certs = m.issue_certificate(orderr)
        assert "-----BEGIN CERTIFICATE-----" in certs
        assert "-----END CERTIFICATE-----" in certs

    with pytest.raises(exceptions.RateLimited) as e:
        orderr = m.acquire_domain_validations(dnsboulder_validator, csr)
        assert len(orderr.authorizations) is 1
        m.issue_certificate(orderr)
    assert domains[0] in str(e.value)
