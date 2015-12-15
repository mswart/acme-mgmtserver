import io
import hmac

import pytest

from acmems import auth, config
from tests.helpers import gencsrpem


def args(ckey, client_ip, *domains, hmac_type=None, hmac_key=None, **headers):
    csrpem = gencsrpem(domains, ckey)
    headers['Content-Length'] = len(csrpem)
    if hmac_key and hmac_type:
        hash = hmac.new(hmac_key, csrpem, digestmod=hmac_type).hexdigest()
        headers['Authentication'] = 'hmac name={}, hash={}'.format(hmac_type, hash)
    return ((client_ip, 3405), headers, io.BytesIO(csrpem))


def test_reject_for_no_auth_block():
    a = auth.Authenticator()
    with a.process('192.0.2.34', {}, '') as p:
        assert p.acceptable() is False

# generall


def test_warning_on_unknown_option(ckey):
    a = auth.Authenticator()
    with pytest.warns(config.UnusedOptionWarning) as e:
        a.parse_block('all', [('pi', '192.0.2.34'), ('domain', '*.example.org')])
    assert 'auth "all"' in str(e[0].message)
    assert 'pi' in str(e[0].message)
    assert '192.0.2.34' in str(e[0].message)


# all auth


def test_accept_with_all_block_but_no_domains(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [('all', 'yes')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org')) as p:
        assert p.acceptable() is False


def test_accept_with_all_block_but_domains(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [('all', 'yes'), ('domain', '*.org')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org')) as p:
        assert p.acceptable() is True
        assert p.common_name == 'test.example.org'
        assert p.dns_names == ['test.example.org']


## ip auth


def test_accept_by_ip_with_correct_domain(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [('ip', '192.0.2.0/24'), ('domain', '*.example.org')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org')) as p:
        assert p.acceptable() is True


def test_accept_by_some_ip_with_correct_domain(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [('ip', '198.51.100.0/24'), ('ip', '192.0.2.0/24'), ('domain', '*.example.org')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org')) as p:
        assert p.acceptable() is True


def test_accept_by_ip_reject_by_domain(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [('ip', '192.0.2.0/24'), ('domain', '*.example.org')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.com')) as p:
        assert p.acceptable() is False


def test_accept_by_ip_reject_by_some_domain(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [('ip', '192.0.2.0/24'), ('domain', '*.example.org')])
    with a.process(*args(ckey, '192.0.2.34', 'www.example.org', 'test.example.com')) as p:
        assert p.acceptable() is False


def test_reject_by_ip(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [('ip', '192.0.2.0/24'), ('domain', '*.example.org')])
    with a.process(*args(ckey, '198.51.100.21', 'test.example.org')) as p:
        assert p.acceptable() is False


def test_reject_multiple_correct_domains_from_different_blocks(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [('ip', '192.0.2.0/24'), ('domain', '*.example.org')])
    a.parse_block('all', [('ip', '192.0.2.0/24'), ('domain', '*.example.com')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org', 'www.example.com')) as p:
        assert p.acceptable() is False


def test_accept_multiple_correct_domains(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [('ip', '192.0.2.0/24'), ('domain', 'test.example.org'), ('domain', 'www.example.com')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org', 'www.example.com')) as p:
        assert p.acceptable() is True


## hmac auth


def test_accept_by_ip_and_hmac_with_correct_domain(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [
        ('ip', '192.0.2.0/24'),
        ('hmac_type', 'sha256'),
        ('hmac_key', b'n55gzRK2UcGa8PqULwCmoeobbBw6pG'),
        ('domain', '*.example.org')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org',
                         hmac_type='sha256', hmac_key=b'n55gzRK2UcGa8PqULwCmoeobbBw6pG')) as p:
        assert p.acceptable() is True


def test_reject_by_valid_ip_but_no_hmac_with_correct_domain(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [
        ('ip', '192.0.2.0/24'),
        ('hmac_type', 'sha256'),
        ('hmac_key', b'n55gzRK2UcGa8PqULwCmoeobbBw6pG'),
        ('domain', '*.example.org')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org')) as p:
        assert p.acceptable() is False


def test_reject_by_valid_ip_but_hmac_with_wrong_key_with_correct_domain(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [
        ('ip', '192.0.2.0/24'),
        ('hmac_type', 'sha256'),
        ('hmac_key', b'n55gzRK2UcGa8PqULwCmoeobbBw6pG'),
        ('domain', '*.example.org')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org',
                         hmac_type='sha256', hmac_key=b'FM278BKEq0q9IsTxi4SNQBTVbggPWf')) as p:
        assert p.acceptable() is False


def test_reject_by_valid_ip_but_hmac_with_wrong_type_with_correct_domain(ckey):
    a = auth.Authenticator()
    a.parse_block('all', [
        ('ip', '192.0.2.0/24'),
        ('hmac_type', 'sha256'),
        ('hmac_key', b'n55gzRK2UcGa8PqULwCmoeobbBw6pG'),
        ('domain', '*.example.org')])
    with a.process(*args(ckey, '192.0.2.34', 'test.example.org',
                         hmac_type='sha384', hmac_key=b'n55gzRK2UcGa8PqULwCmoeobbBw6pG')) as p:
        assert p.acceptable() is False
