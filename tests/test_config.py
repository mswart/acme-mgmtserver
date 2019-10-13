import io
import socket

import pytest

from acmems import config
from acmems import storages


def parse(configcontent):
    return config.Configurator(io.StringIO(configcontent))


### generall


def test_error_on_option_without_section():
    with pytest.warns(config.UnusedOptionWarning) as e:
        parse('''
            acme-server = https://acme.example.org/directory
            [account]
            [mgmt]
            ''')
    assert 'acme-server' in str(e[0].message)
    assert 'https://acme.example.org/directory' in str(e[0].message)


def test_comment():
    parse('''
        [account]
        #acme-server https://acme.example.org/directory
        [mgmt]
        ''')


### [account] acme-server

def test_acme_server_address():
    c = parse('''
[account]
acme-server = https://acme.example.org/directory
[mgmt]
''')
    assert c.acme_server == 'https://acme.example.org/directory'


def test_default_acme_server_address():
    c = parse('''[account]
        [mgmt]''')
    assert c.acme_server == 'https://acme-staging.api.letsencrypt.org/directory'


def test_error_on_multiple_acme_server_addresses():
    with pytest.raises(config.SingletonOptionRedifined) as e:
        parse('''
            [account]
            acme-server = https://acme.example.org/directory
            acme-server = https://acme2.example.org/directory
            [mgmt]
            ''')
    assert 'https://acme.example.org/directory' in str(e.value)
    assert 'https://acme2.example.org/directory' in str(e.value)


### [account] dir

def test_account_dir():
    config = parse('''
        [account]
        dir = /tmp/test
        [mgmt]
        ''')
    assert config.account_dir == '/tmp/test'


### [account] unknown option

def test_warning_on_unknown_account_option():
    with pytest.warns(config.UnusedOptionWarning) as e:
        parse('''
            [account]
            acme_server = https://acme.example.org/directory
            [mgmt]
            ''')
    assert 'acme_server' in str(e[0].message)
    assert 'https://acme.example.org/directory' in str(e[0].message)


### [mgmt] mgmt


def test_simple_mgmt_listener():
    config = parse('''
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        listener=127.0.0.1:13
        listener=[fe80::abba:abba%lo]:1380
        ''')
    assert len(config.mgmt_listeners) is 2
    l = config.mgmt_listeners
    assert l[0][0] is socket.AF_INET
    assert l[0][4][0] == '127.0.0.1'
    assert l[0][4][1] == 13
    assert l[1][0] is socket.AF_INET6
    assert l[1][4][0] == 'fe80::abba:abba%lo'
    assert l[1][4][1] == 1380


def test_default_mgmt_listener():
    config = parse('''
        [account]
        [mgmt]
        ''')
    assert len(config.mgmt_listeners) is 2
    l = config.mgmt_listeners
    assert l[0][0] is socket.AF_INET
    assert l[0][4][0] == '127.0.0.1'
    assert l[0][4][1] == 1313
    assert l[1][0] is socket.AF_INET6
    assert l[1][4][0] == '::1'
    assert l[1][4][1] == 1313


def test_disable_mgmt_listener():
    config = parse('''
        [account]
        [mgmt]
        listener=
        ''')
    assert len(config.mgmt_listeners) is 0


def test_unix_socket_as_mgmt_listener():
    with pytest.raises(config.ConfigurationError) as e:
        parse('''
            [account]
            [mgmt]
            listener=/run/acmems/mgmt.sock
            ''')
    assert 'unix socket' in str(e.value)


### [mgmt] max size

def test_default_max_size_options():
    p = parse('''
        [account]
        [mgmt]
        ''')
    assert p.max_size == 4096


def test_max_size_options_in_bytes():
    p = parse('''
        [account]
        [mgmt]
        max-size = 2394
        ''')
    assert p.max_size == 2394


def test_max_size_options_in_kbytes():
    p = parse('''
        [account]
        [mgmt]
        max-size = 4k
        ''')
    assert p.max_size == 4096


def test_max_size_options_in_mbytes():
    p = parse('''
        [account]
        [mgmt]
        max-size = 1m
        ''')
    assert p.max_size == 1024 * 1024


### [mgmt] unknown option

def test_warning_on_unknown_mgmt_option():
    with pytest.warns(config.UnusedOptionWarning) as e:
        parse('''
            [account]
            [mgmt]
            manager = https://acme.example.org/directory
            ''')
    assert 'manager' in str(e[0].message)
    assert 'https://acme.example.org/directory' in str(e[0].message)


### unknown section

def test_warning_on_unknown_section():
    with pytest.warns(config.UnusedSectionWarning) as e:
        parse('''
            [account]
            [mgmt]
            [unknown]
            ''')
    assert 'unknown' in str(e[0].message)


### http verification

def test_simple_http_listener():
    config = parse('''
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-verification=http
        [verification "http"]
        type=http01
        listener=127.0.0.1:80
        listener=[::]:80
        ''')
    assert tuple(config.validators.keys()) == ('http', )
    assert len(config.validators['http'].listeners) is 2
    l = config.validators['http'].listeners
    assert l[0][0] is socket.AF_INET
    assert l[0][4][0] == '127.0.0.1'
    assert l[0][4][1] is 80
    assert l[1][0] is socket.AF_INET6
    assert l[1][4][0] == '::'
    assert l[1][4][1] is 80


def test_unix_socket_as_http_listener():
    with pytest.raises(config.ConfigurationError) as e:
        parse('''
            [account]
            [mgmt]
            default-verification=http
            [verification "http"]
            type=http01
            listener=/run/acmems/http.sock
            ''')
    assert 'unix socket' in str(e.value)


### dns verification

def test_dns01_listener_default_options():
    config = parse('''
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-verification=dns
        [verification "dns"]
        type=dns01-dnsUpdate
        ''')
    assert tuple(config.validators.keys()) == ('dns', )
    v = config.validators['dns']
    assert v.dns_servers == ['127.0.0.1']
    assert v.timeout is 5
    assert v.ttl is 60


def test_dns01_listener_with_explicit_options():
    config = parse('''
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-verification=
        [verification "dns"]
        type=dns01-dnsUpdate
        dns-server = 127.0.0.2
        timeout = 6
        ttl = 61
        ''')
    assert tuple(config.validators.keys()) == ('dns', )
    v = config.validators['dns']
    assert v.dns_servers == ['127.0.0.2']
    assert v.timeout is 6
    assert v.ttl is 61


#### default verification


def test_default_http_listener():
    config = parse('''
        [account]
        [mgmt]
        ''')
    assert tuple(config.validators.keys()) == ('http', )
    assert len(config.validators['http'].listeners) is 2
    l = config.validators['http'].listeners
    assert l[0][0] is socket.AF_INET
    assert l[0][4][0] == '0.0.0.0'
    assert l[0][4][1] == 1380
    assert l[1][0] is socket.AF_INET6
    assert l[1][4][0] == '::'
    assert l[1][4][1] == 1380


def test_disable_http_listener():
    config = parse('''
        [account]
        [mgmt]
        default-verification=
        ''')
    assert config.default_validator is False


def test_use_single_verification_as_default():
    config = parse('''
        [account]
        [mgmt]
        [verification "http234"]
        type = http01
        ''')
    assert tuple(config.validators.keys()) == ('http234', )
    assert config.default_validator is config.validators['http234']


### storages


def test_explict_none_storage():
    config = parse('''
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-storage = ntest
        [storage "ntest"]
        type = none
        ''')
    assert set(config.storages) == set(('ntest',))
    assert type(config.storages['ntest']) is storages.NoneStorageImplementor


def test_not_other_none_storage_options():
    with pytest.raises(config.ConfigurationError) as e:
        parse('''
            [account]
            acme-server = https://acme.example.org/directory
            [mgmt]
            default-storage = ntest
            [storage "ntest"]
            type = none
            other = test
            ''')
    assert 'other' in str(e.value)


def test_implicit_default_storage():
    config = parse('''
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        ''')
    assert set(config.storages) == set(('none',))


def test_use_single_stroage_as_default():
    config = parse('''
        [account]
        [mgmt]
        [storage "io"]
        type = file
        directory = /tmp
        ''')
    assert tuple(config.storages.keys()) == ('io', )
    assert config.default_storage is config.storages['io']
