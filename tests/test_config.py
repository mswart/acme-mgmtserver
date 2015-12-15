import io
import socket

import pytest

from acmems import config


def parse(configcontent):
    return config.Configurator(io.StringIO(configcontent))


### generall


def test_error_on_option_without_section():
    with pytest.warns(config.UnusedOptionWarning) as e:
        parse('''
            acme-server = https://acme.example.org/directory
            [account]
            [listeners]
            ''')
    assert 'acme-server' in str(e[0].message)
    assert 'https://acme.example.org/directory' in str(e[0].message)


def test_comment():
    parse('''
        [account]
        #acme-server https://acme.example.org/directory
        [listeners]
        ''')


### [account] acme-server

def test_acme_server_address():
    c = parse('''
[account]
acme-server = https://acme.example.org/directory
[listeners]
''')
    assert c.acme_server == 'https://acme.example.org/directory'


def test_default_acme_server_address():
    c = parse('''[account]
        [listeners]''')
    assert c.acme_server == 'https://acme-staging.api.letsencrypt.org/directory'


def test_error_on_multiple_acme_server_addresses():
    with pytest.raises(config.SingletonOptionRedifined) as e:
        parse('''
            [account]
            acme-server = https://acme.example.org/directory
            acme-server = https://acme2.example.org/directory
            [listeners]
            ''')
    assert 'https://acme.example.org/directory' in str(e)
    assert 'https://acme2.example.org/directory' in str(e)


### [account] dir

def test_account_dir():
    config = parse('''
        [account]
        dir = /tmp/test
        [listeners]
        ''')
    assert config.account_dir == '/tmp/test'


### [account] unknown option

def test_warning_on_unknown_account_option():
    with pytest.warns(config.UnusedOptionWarning) as e:
        parse('''
            [account]
            acme_server = https://acme.example.org/directory
            [listeners]
            ''')
    assert 'acme_server' in str(e[0].message)
    assert 'https://acme.example.org/directory' in str(e[0].message)


### [listeners] http


def test_simple_http_listener():
    config = parse('''
        [account]
        acme-server = https://acme.example.org/directory
        [listeners]
        http=127.0.0.1:80
        http=[::]:80
        ''')
    assert len(config.http_listeners) is 2
    l = config.http_listeners
    assert l[0][0] is socket.AF_INET
    assert l[0][4][0] == '127.0.0.1'
    assert l[0][4][1] is 80
    assert l[1][0] is socket.AF_INET6
    assert l[1][4][0] == '::'
    assert l[1][4][1] is 80


def test_default_http_listener():
    config = parse('''
        [account]
        [listeners]
        ''')
    assert len(config.http_listeners) is 2
    l = config.http_listeners
    assert l[0][0] is socket.AF_INET
    assert l[0][4][0] == '0.0.0.0'
    assert l[0][4][1] == 1380
    assert l[1][0] is socket.AF_INET6
    assert l[1][4][0] == '::'
    assert l[1][4][1] == 1380


def test_disable_http_listener():
    config = parse('''
        [account]
        [listeners]
        http=
        ''')
    assert len(config.http_listeners) is 0


def test_unix_socket_as_http_listener():
    with pytest.raises(config.ConfigurationError) as e:
        parse('''
            [account]
            [listeners]
            http=/run/acmems/http.sock
            ''')
    assert 'unix socket' in str(e)


### [listeners] mgmt


def test_simple_mgmt_listener():
    config = parse('''
        [account]
        acme-server = https://acme.example.org/directory
        [listeners]
        mgmt=127.0.0.1:13
        mgmt=[fe80::abba:abba%eth0]:1380
        ''')
    assert len(config.mgmt_listeners) is 2
    l = config.mgmt_listeners
    assert l[0][0] is socket.AF_INET
    assert l[0][4][0] == '127.0.0.1'
    assert l[0][4][1] == 13
    assert l[1][0] is socket.AF_INET6
    assert l[1][4][0] == 'fe80::abba:abba%eth0'
    assert l[1][4][1] == 1380


def test_default_mgmt_listener():
    config = parse('''
        [account]
        [listeners]
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
        [listeners]
        mgmt=
        ''')
    assert len(config.mgmt_listeners) is 0


def test_unix_socket_as_mgmt_listener():
    with pytest.raises(config.ConfigurationError) as e:
        parse('''
            [account]
            [listeners]
            mgmt=/run/acmems/mgmt.sock
            ''')
    assert 'unix socket' in str(e)


### [listeners] max size

def test_default_max_size_options():
    p = parse('''
        [account]
        [listeners]
        ''')
    assert p.max_size == 4096


def test_max_size_options_in_bytes():
    p = parse('''
        [account]
        [listeners]
        max-size = 2394
        ''')
    assert p.max_size == 2394


def test_max_size_options_in_kbytes():
    p = parse('''
        [account]
        [listeners]
        max-size = 4k
        ''')
    assert p.max_size == 4096


def test_max_size_options_in_mbytes():
    p = parse('''
        [account]
        [listeners]
        max-size = 1m
        ''')
    assert p.max_size == 1024 * 1024


### [listeners] unknown option

def test_warning_on_unknown_listeners_option():
    with pytest.warns(config.UnusedOptionWarning) as e:
        parse('''
            [account]
            [listeners]
            manager = https://acme.example.org/directory
            ''')
    assert 'manager' in str(e[0].message)
    assert 'https://acme.example.org/directory' in str(e[0].message)


### unknown section

def test_warning_on_unknown_section():
    with pytest.warns(config.UnusedSectionWarning) as e:
        parse('''
            [account]
            [listeners]
            [unknown]
            ''')
    assert 'unknown' in str(e[0].message)
