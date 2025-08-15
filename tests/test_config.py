import io
import socket

import pytest

from acmems import config, storages


def parse(configcontent: str) -> config.Configurator:
    return config.Configurator(io.StringIO(configcontent))


### generall


def test_error_on_option_without_section() -> None:
    with pytest.warns(config.UnusedOptionWarning) as w:
        parse("""
            acme-server = https://acme.example.org/directory
            [account]
            [mgmt]
            """)
    assert "acme-server" in str(w[-1].message)
    assert "https://acme.example.org/directory" in str(w[-1].message)


def test_comment() -> None:
    parse("""
        [account]
        #acme-server https://acme.example.org/directory
        [mgmt]
        """)


### [account] acme-server


def test_acme_server_address() -> None:
    c = parse("""
[account]
acme-server = https://acme.example.org/directory
[mgmt]
""")
    assert c.acme_server == "https://acme.example.org/directory"


def test_default_acme_server_address() -> None:
    c = parse("""[account]
        [mgmt]""")
    assert c.acme_server == "https://acme-staging.api.letsencrypt.org/directory"


def test_error_on_multiple_acme_server_addresses() -> None:
    with pytest.raises(config.SingletonOptionRedifined) as e:
        parse("""
            [account]
            acme-server = https://acme.example.org/directory
            acme-server = https://acme2.example.org/directory
            [mgmt]
            """)
    assert "https://acme.example.org/directory" in str(e.value)
    assert "https://acme2.example.org/directory" in str(e.value)


### [account] dir


def test_account_dir() -> None:
    config = parse("""
        [account]
        dir = /tmp/test
        [mgmt]
        """)
    assert config.account_dir == "/tmp/test"  # noqa: S108


### [account] unknown option


def test_warning_on_unknown_account_option() -> None:
    with pytest.warns(config.UnusedOptionWarning) as w:
        parse("""
            [account]
            acme_server = https://acme.example.org/directory
            [mgmt]
            """)
    assert "acme_server" in str(w[-1].message)
    assert "https://acme.example.org/directory" in str(w[-1].message)


### [mgmt] mgmt


def test_simple_mgmt_listener() -> None:
    config = parse("""
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        listener=127.0.0.1:13
        listener=[fe80::abba:abba%lo]:1380
        """)
    assert len(config.mgmt_listeners) == 2
    listeners = config.mgmt_listeners
    assert listeners[0][0] is socket.AF_INET
    assert listeners[0][4][0] == "127.0.0.1"
    assert listeners[0][4][1] == 13
    assert listeners[1][0] is socket.AF_INET6
    # Since Python 3.7, the interface name is removed as the interface number
    # is stored as fourth value in the tuple
    assert listeners[1][4][0] in ["fe80::abba:abba%lo", "fe80::abba:abba"]
    assert listeners[1][4][1] == 1380
    assert listeners[1][4][3] == socket.if_nametoindex("lo")  # pyright: ignore[reportGeneralTypeIssues] (we parse a link local address and have more fields)


def test_default_mgmt_listener() -> None:
    config = parse("""
        [account]
        [mgmt]
        """)
    assert len(config.mgmt_listeners) == 2
    listeners = config.mgmt_listeners
    assert listeners[0][0] is socket.AF_INET
    assert listeners[0][4][0] == "127.0.0.1"
    assert listeners[0][4][1] == 1313
    assert listeners[1][0] is socket.AF_INET6
    assert listeners[1][4][0] == "::1"
    assert listeners[1][4][1] == 1313


def test_disable_mgmt_listener() -> None:
    config = parse("""
        [account]
        [mgmt]
        listener=
        """)
    assert len(config.mgmt_listeners) == 0


def test_unix_socket_as_mgmt_listener() -> None:
    with pytest.raises(config.ConfigurationError) as e:
        parse("""
            [account]
            [mgmt]
            listener=/run/acmems/mgmt.sock
            """)
    assert "unix socket" in str(e.value)


### [mgmt] max size


def test_default_max_size_options() -> None:
    p = parse("""
        [account]
        [mgmt]
        """)
    assert p.max_size == 4096


def test_max_size_options_in_bytes() -> None:
    p = parse("""
        [account]
        [mgmt]
        max-size = 2394
        """)
    assert p.max_size == 2394


def test_max_size_options_in_kbytes() -> None:
    p = parse("""
        [account]
        [mgmt]
        max-size = 4k
        """)
    assert p.max_size == 4096


def test_max_size_options_in_mbytes() -> None:
    p = parse("""
        [account]
        [mgmt]
        max-size = 1m
        """)
    assert p.max_size == 1024 * 1024


### [mgmt] unknown option


def test_warning_on_unknown_mgmt_option() -> None:
    with pytest.warns(config.UnusedOptionWarning) as w:
        parse("""
            [account]
            [mgmt]
            manager = https://acme.example.org/directory
            """)
    assert "manager" in str(w[-1].message)
    assert "https://acme.example.org/directory" in str(w[-1].message)


### unknown section


def test_warning_on_unknown_section() -> None:
    with pytest.warns(config.UnusedSectionWarning) as w:
        parse("""
            [account]
            [mgmt]
            [unknown]
            """)
    assert "unknown" in str(w[-1].message)


### http verification


def test_simple_http_listener() -> None:
    config = parse("""
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-verification=http
        [verification "http"]
        type=http01
        listener=127.0.0.1:80
        listener=[::]:80
        """)
    assert tuple(config.validators.keys()) == ("http",)
    assert len(config.validators["http"].listeners) == 2
    listeners = config.validators["http"].listeners
    assert listeners[0][0] is socket.AF_INET
    assert listeners[0][4][0] == "127.0.0.1"
    assert listeners[0][4][1] == 80
    assert listeners[1][0] is socket.AF_INET6
    assert listeners[1][4][0] == "::"
    assert listeners[1][4][1] == 80


def test_unix_socket_as_http_listener() -> None:
    with pytest.raises(config.ConfigurationError) as e:
        parse("""
            [account]
            [mgmt]
            default-verification=http
            [verification "http"]
            type=http01
            listener=/run/acmems/http.sock
            """)
    assert "unix socket" in str(e.value)


### dns verification


def test_dns01_listener_default_options() -> None:
    config = parse("""
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-verification=dns
        [verification "dns"]
        type=dns01-dnsUpdate
        """)
    assert tuple(config.validators.keys()) == ("dns",)
    v = config.validators["dns"]
    assert v.dns_servers == ["127.0.0.1"]
    assert v.timeout == 5
    assert v.ttl == 60


def test_dns01_listener_with_explicit_options() -> None:
    config = parse("""
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-verification=
        [verification "dns"]
        type=dns01-dnsUpdate
        dns-server = 127.0.0.2
        timeout = 6
        ttl = 61
        """)
    assert tuple(config.validators.keys()) == ("dns",)
    v = config.validators["dns"]
    assert v.dns_servers == ["127.0.0.2"]
    assert v.timeout == 6
    assert v.ttl == 61


#### default verification


def test_default_http_listener() -> None:
    config = parse("""
        [account]
        [mgmt]
        """)
    assert tuple(config.validators.keys()) == ("http",)
    assert len(config.validators["http"].listeners) == 2
    listeners = config.validators["http"].listeners
    assert listeners[0][0] is socket.AF_INET
    assert listeners[0][4][0] == "0.0.0.0"  # noqa: S104
    assert listeners[0][4][1] == 1380
    assert listeners[1][0] is socket.AF_INET6
    assert listeners[1][4][0] == "::"
    assert listeners[1][4][1] == 1380


def test_disable_http_listener() -> None:
    config = parse("""
        [account]
        [mgmt]
        default-verification=
        """)
    assert config.default_validator is None


def test_use_single_verification_as_default() -> None:
    config = parse("""
        [account]
        [mgmt]
        [verification "http234"]
        type = http01
        """)
    assert tuple(config.validators.keys()) == ("http234",)
    assert config.default_validator is config.validators["http234"]


### storages


def test_explict_none_storage() -> None:
    config = parse("""
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        default-storage = ntest
        [storage "ntest"]
        type = none
        """)
    assert set(config.storages) == {"ntest"}
    assert type(config.storages["ntest"]) is storages.NoneStorageImplementor


def test_not_other_none_storage_options() -> None:
    with pytest.raises(config.ConfigurationError) as e:
        parse("""
            [account]
            acme-server = https://acme.example.org/directory
            [mgmt]
            default-storage = ntest
            [storage "ntest"]
            type = none
            other = test
            """)
    assert "other" in str(e.value)


def test_implicit_default_storage() -> None:
    config = parse("""
        [account]
        acme-server = https://acme.example.org/directory
        [mgmt]
        """)
    assert set(config.storages) == {"none"}


def test_use_single_stroage_as_default() -> None:
    config = parse("""
        [account]
        [mgmt]
        [storage "io"]
        type = file
        directory = /tmp
        """)
    assert tuple(config.storages.keys()) == ("io",)
    assert config.default_storage is config.storages["io"]
