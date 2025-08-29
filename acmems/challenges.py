from abc import abstractmethod
import http.server
import json
import os
import socket
from threading import Event, Thread
from typing import Any, Literal, Sequence, cast, overload
import urllib.request
import warnings

import acme.challenges
import acme.client
import acme.messages
import josepy.jwk

from acmems.config import ConfigurationError, UnusedOptionWarning
from acmems.server import ACMEHTTPHandler, ThreadedACMEServerByType

ListenerInfo = tuple[
    socket.AddressFamily,
    socket.SocketKind,
    int,
    str,
    tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
]


class ChallengeImplementor:
    def __init__(self, type: str, name: str, options: Sequence[tuple[str, str]]) -> None:
        self.type = type
        self.name = name
        self.parse(options)

    @abstractmethod
    def parse(self, options: Sequence[tuple[str, str]]) -> None: ...

    @abstractmethod
    def start(self) -> Any: ...  # noqa: ANN401 (depends on implementation)

    @abstractmethod
    def new_authorization(
        self,
        authz: acme.messages.Authorization,
        client: acme.client.ClientV2,
        key: josepy.jwk.JWK,
        domain: str,
    ) -> bool: ...


class HttpChallengeImplementor(ChallengeImplementor):
    responses: dict[str, dict[str, tuple[str, Event]]]

    def parse(self, options: Sequence[tuple[str, str]]) -> None:
        listeners: list[ListenerInfo] = []
        listener_disabled = False
        for option, value in options:
            if option == "listener":
                if value == "":  # disable listener
                    listener_disabled = True
                    continue
                if ":" not in value:
                    raise ConfigurationError("unix socket are currenlty not supported as listeners")
                host, port = value.rsplit(":", 1)
                if host[0] == "[" and host[-1] == "]":
                    host = host[1:-1]
                listeners += socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_TCP)
        if listener_disabled:
            self.listeners = []
        elif listeners:
            self.listeners = listeners
        else:
            self.listeners = socket.getaddrinfo(
                "0.0.0.0",  # noqa: S104
                1380,
                proto=socket.IPPROTO_TCP,
            ) + socket.getaddrinfo("::", 1380, proto=socket.IPPROTO_TCP)

    def start(self) -> list[tuple[http.server.HTTPServer, Thread]]:
        services: list[tuple[http.server.HTTPServer, Thread]] = []

        def bound_handler(*args: Any, **kwargs: Any) -> ACMEHTTPHandler:  # noqa: ANN401 (we just delegate)
            return ACMEHTTPHandler(self, *args, **kwargs)

        for http_listen in self.listeners:
            http_service = ThreadedACMEServerByType[http_listen[0]](http_listen[4], bound_handler)
            thread = Thread(
                target=http_service.serve_forever,
                daemon=True,
                name="http service to server validation request",
            )
            thread.start()
            services.append((http_service, thread))
        self.responses = {}
        return services

    def new_authorization(
        self,
        authz: acme.messages.Authorization,
        client: acme.client.ClientV2,
        key: josepy.jwk.JWK,
        domain: str,
    ) -> bool:
        for challenger in authz.challenges:
            challenge = challenger.chall
            if isinstance(challenge, acme.challenges.HTTP01):
                # store (and deliver) needed response for challenge
                content = challenge.validation(key)
                event = Event()
                self.responses.setdefault(domain, {})
                self.responses[domain][challenge.path] = (content, event)

                # answer challenges / give ACME server go to check challenge
                resp = challenge.response(key)
                client.answer_challenge(challenger, resp)

                return True
        else:
            return False

    def response_for(self, host: str, path: str) -> str:
        """request a response for a given request

        :param str host: Hostname of the request
        :param str path: Requested path (e.g. /.well-known/acme-challenges/?)
        :raises KeyError: Unknown host or path; return 404
        """
        content, event = self.responses[host][path]
        event.set()
        return content


class DnsChallengeImplementor(ChallengeImplementor):
    """WIP"""

    def start(self) -> None:
        pass

    def new_authorization(
        self,
        authz: acme.messages.Authorization,
        client: acme.client.ClientV2,
        key: josepy.jwk.JWK,
        domain: str,
    ) -> bool:
        for challenger in cast(tuple[acme.messages.ChallengeBody, ...], authz.challenges):
            challenge = challenger.chall
            if isinstance(challenge, acme.challenges.DNS01):
                response, validation = challenge.response_and_validation(key)

                self.add_entry(challenge.validation_domain_name(domain) + ".", validation)

                # answer challenges / give ACME server go to check challenge
                client.answer_challenge(challenger, response)

                return True
        else:
            return False

    @abstractmethod
    def add_entry(self, entry: str, value: str) -> None:
        pass


class DnsChallengeServerImplementor(DnsChallengeImplementor):
    def parse(self, options: Sequence[tuple[str, str]]) -> None:
        self.listeners = None
        for option, value in options:
            if option == "listener":
                if self.listeners is None:
                    self.listeners = []
                if value == "":  # disable listener
                    continue
                if ":" not in value:
                    raise ConfigurationError("unix socket are currenlty not supported as listeners")
                host, port = value.rsplit(":", 1)
                if host[0] == "[" and host[-1] == "]":
                    host = host[1:-1]
                self.listeners += socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_TCP)
        if self.listeners is None:
            self.listeners = socket.getaddrinfo("0.0.0.0", 1353, proto=socket.IPPROTO_TCP)  # noqa: S104
        if len(self.listeners) > 1:
            raise ConfigurationError("For now only one listener is supported!")

    def start(self) -> None:
        import dnslib.server

        self.responses: "dict[tuple[dnslib.DNSLabel, dnslib.CLASS, dnslib.QTYPE], dnslib.DNSRecord]" = {}
        for dns_listen in self.listeners:
            server = dnslib.server.DNSServer(self, port=dns_listen[4][1], address=dns_listen[4][0])
            server.start_thread()

    def resolve(self, request: Any, handler: Any) -> None:  # noqa: ANN401
        import dnslib

        question = request.q
        lookup = (question.qname, question.qclass, question.qtype)
        reply = request.reply()
        if lookup in self.responses:
            reply.add_answer(
                dnslib.RR(question.qname, question.qtype, rdata=self.responses[lookup], ttl=5)
            )
        elif question.qtype == dnslib.QTYPE.A:
            reply.add_answer(
                dnslib.RR(
                    question.qname,
                    question.qtype,
                    rdata=dnslib.A(os.getenv("FAKE_DNS", "127.0.0.1")),
                    ttl=5,
                )
            )
        else:
            reply.header.rcode = dnslib.RCODE.NXDOMAIN
        return reply

    def add_entry(self, entry: str, value: str) -> None:
        import dnslib

        self.responses[(dnslib.DNSLabel(entry), dnslib.CLASS.IN, dnslib.QTYPE.TXT)] = dnslib.TXT(
            value
        )


class DnsChallengeBoulderImplementor(DnsChallengeImplementor):
    """WIP"""

    def parse(self, options: Sequence[tuple[str, str]]) -> None:
        url: str | None = None
        for option, value in options:
            if option == "set-txt_url":
                url = value
        self.set_txt_url = url or "http://localhost:8055/set-txt"

    def add_entry(self, entry: str, value: str) -> None:
        task = json.dumps({"host": entry, "value": value}).encode("utf-8")

        response = urllib.request.urlopen(self.set_txt_url, task)
        assert response.code == 200


class DnsChallengeDnsUpdateImplementor(DnsChallengeImplementor):
    """WIP"""

    def parse(self, options: Sequence[tuple[str, str]]) -> None:
        self.dns_servers: list[str] | None = None
        self.ttl = None
        self.timeout = None
        for option, value in options:
            if option == "dns-server":
                if self.dns_servers is None:
                    self.dns_servers = []
                self.dns_servers.append(value)
            elif option == "ttl":
                self.ttl = int(value)
            elif option == "timeout":
                self.timeout = int(value)
            else:
                warnings.warn(
                    'Option unknown [verification "{}"]{} = {}'.format(self.name, option, value),
                    UnusedOptionWarning,
                    stacklevel=2,
                )
        if self.dns_servers is None:
            self.dns_servers = ["127.0.0.1"]
        if self.ttl is None:
            self.ttl = 60
        if self.timeout is None:
            self.timeout = 5

    def add_entry(self, entry: str, value: str) -> None:
        import dns
        import dns.query
        import dns.update

        upd = dns.update.Update(
            self.select_zone(entry),
            # keyring=dns.tsigkeyring.from_text({keyname: key}),
            # keyalgorithm=algo)
        )
        upd.add(entry, self.ttl, "TXT", value)
        try:
            response = dns.query.tcp(upd, self.dns_servers[0], timeout=self.timeout)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                rcode_text = dns.rcode.to_text(rcode)
                raise ValueError(rcode_text)
            return response
        except Exception as e:
            raise ValueError("could not update {}: {}".format(e.__class__.__name__, e)) from None

    def select_zone(self, entry: str) -> str:
        parts = entry.split(".")
        return ".".join(parts[-3:])


implementors: dict[str, type[ChallengeImplementor]] = {
    "http01": HttpChallengeImplementor,
    "dns01-boulder": DnsChallengeBoulderImplementor,
    "dns01-server": DnsChallengeServerImplementor,
    "dns01-dnsUpdate": DnsChallengeDnsUpdateImplementor,
}


@overload
def setup(
    type: Literal["http01"], name: str, options: Sequence[tuple[str, str]]
) -> HttpChallengeImplementor: ...
@overload
def setup(
    type: Literal["dns01-boulder"], name: str, options: Sequence[tuple[str, str]]
) -> DnsChallengeBoulderImplementor: ...
@overload
def setup(
    type: Literal["dns01-server"], name: str, options: Sequence[tuple[str, str]]
) -> DnsChallengeServerImplementor: ...
@overload
def setup(
    type: Literal["dns01-dnsUpdate"], name: str, options: Sequence[tuple[str, str]]
) -> DnsChallengeDnsUpdateImplementor: ...
@overload
def setup(type: str, name: str, options: Sequence[tuple[str, str]]) -> ChallengeImplementor: ...


def setup(type: str, name: str, options: Sequence[tuple[str, str]]) -> ChallengeImplementor:
    try:
        return implementors[type](type, name, options)
    except KeyError:
        raise ConfigurationError('Unsupported challenge type "{}"'.format(type)) from None
