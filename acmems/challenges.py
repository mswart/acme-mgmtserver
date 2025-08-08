import json
import os
import socket
from threading import Event, Thread
import urllib.request
import warnings

import acme.client

from acmems.config import ConfigurationError, UnusedOptionWarning
from acmems.server import ACMEHTTPHandler, ThreadedACMEServerByType


class ChallengeImplementor:
    def __init__(self, type, name, options):
        self.type = type
        self.name = name
        self.parse(options)


class HttpChallengeImplementor(ChallengeImplementor):
    def parse(self, options):
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
            self.listeners = socket.getaddrinfo(
                "0.0.0.0",  # noqa: S104
                1380,
                proto=socket.IPPROTO_TCP,
            ) + socket.getaddrinfo("::", 1380, proto=socket.IPPROTO_TCP)

    def start(self):
        services = []

        def bound_handler(*args, **kwargs):
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

    def new_authorization(self, authz, client, key, domain):
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

    def response_for(self, host, path):
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

    def start(self):
        pass

    def new_authorization(self, authz, client, key, domain):
        for challenger in authz.challenges:
            challenge = challenger.chall
            if isinstance(challenge, acme.challenges.DNS01):
                response, validation = challenge.response_and_validation(key)

                self.add_entry(challenge.validation_domain_name(domain) + ".", validation)

                # answer challenges / give ACME server go to check challenge
                client.answer_challenge(challenger, response)

                return True
        else:
            return False


class DnsChallengeServerImplementor(DnsChallengeImplementor):
    def parse(self, options):
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

    def start(self):
        import dnslib.server

        self.responses = {}
        for dns_listen in self.listeners:
            server = dnslib.server.DNSServer(self, port=dns_listen[4][1], address=dns_listen[4][0])
            server.start_thread()

    def resolve(self, request, handler):
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

    def add_entry(self, entry, value):
        import dnslib

        self.responses[(dnslib.DNSLabel(entry), dnslib.CLASS.IN, dnslib.QTYPE.TXT)] = dnslib.TXT(
            value
        )


class DnsChallengeBoulderImplementor(DnsChallengeImplementor):
    """WIP"""

    def parse(self, options):
        self.set_txt_url = None
        for option, value in options:
            if option == "set-txt_url":
                self.set_txt_url = value
        if self.set_txt_url is None:
            self.set_txt_url = "http://localhost:8055/set-txt"

    def add_entry(self, entry, value):
        task = json.dumps({"host": entry, "value": value}).encode("utf-8")

        response = urllib.request.urlopen(self.set_txt_url, task)
        assert response.code == 200


class DnsChallengeDnsUpdateImplementor(DnsChallengeImplementor):
    """WIP"""

    def parse(self, options):
        self.dns_servers = None
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

    def add_entry(self, entry, value):
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

    def select_zone(self, entry):
        parts = entry.split(".")
        return ".".join(parts[-3:])


implementors = {
    "http01": HttpChallengeImplementor,
    "dns01-boulder": DnsChallengeBoulderImplementor,
    "dns01-server": DnsChallengeServerImplementor,
    "dns01-dnsUpdate": DnsChallengeDnsUpdateImplementor,
}


def setup(type, name, options):
    try:
        return implementors[type](type, name, options)
    except KeyError:
        raise ConfigurationError('Unsupported challenge type "{}"'.format(type)) from None
