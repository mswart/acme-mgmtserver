import socket
from threading import Thread, Event
from datetime import datetime, timedelta
import json
import urllib.request
import warnings

import acme.client

from acmems.config import ConfigurationError, UnusedOptionWarning
from acmems.server import ThreadedACMEServerByType, ACMEHTTPHandler
from acmems import exceptions


class ChallengeImplementor():
    def __init__(self, type, name, options):
        self.type = type
        self.name = name
        self.parse(options)


class HttpChallengeImplementor(ChallengeImplementor):
    def parse(self, options):
        self.listeners = None
        for option, value in options:
            if option == 'listener':
                if self.listeners is None:
                    self.listeners = []
                if value == '':  # disable listener
                    continue
                if ':' not in value:
                    raise ConfigurationError('unix socket are currenlty not supported as listeners')
                host, port = value.rsplit(':', 1)
                if host[0] == '[' and host[-1] == ']':
                    host = host[1:-1]
                self.listeners += socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_TCP)
        if self.listeners is None:
            self.listeners = socket.getaddrinfo('0.0.0.0', 1380, proto=socket.IPPROTO_TCP) \
                + socket.getaddrinfo('::', 1380, proto=socket.IPPROTO_TCP)

    def start(self):
        services = []
        bound_handler = lambda *args, **kwargs: ACMEHTTPHandler(self, *args, **kwargs)
        for http_listen in self.listeners:
            http_service = ThreadedACMEServerByType[http_listen[0]](http_listen[4], bound_handler)
            thread = Thread(target=http_service.serve_forever,
                            daemon=True,
                            name='http service to server validation request')
            thread.start()
            services.append((http_service, thread))
        self.responses = {}
        return services

    def new_authorization(self, authz, client, key, domain):
        for combination in authz.combinations:
            if len(combination) == 1:
                challenger = authz.challenges[combination[0]]
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

                    # we can wait until this challenge is first requested ...
                    raise exceptions.AuthorizationNotYetRequested(event)
        else:
            return False

    def response_for(self, host, path):
        ''' request a response for a given request

        :param str host: Hostname of the request
        :param str path: Requested path (e.g. /.well-known/acme-challenges/?)
        :raises KeyError: Unknown host or path; return 404
        '''
        content, event = self.responses[host][path]
        event.set()
        return content


class DnsChallengeImplementor(ChallengeImplementor):
    """ WIP """
    def start(self):
        pass

    def new_authorization(self, authz, client, key, domain):
        for combination in authz.combinations:
            if len(combination) == 1:
                challenger = authz.challenges[combination[0]]
                challenge = challenger.chall
                if isinstance(challenge, acme.challenges.DNS01):
                    response, validation = challenge.response_and_validation(key)

                    self.add_entry(challenge.validation_domain_name(domain) + '.', validation)

                    # answer challenges / give ACME server go to check challenge
                    client.answer_challenge(challenger, response)

                    # we can wait until this challenge is first requested ...
                    raise exceptions.AuthorizationNotYetProcessed(datetime.now() + timedelta(seconds=2))
        else:
            return False


class DnsChallengeBoulderImplementor(DnsChallengeImplementor):
    """ WIP """
    def parse(self, options):
        self.set_txt_url = None
        for option, value in options:
            if option == 'set-txt_url':
                self.set_txt_url = value
        if self.set_txt_url is None:
            self.set_txt_url = 'http://localhost:8055/set-txt'

    def add_entry(self, entry, value):
        task = json.dumps({
            'host': entry,
            'value': value
        }).encode('utf-8')

        response = urllib.request.urlopen(self.set_txt_url, task)
        assert response.code is 200


class DnsChallengeDnsUpdateImplementor(DnsChallengeImplementor):
    """ WIP """
    def parse(self, options):
        self.dns_servers = None
        self.ttl = None
        self.timeout = None
        for option, value in options:
            if option == 'dns-server':
                if self.dns_servers is None:
                    self.dns_servers = []
                self.dns_servers.append(value)
            elif option == 'ttl':
                self.ttl = int(value)
            elif option == 'timeout':
                self.timeout = int(value)
            else:
                warnings.warn('Option unknown [verification "{}"]{} = {}'.format(self.name, option, value),
                              UnusedOptionWarning, stacklevel=2)
        if self.dns_servers is None:
            self.dns_servers = ['127.0.0.1']
        if self.ttl is None:
            self.ttl = 60
        if self.timeout is None:
            self.timeout = 5

    def add_entry(self, entry, value):
        import dns
        import dns.update
        import dns.query
        upd = dns.update.Update(self.select_zone(entry),
                                #keyring=dns.tsigkeyring.from_text({keyname: key}),
                                #keyalgorithm=algo)
                                )
        upd.add(entry, self.ttl, 'TXT', value)
        try:
            response = dns.query.tcp(upd, self.dns_servers[0], timeout=self.timeout)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                rcode_text = dns.rcode.to_text(rcode)
                raise ValueError(rcode_text)
            return response
        except Exception as e:
            raise ValueError('could not update {}: {}'.format(e.__class__.__name__, e))

    def select_zone(self, entry):
        parts = entry.split('.')
        return '.'.join(parts[-3:])


implementors = {
    'http01': HttpChallengeImplementor,
    'dns01-boulder': DnsChallengeBoulderImplementor,
    'dns01-dnsUpdate': DnsChallengeDnsUpdateImplementor,
}


def setup(type, name, options):
    try:
        return implementors[type](type, name, options)
    except KeyError:
        raise ConfigurationError('Unsupported challenge type "{}"'.format(type))
