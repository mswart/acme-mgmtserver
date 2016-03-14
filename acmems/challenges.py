import socket
from threading import Thread, Event

import acme.client


from acmems.config import ConfigurationError
from acmems.server import ThreadedACMEServerByType, ACMEHTTPHandler
from acmems import exceptions


class ChallengeImplementor():
    def __init__(self, type, options):
        self.type = type
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


implementors = {
    'http01': HttpChallengeImplementor
}


def setup(type, options):
    try:
        return implementors[type](type, options)
    except KeyError:
        raise ConfigurationError('Unsupported challenge type "{}"'.format(type))
