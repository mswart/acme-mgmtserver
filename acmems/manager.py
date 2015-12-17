import os.path
import time
from datetime import datetime, timedelta
import threading

import OpenSSL.crypto

import acme.client
import acme.messages
import acme.jose
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as pem_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acmems import exceptions


class ACMEManager():
    ''' ACME manager - high level ACME client; process authorizations via
        http01 automatically.

    :ivar dict responses: Responses to deliver; designed as answers for
        authorization challenges. dict[host][path] = value
    :ivar dict authzrs: List of current active `acme.message.AuthorizationResource`
    :ivar acmems.config.Configuration config: Active configuration

    '''
    def __init__(self, config, connect=True):
        self.responses = {}
        self.authzrs = {}
        self.config = config
        if connect:
            self.connect()

    def log(self, *args):
        ''' log something

        .. todo::
            Switch to real logging'''
        print(*args)

    def response_for(self, host, path):
        ''' request a response for a given request

        :param str host: Hostname of the request
        :param str path: Requested path (e.g. /.well-known/acme-challenges/?)
        :raises KeyError: Unknown host or path; return 404
        '''
        content, event = self.responses[host][path]
        event.set()
        return content

    # ----------------------------------------------------------
    # 1. generall ACME account handling (keys, registration ...)
    # ----------------------------------------------------------

    def connect(self):
        ''' initialize/setup ourself; load private key, create ACME client
            and refresh our registration

            :raises acmems.exceptions.AccountError: could not load account
            :raises acmems.exceptions.NeedToAgreeToTOS: terms of service are
                not accepted - cannot operate
        '''
        self.load_private_key()
        self.init_client()
        self.refresh_registration()

    def load_private_key(self):
        ''' load our private key / the key to identify ourself against
            the ACME server. This key MUST NOT be used for certificates.

            :raises acmems.exceptions.AccountError: something is broken
                with our account (mustly key not found)
        '''
        try:
            with open(self.config.keyfile, 'rb') as f:
                key = pem_serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend())
        except FileNotFoundError:
            raise exceptions.AccountError('Key {} not found'
                                          .format(self.config.keyfile))
        # TODO - handle IOError; keyfile without valid key
        self.key = acme.jose.JWKRSA(key=acme.jose.ComparableRSAKey(key))

    def create_private_key(self, force=False, key_size=4096):
        ''' create new private key to be used for identify ourself against
            the ACME server

            Key is afterwards read via `load_private_key`!

            :param bool force: create new key even key exists already
            :param int key_size: private key size in bits (at least 2048)

            :raises acmems.exceptions.AccountError: account dir not found
                or private key will not be overriden (force is `False`).
        '''
        if os.path.isfile(self.config.keyfile) and not force:
            raise exceptions.AccountError('Existing key is only override'
                                          ' if I am forced to')
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend())
        with open(self.config.keyfile, 'wb') as f:
            f.write(key.private_bytes(
                encoding=pem_serialization.Encoding.PEM,
                format=pem_serialization.PrivateFormat.PKCS8,
                encryption_algorithm=pem_serialization.NoEncryption(),
            ))
        # verify that everythings works by reading the key from disk
        self.load_private_key()

    def init_client(self):
        ''' create ACME client
        '''
        self.client = acme.client.Client(self.config.acme_server, self.key)

    def register(self, emails=[], phones=[]):
        resource = acme.messages.NewRegistration(
            key=self.key.public_key(),
            contact=tuple(
                ['mailto:{}'.format(mail) for mail in emails]
                + ['tel:{}'.format(phone) for phone in phones]))
        self.registration = self.client.register(resource)
        self.dump_registration()

    def tos_agreement_required(self):
        if self.registration.body.agreement is not True:
            return self.registration.terms_of_service

    def accept_terms_of_service(self, url):
        newreg = self.registration.update(
            body=self.registration.body.update(agreement=url)
        )
        self.registration = self.client.update_registration(newreg)

    def dump_registration(self):
        with open(self.config.registration_file, 'w') as f:
            f.write(self.registration.json_dumps_pretty())

    def refresh_registration(self):
        # Register or validate and update our registration.
        existing_regr = None

        # Validate existing registration by querying for it from the server.
        try:
            with open(self.config.registration_file, 'r') as f:
                self.registration = acme.messages.RegistrationResource \
                    .json_loads(f.read())
        except FileNotFoundError:
            raise exceptions.AccountError('Key is not yet registered'
                                          ' or registration is losted!')
        existing_regr = self.registration.json_dumps()
        self.registration = self.client.query_registration(self.registration)

        if existing_regr != self.registration.json_dumps():
            self.dump_registration()

        # the terms of server needs to be agreed to use the ACME server!
        if not self.registration.body.agreement:
            raise exceptions.NeedToAgreeToTOS(
                self.registration.terms_of_service)

    # ---------------------------------------------------------
    # 2. the real part (handling authorizations + certificates)
    # ---------------------------------------------------------

    def acquire_domain_validations(self, domains):
        ''' requests for all given domains domain validations
            If we have cached a valid challenge return this.
            Expired challenges will clear automatically; invalided challenges
            will not.

            :param list[str] domains: List of domains to validate
            :return list[acme.message.Challenge]: Challenges for the requested
                domains
        '''
        while True:
            authzrs = []
            request_events = []  # we wait for same challenges to be requested
            wait_until = None
            for domain in domains:
                try:
                    authzr = self.authzrs.get(domain, None)
                    if authzr:
                        authzrs.append(self.evaluate_domain_authorization(authzr))
                    else:
                        authzrs.append(self.new_domain_authorization(domain))
                except exceptions.AuthorizationNotYetProcessed as e:
                    # we have to wait until validation is decided
                    wait_until = max(wait_until or datetime.min,
                                     e.wait_until)
                except exceptions.AuthorizationNotYetRequested as e:
                    request_events.append(e.event)
            # some challenges are new; wait until someone (hopefully the ACME
            # server) requests the challenges until further processing
            if request_events:
                for event in request_events:
                    event.wait(timeout=10)
                # give the ACME server 1 second to process the response
                wait_until = max(wait_until or datetime.min,
                                 datetime.now() + timedelta(seconds=1))
            if wait_until:
                wait_time = wait_until - datetime.now()
                self.log('Next authorization poll in {}s ...'.format(wait_time))
                time.sleep(wait_time.total_seconds())
            else:
                return authzrs

    def evaluate_domain_authorization(self, authzr, refresh_timer=None):
        ''' Processes a given AuthorizationResource that was fetch from
            the authzrs cache or updated by `refresh_domain_authorization` /
            `acme.client.Client.poll`.

            Renew revoked or expired ones.
            Refresh pending/processing authorizations

            :param acme.message.AuthorizationResource authzr: the authzr in
                question
            :return acme.message.AuthorizationResource: a valid authzr
            :raises acmems.exceptions.AuthorizationNotYetProcessed: We have to
                wait while the ACME server processes the autzr
            :raises acmems.exceptions.AuthorizationNotYetRequested: new authzr
                created; have to wait until someone requests it
            :raises acmems.exceptions.ChallengesUnknownStatus: unknown status
            :raises acmems.excpetions.NoChallengeMethodsSupported: HTTP01 is
                not supported
        '''
        authz = authzr.body
        domain = authz.identifier.value
        if authz.status.name == 'valid':
            return authzr
        elif self.invalid_authz(authz):
            # remove auth
            self.authzrs.pop(domain)
            # request new validation
            return self.new_domain_authorization(domain)
        elif authz.status.name == 'invalid':
            message = '; '.join(c.error.detail
                                for c in authz.challenges
                                if c.status.name == 'invalid')
            raise exceptions.ChallengeFailed(domain, message, authzr.uri)
        elif authz.status.name in ('pending', 'processing'):
            # validation in process; check for updates ...
            if refresh_timer:  # we already did a refresh, wait for changes
                raise exceptions.AuthorizationNotYetProcessed(refresh_timer)
            else:
                return self.refresh_domain_authorization(domain)
        else:
            raise exceptions.ChallengesUnknownStatus(authz.status.name)

    def invalid_authz(self, authz):
        if authz.status.name == 'revoked':
            return True
        return (authz.expires.replace(tzinfo=None) - datetime.utcnow()) \
            < timedelta(seconds=2 * 24 * 3600)  # two days

    def refresh_domain_authorization(self, domain):
        ''' Refreshes a authorization for status changes

            :param str domain: domain name for the authorization
            :return acme.message.AuthorizationResource: a valid authzr
            :raises acmems.exceptions.AuthorizationNotYetProcessed: We have to
                wait while the ACME server processes the autzr
            :raises acmems.exceptions.AuthorizationNotYetRequested: new authzr
                created; have to wait until someone requests it
            :raises acmems.exceptions.ChallengesUnknownStatus: unknown status
            :raises acmems.excpetions.NoChallengeMethodsSupported: HTTP01 is
                not supported
        '''
        self.log('Refresh authorization for {}'.format(domain))
        self.authzrs[domain], resp = self.client.poll(self.authzrs[domain])
        return self.evaluate_domain_authorization(
            self.authzrs[domain],
            refresh_timer=self.client.retry_after(resp, default=10))

    def new_domain_authorization(self, domain):
        ''' Requests a complete new authorization for the given domain

            :param str domain: domain name for the authorization
            :return acme.message.AuthorizationResource: a valid authzr
            :raises acmems.exceptions.AuthorizationNotYetProcessed: We have to
                wait while the ACME server processes the autzr
            :raises acmems.exceptions.AuthorizationNotYetRequested: new authzr
                created; have to wait until someone requests it
            :raises acmems.exceptions.ChallengesUnknownStatus: unknown status
            :raises acmems.excpetions.NoChallengeMethodsSupported: HTTP01 is
                not supported
        '''
        self.log('Requesting new authorization for {}'.format(domain))
        try:
            authzr = self.client.request_domain_challenges(
                domain, self.registration.new_authzr_uri)
            authz = authzr.body
        except acme.messages.Error as e:
            if e.typ == 'urn:acme:error:malformed':
                raise exceptions.InvalidDomainName(domain, e.detail)
            raise
        self.authzrs[domain] = authzr

        for combination in authz.combinations:
            if len(combination) == 1:
                challenger = authz.challenges[combination[0]]
                challenge = challenger.chall
                if isinstance(challenge, acme.challenges.HTTP01):
                    # store (and deliver) needed response for challenge
                    content = challenge.validation(self.key)
                    event = threading.Event()
                    self.responses.setdefault(domain, {})
                    self.responses[domain][challenge.path] = (content, event)

                    # answer challenges / give ACME server go to check challenge
                    resp = challenge.response(self.key)
                    self.client.answer_challenge(challenger, resp)

                    # we can wait until this challenge is first requested ...
                    raise exceptions.AuthorizationNotYetRequested(event)
        else:
            # HTTP01 is not support; no clue what to do ...
            raise exceptions.NoChallengeMethodsSupported(
                'No supported challenge methods were offered for {}.'
                .format(domain))

    # cert_response.body and chain now hold OpenSSL.crypto.X509 objects.
    # Convert them to PEM format.
    @staticmethod
    def cert_to_pem(cert):
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode('utf-8')

    def issue_certificate(self, csr, authzrs):
        # Request a certificate using the CSR and some number of domain validation challenges.
        self.log("Requesting a certificate.")
        try:
            cert_response = self.client.request_issuance(csr, authzrs)
        except acme.messages.Error as e:
            if e.typ == "urn:acme:error:rateLimited":
                raise exceptions.RateLimited(e.detail)
            raise  # unhandled

        certs = [self.cert_to_pem(cert_response.body)]

        # Get the certificate chain.
        for cert in self.client.fetch_chain(cert_response):
            certs.append(self.cert_to_pem(cert))

        return tuple(certs)
