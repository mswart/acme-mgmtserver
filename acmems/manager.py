from datetime import datetime, timedelta
import logging
import os.path
import sys

if sys.version_info >= (3, 11):
    from datetime import UTC
else:
    from datetime import timezone

    UTC: timezone = timezone.utc

import acme.client
import acme.messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as pem_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy.jwk
import josepy.util

from acmems import exceptions

logger = logging.getLogger(__name__)


class ACMEManager:
    """ACME manager - high level ACME client; process authorizations via
        http01 automatically.

    :ivar dict responses: Responses to deliver; designed as answers for
        authorization challenges. dict[host][path] = value
    :ivar dict authzrs: List of current active `acme.messages.AuthorizationResource`
    :ivar acmems.config.Configuration config: Active configuration

    """

    def __init__(self, config, connect=True):
        self.responses = {}
        self.authzrs = {}
        self.config = config
        self.directory = None
        if connect:
            self.connect()

    # ----------------------------------------------------------
    # 1. generall ACME account handling (keys, registration ...)
    # ----------------------------------------------------------

    def connect(self):
        """initialize/setup ourself; load private key, create ACME client
        and refresh our registration

        :raises acmems.exceptions.AccountError: could not load account
        :raises acmems.exceptions.NeedToAgreeToTOS: terms of service are
            not accepted - cannot operate
        """
        self.load_private_key()
        self.init_client()
        self.refresh_registration()

    def load_private_key(self):
        """load our private key / the key to identify ourself against
        the ACME server. This key MUST NOT be used for certificates.

        :raises acmems.exceptions.AccountError: something is broken
            with our account (mustly key not found)
        """
        try:
            with open(self.config.keyfile, "rb") as f:
                key = pem_serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
        except FileNotFoundError:
            raise exceptions.AccountError("Key {} not found".format(self.config.keyfile)) from None
        # TODO - handle IOError; keyfile without valid key
        self.key = josepy.jwk.JWKRSA(key=josepy.util.ComparableRSAKey(key))

    def create_private_key(self, force=False, key_size=4096):
        """create new private key to be used for identify ourself against
        the ACME server

        Key is afterwards read via `load_private_key`!

        :param bool force: create new key even key exists already
        :param int key_size: private key size in bits (at least 2048)

        :raises acmems.exceptions.AccountError: account dir not found
            or private key will not be overriden (force is `False`).
        """
        if os.path.isfile(self.config.keyfile) and not force:
            raise exceptions.AccountError("Existing key is only override if I am forced to")
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        with open(self.config.keyfile, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=pem_serialization.Encoding.PEM,
                    format=pem_serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=pem_serialization.NoEncryption(),
                )
            )
        # verify that everythings works by reading the key from disk
        self.load_private_key()

    def load_directory(self):
        self.directory = acme.messages.Directory.from_json(
            acme.client.ClientNetwork(None, verify_ssl=os.getenv("ACME_CAFILE", True))
            .get(self.config.acme_server)
            .json()
        )

    def init_client(self):
        """create ACME client"""
        self.directory or self.load_directory()
        net = acme.client.ClientNetwork(self.key, verify_ssl=os.getenv("ACME_CAFILE", True))
        directory = acme.messages.Directory.from_json(net.get(self.config.acme_server).json())
        self.client = acme.client.ClientV2(directory, net)

    def register(self, emails=None, tos_agreement=None):
        resource = acme.messages.NewRegistration(
            key=self.key.public_key(),
            contact=tuple(["mailto:{}".format(mail) for mail in emails or []]),
            terms_of_service_agreed=bool(tos_agreement),
        )
        try:
            self.registration = self.client.new_account(resource)
        except acme.messages.Error as err:
            if err.typ == "urn:ietf:params:acme:error:agreementRequired":
                raise exceptions.NeedToAgreeToTOS(
                    self.client.directory.meta.terms_of_service
                ) from None
            elif (
                err.typ == "urn:ietf:params:acme:error:malformed"
                and "must agree to terms of service" in err.detail
            ):
                # fallback for boulder :-(
                raise exceptions.NeedToAgreeToTOS(
                    self.client.directory.meta.terms_of_service
                ) from None
            raise
        self.dump_registration()

    def tos_agreement_required(self):
        self.directory or self.load_directory()
        if "terms_of_service" not in self.directory.meta:
            return None
        if not hasattr(self, "registration"):
            return self.directory.meta.terms_of_service
        return False

    def accept_terms_of_service(self, url):
        assert url is not False
        self.registration.body.update(terms_of_service_agreed=True)
        self.dump_registration()

    def dump_registration(self):
        with open(self.config.registration_file, "w") as f:
            f.write(self.registration.json_dumps_pretty())
        self.client.net.account = self.registration

    def refresh_registration(self):
        # return
        # Register or validate and update our registration.
        existing_regr = None

        # Validate existing registration by querying for it from the server.
        try:
            with open(self.config.registration_file, "r") as f:
                self.registration = acme.messages.RegistrationResource.json_loads(f.read())
        except FileNotFoundError:
            raise exceptions.AccountError(
                "Key is not yet registered or registration is losted!"
            ) from None
        existing_regr = self.registration.json_dumps()
        self.client.net.account = self.registration
        self.registration = self.client.query_registration(self.registration)

        if existing_regr != self.registration.json_dumps():
            self.dump_registration()

        # the terms of server needs to be agreed to use the ACME server!
        if self.tos_agreement_required():
            raise exceptions.NeedToAgreeToTOS(self.tos_agreement_required)

    # ---------------------------------------------------------
    # 2. the real part (handling authorizations + certificates)
    # ---------------------------------------------------------

    def acquire_domain_validations(self, validator, csrpem):
        """requests for all given domains domain validations
        If we have cached a valid challenge return this.
        Expired challenges will clear automatically; invalided challenges
        will not.

        :param csrpem: certificate sign request
        :type domains: `str`
        :returns: Challenges for the requested domains
        :rtype: acme.messages.ChallengeBody
        """
        logger.info("Requesting a new order for a certificate")
        try:
            order = self.client.new_order(csrpem)
        except acme.messages.Error as e:
            logger.info("Request for a new order has been declined")
            if e.typ == "urn:ietf:params:acme:error:rejectedIdentifier":
                raise exceptions.InvalidDomainName("unknown", e.detail) from None
            elif e.typ == "urn:ietf:params:acme:error:rateLimited":
                logger.warning("New certificate rejected due to rate limiting")
                raise exceptions.RateLimited(e.detail) from None
            raise
        for authz in order.authorizations:
            domain = authz.body.identifier.value
            logger.info("processing authorization for %s", domain)
            if not validator.new_authorization(authz.body, self.client, self.key, domain):
                # HTTP01 is not support; no clue what to do ...
                raise exceptions.NoChallengeMethodsSupported(
                    "No supported challenge methods were offered for {}.".format(domain)
                )
        logger.info("Awaiting for authorization to be validated")
        try:
            return self.client.poll_authorizations(order, datetime.now() + timedelta(seconds=90))  # noqa: DTZ005 (acme expects offset-naive datetimes)
        except acme.errors.ValidationError:
            logger.error("Authorizations could not be validated!")
            raise exceptions.ChallengeFailed() from None

    def issue_certificate(self, order):
        # Request a certificate using the CSR and some number of domain validation challenges.
        logger.info("Requesting a certificate for order")
        try:
            order = self.client.finalize_order(order, datetime.now() + timedelta(seconds=90))  # noqa: DTZ005 (acme expects offset-naive datetimes)
        except acme.messages.Error as e:
            if e.typ == "urn:ietf:params:acme:error:rateLimited":
                logger.warning("New certificate rejected due to rate limiting")
                raise exceptions.RateLimited(e.detail) from None
            logger.warning("Certificate issueing failed")
            raise  # unhandled
        logger.info("New certificate issued")
        return order.fullchain_pem.replace(
            "-----END CERTIFICATE-----", "-----END CERTIFICATE-----\n"
        ).strip()
