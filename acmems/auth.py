"""
This modules organize the decision making whether the signing request is
valid and should be processed or unauthorized and should be rejected.

The main external interfaced is constructed with the `.Authenticator`:
it tangles everything together. The `.Processor` implemented the generel
decision process by iterating through all available authentication blocks
and invokes every referenced auchentication mothod to execute it
authentication and autorisation itself.
"""

from fnmatch import fnmatch
import hashlib
import hmac
import logging
import warnings

from cryptography import x509
from IPy import IP
from OpenSSL import crypto

from acmems import exceptions

logger = logging.getLogger(__name__)


class Authenticator:
    """Cooridantes the authentication. It stores to configuration with all
    known authentication blocks.
    """

    def __init__(self, config=None):
        self.config = config
        self.blocks = []

    def parse_block(self, name, options):
        self.blocks.append(Block(name, options, self.config))

    def process(self, client_address, headers, rfile):
        """Executes the request authentication by delicating it to the
        `.Processor`.
        """
        return Processor(self, client_address, headers, rfile)


class IPAuthMethod:
    """Autentication by source IP"""

    option_names = ("ip",)

    def __init__(self, ips=None):
        self.ips = ips or []

    def parse(self, option, value):
        assert option == "ip"
        self.ips.append(IP(value))

    def possible(self, processor):
        return self.check(processor)

    def check(self, processor):
        cip = IP(processor.client_address[0])
        for ip in self.ips:
            if cip in ip:
                return True
        return False


class HmacAuthMethod:
    """Authentication by HMAC / secret key"""

    option_names = ("hmac_type", "hmac_key")

    def parse(self, option, value):
        if option == "hmac_type":
            self.name = value
            self.hmac = getattr(hashlib, self.name)
        elif option == "hmac_key":
            self.key = value.encode("utf-8")

    def parse_authentification_header(self, processor):
        if "Authentication" not in processor.headers:
            return (None, {})
        else:
            name, opts = processor.headers["Authentication"].split(" ", 1)
            opts = {opt.split("=")[0]: opt.split("=", 1)[1] for opt in opts.split(", ")}
            return name, opts

    def possible(self, processor):
        name, opts = self.parse_authentification_header(processor)
        if name != "hmac":
            return False
        if opts.get("name", None) != self.name:
            return False
        if "hash" not in opts:
            return False
        return True

    def check(self, processor):
        name, opts = self.parse_authentification_header(processor)
        csrhash = hmac.new(self.key, processor.csrpem, digestmod=self.hmac).hexdigest()
        if hmac.compare_digest(csrhash, opts["hash"]):
            return True
        else:
            return False


class AllAuthMethod:
    """Allow all authentication"""

    option_names = ("all",)

    def parse(self, option, value):
        assert option == "all"
        assert value == "yes"

    def possible(self, processor):
        return True

    def check(self, processor):
        return True


class Block:
    """One authentication block - combination of authentications
    and list of allowed domains
    """

    def __init__(self, name, options, config):
        self.name = name
        self.methods = []
        self.domain_matchers = []
        self.validator = None
        self.storage = None
        self.parse(options, config)

    def possible(self, processor):
        if not self.domain_matchers:
            return False
        for method in self.methods:
            if not method.possible(processor):
                logger.debug("block %s excluded by %s", self.name, method.__class__.__name__)
                return False
        return True

    def check(self, processor):
        for method in self.methods:
            if not method.check(processor):
                return False
        # check matching of domain names
        for dns_name in processor.dns_names:
            for matcher in self.domain_matchers:
                if fnmatch(dns_name, matcher):
                    break
            else:
                return False
        return True

    def parse(self, options, config):
        unused_methods = [IPAuthMethod, AllAuthMethod, HmacAuthMethod]
        for option, value in options:
            if option == "domain":
                self.domain_matchers.append(value)
                continue
            if option == "verification":
                try:
                    self.validator = config.validators[value.strip()]
                except KeyError:
                    from acmems.config import UnknownVerificationError

                    raise UnknownVerificationError(
                        'Validator "{}" undefined'.format(value.strip())
                    ) from None
                continue
            if option == "storage":
                try:
                    self.storage = config.storages[value.strip()]
                except KeyError:
                    from acmems.config import UnknownStorageError

                    raise UnknownStorageError(
                        'Storage "{}" undefined'.format(value.strip())
                    ) from None
                continue
            for method in self.methods:
                if option in method.option_names:
                    method.parse(option, value)
                    break
            else:  # no known method processes this option
                for method in unused_methods:
                    if option in method.option_names:
                        break
                else:
                    from acmems.config import UnusedOptionWarning

                    warnings.warn(
                        'Option unknown [auth "{}"]{} = {}'.format(self.name, option, value),
                        UnusedOptionWarning,
                        stacklevel=2,
                    )
                    break
                unused_methods.remove(method)
                self.methods.append(method())
                self.methods[-1].parse(option, value)
        if self.validator is None:
            self.validator = config.default_validator
            if self.validator is False:
                from acmems.config import UnknownVerificationError

                raise UnknownVerificationError(
                    'auth "{}" does not define a validator and the default one is disabled'.format(
                        self.name
                    )
                )
        if self.storage is None:
            self.storage = config.default_storage
            if self.storage is False:
                from acmems.config import UnknownStorageError

                raise UnknownStorageError(
                    'auth "{}" does not define a storage and the default one is disabled'.format(
                        self.name
                    )
                )


class Processor:
    """Helper object to process a request, check authentication,
    reads and parse CSR
    """

    def __init__(self, auth, client_address, headers, rfile):
        self.auth = auth
        self.client_address = client_address
        self.headers = headers
        self.rfile = rfile

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def acceptable(self):
        """process the given request parameter for a CSR signing request and
        decide whether this request is allowed or not.

        :param client_ip str: The source IP of the client (TCP level)
        :param dict headers: The request header
        :param callable get_body: function to read in body (CSR)
        :return bool: whether request should be accepted
        """
        self.validator = None
        self.storage = None
        # 1. precheck
        possible_blocks = []
        for block in self.auth.blocks:
            if block.possible(self):
                possible_blocks.append(block)
        if not possible_blocks:
            return False
        # 2. process CSR
        try:
            self.read_and_parse_csr()
        except crypto.Error:
            raise exceptions.PayloadInvalid() from None
        self.accepted_block = None
        # 3. final check
        for block in possible_blocks:
            if block.check(self):
                self.validator = block.validator
                self.storage = block.storage
                return True
        return False

    def read_and_parse_csr(self):
        content_length = int(self.headers["Content-Length"])
        if self.auth.config and content_length > self.auth.config.max_size:
            raise exceptions.PayloadToLarge(size=content_length, allowed=self.auth.config.max_size)
        self.csrpem = self.rfile.read(content_length)
        self.csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, self.csrpem)
        csr = self.csr.to_cryptography()
        self.common_name = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        try:
            extension = csr.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            self.dns_names = extension.value.get_values_for_type(x509.DNSName)
        except x509.extensions.ExtensionNotFound:
            self.dns_names = []
        if self.common_name not in self.dns_names:
            self.dns_names.insert(0, self.common_name)
