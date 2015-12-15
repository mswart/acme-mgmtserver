import warnings
from fnmatch import fnmatch
import hmac
import hashlib

from OpenSSL import crypto
import pyasn1.type
from pyasn1.codec.der import decoder
from ndg.httpsclient.subj_alt_name import SubjectAltName as BaseSubjectAltName
from IPy import IP

from acmems import exceptions


### Note: This is a slightly bug-fixed version of same from ndg-httpsclient.
class SubjectAltName(BaseSubjectAltName):
    '''ASN.1 implementation for subjectAltNames support'''

    # There is no limit to how many SAN certificates a certificate may have,
    #   however this needs to have some limit so we'll set an arbitrarily high
    #   limit.
    sizeSpec = pyasn1.type.univ.SequenceOf.sizeSpec + \
        pyasn1.type.constraint.ValueSizeConstraint(1, 1024)


class Authenticator():
    def __init__(self, config=None):
        self.config = config
        self.blocks = []

    def parse_block(self, name, options):
        self.blocks.append(Block(name, options))

    def process(self, client_address, headers, rfile):
        return Processor(self, client_address, headers, rfile)


class IPAuthMethod():
    option_names = ['ip']

    def __init__(self, ips=None):
        self.ips = ips or []

    def parse(self, option, value):
        assert option == 'ip'
        self.ips.append(IP(value))

    def possible(self, processor):
        return self.check(processor)

    def check(self, processor):
        cip = IP(processor.client_address[0])
        for ip in self.ips:
            if cip in ip:
                return True
        return False


class HmacAuthMethod():
    option_names = ['hmac_type', 'hmac_key']

    def parse(self, option, value):
        if option == 'hmac_type':
            self.name = value
            self.hmac = getattr(hashlib, self.name)
        elif option == 'hmac_key':
            self.key = value.encode('utf-8')

    def parse_authentification_header(self, processor):
        if 'Authentication' not in processor.headers:
            return (None, {})
        else:
            name, opts = processor.headers['Authentication'].split(' ', 1)
            opts = {opt.split('=')[0]: opt.split('=', 1)[1] for opt in opts.split(', ')}
            return name, opts

    def possible(self, processor):
        name, opts = self.parse_authentification_header(processor)
        if name != 'hmac':
            return False
        if opts.get('name', None) != self.name:
            return False
        if 'hash' not in opts:
            return False
        return True

    def check(self, processor):
        name, opts = self.parse_authentification_header(processor)
        csrhash = hmac.new(self.key, processor.csrpem, digestmod=self.hmac).hexdigest()
        if hmac.compare_digest(csrhash, opts['hash']):
            return True
        else:
            return False


class AllAuthMethod():
    option_names = ['all']

    def parse(self, option, value):
        assert option == 'all'
        assert value == 'yes'

    def possible(self, processor):
        return True

    def check(self, processor):
        return True


class Block():
    def __init__(self, name, options):
        self.name = name
        self.methods = []
        self.domain_matchers = []
        self.parse(options)

    def possible(self, processor):
        if not self.domain_matchers:
            return False
        for method in self.methods:
            if not method.possible(processor):
                print('block {} excluded by {}'.format(self.name, method.__class__.__name__))
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

    def parse(self, options):
        unused_methods = [IPAuthMethod, AllAuthMethod, HmacAuthMethod]
        for option, value in options:
            if option == 'domain':
                self.domain_matchers.append(value)
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
                    warnings.warn('Option unknown [auth "{}"]{} = {}'.format(self.name, option, value),
                                  UnusedOptionWarning, stacklevel=2)
                    break
                unused_methods.remove(method)
                self.methods.append(method())
                self.methods[-1].parse(option, value)


class Processor():
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
        ''' process the given request parameter for a CSR signing request and
            decide whether this request is allowed or not.

            :param client_ip str: The source IP of the client (TCP level)
            :param dict headers: The request header
            :param callable get_body: function to read in body (CSR)
            :return bool: whether request should be accepted
        '''
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
            raise exceptions.PayloadInvalid()
        # 3. final check
        for block in possible_blocks:
            if block.check(self):
                return True
        return False

    def read_and_parse_csr(self):
        content_length = int(self.headers['Content-Length'])
        if self.auth.config and content_length > self.auth.config.max_size:
            raise exceptions.PayloadToLarge(size=content_length, allowed=self.auth.config.max_size)
        self.csrpem = self.rfile.read(content_length)
        self.csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, self.csrpem)
        self.common_name = self.csr.get_subject().CN
        self.dns_names = []
        for ext in self.csr.get_extensions():
            if ext.get_short_name() != b'subjectAltName':
                continue
            general_names = SubjectAltName()
            data = ext.get_data()
            decoded_dat = decoder.decode(data, asn1Spec=general_names)
            for name in decoded_dat:
                if not isinstance(name, SubjectAltName):
                    continue
                for entry in range(len(name)):
                    component = name.getComponentByPosition(entry)
                    if component.getName() != 'dNSName':
                        continue
                    self.dns_names.append(str(component.getComponent()))
        if self.common_name not in self.dns_names:
            self.dns_names.insert(0, self.common_name)
