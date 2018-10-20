class AcmeException(Exception):
    ''' Base exception call to be able to catch all ACMEMS specific
        errors
    '''
    pass


class NoChallengeMethodsSupported(AcmeException):
    ''' The domain can not be validated HTTP01
    '''
    pass


class ChallengeFailed(AcmeException):
    ''' The challenge to validate the requested domain failed.

        :ivar str domain: the domain which the challenge should validate
        :ivar str message: message description from ACME server
        :ivar str challenge_uri: the URI of the failed challenge
    '''
    def __init__(self, domain, message, challenge_uri):
        self.domain = domain
        self.message = message
        self.challenge_uri = challenge_uri

    def __str__(self):
        return "The challenge for {} failed: {}.".format(self.domain, self.message)


class RateLimited(AcmeException):
    ''' To many requests '''
    pass


class AccountError(AcmeException):
    ''' Generic account error - e.g.
        - could not read private key
        - could not refresh the registration
    '''
    pass


class NeedToAgreeToTOS(AccountError):
    ''' We are registered at the ACME server. But to use it,
        we need to accept the "Terms of Service"
    '''
    def __init__(self, url):
        self.url = url


class InvalidDomainName(AcmeException):
    ''' The domain name is not excepted by the ACME server.

        :ivar str domain: the domain that was rejected
        :ivar str detail: the reject reason as string
    '''
    def __init__(self, domain, detail):
        self.domain = domain
        self.detail = detail

    def __str__(self):
        return '{} is not a domain name that the ACME server can issue ' \
            'a certificate for: {}'.format(self.domain, self.detail)


class PayloadToLarge(AcmeException):
    ''' The payload (CSR) it to large

        :ivar int size: the request size to upload (in bytes)
        :ivar int allowed: the maximal size in bytes
    '''
    def __init__(self, size, allowed):
        self.size = size
        self.allowed = allowed


class PayloadInvalid(AcmeException):
    ''' The payload is not a valid CSR '''
    pass
