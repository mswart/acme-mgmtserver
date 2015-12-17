class AcmeException(Exception):
    pass


class NeedToAgreeToTOS(AcmeException):
    def __init__(self, url):
        self.url = url


class NoChallengeMethodsSupported(AcmeException):
    pass


class ChallengeFailed(AcmeException):
    def __init__(self, domain, message, challenge_uri):
        self.domain = domain
        self.message = message
        self.challenge_uri = challenge_uri

    def __str__(self):
        return "The challenge for {} failed: {}.".format(self.domain, self.message)


class ChallengesUnknownStatus(AcmeException):
    pass


class AuthorizationNotYetProcessed(AcmeException):
    def __init__(self, wait_until):
        self.wait_until = wait_until


class AuthorizationNotYetRequested(AcmeException):
    def __init__(self, event):
        self.event = event


class RateLimited(AcmeException):
    pass


class AccountError(AcmeException):
    pass


class InvalidDomainName(AcmeException):
    def __init__(self, domain, detail):
        self.domain = domain
        self.detail = detail

    def __str__(self):
        return '{} is not a domain name that the ACME server can issue ' \
            'a certificate for: {}'.format(self.domain, self.detail)


class PayloadToLarge(AcmeException):
    def __init__(self, size, allowed):
        self.size = size
        self.allowed = allowed


class PayloadInvalid(AcmeException):
    pass
