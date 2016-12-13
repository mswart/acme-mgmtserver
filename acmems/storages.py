import os
import os.path
from hashlib import sha384
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from acmems.config import ConfigurationError


class StorageImplementor():
    def __init__(self, type, name, options):
        self.type = type
        self.name = name
        self.parse(options)


class NoneStorageImplementor(StorageImplementor):
    def parse(self, options):
        if len(options) > 0:
            raise ConfigurationError('none storage does not support any options, but found "{}"'.format('", "'.join(o[0] for o in options)))

    def from_cache(self, csr):
        return None

    def add_to_cache(self, csr, certs):
        return None


class FileStorageImplementor(StorageImplementor):
    def parse(self, options):
        self.directory = None
        self.renew_within = None
        for option, value in options:
            if option == 'directory':
                self.directory = value
            elif option == 'renew-within':
                self.renew_within = timedelta(days=int(value))
            else:
                raise ConfigurationError('FileStorage: unknown option "{}"'.format(option))
        if self.directory is None:
            raise ConfigurationError('FileStorage: option directory is required')
        if self.renew_within is None:
            self.renew_within = timedelta(days=14)

    def cache_dir(self, csr):
        hash = sha384(csr).hexdigest()
        return os.path.join(self.directory, hash[0:2], hash[2:])

    def from_cache(self, csr):
        dir = self.cache_dir(csr)
        if not os.path.isfile(os.path.join(dir, 'csr.pem')):
            return None
        if not os.path.isfile(os.path.join(dir, 'cert.pem')):
            return None
        if csr != open(os.path.join(dir, 'csr.pem'), 'rb').read():
            # should not happen!!
            return None
        certpem = open(os.path.join(dir, 'cert.pem'), 'rb').read()
        cert = x509.load_pem_x509_certificate(certpem, default_backend())
        current_validation_time = cert.not_valid_after - datetime.now()
        if current_validation_time < self.renew_within:
            return None
        else:
            return certpem.decode('utf-8')

    def add_to_cache(self, csr, cert):
        dir = self.cache_dir(csr)
        os.makedirs(dir, exist_ok=True)
        with open(os.path.join(dir, 'csr.pem'), 'bw') as f:
            f.write(csr)
        with open(os.path.join(dir, 'cert.pem'), 'w') as f:
            f.write(cert)
        return True


implementors = {
    'none': NoneStorageImplementor,
    'file': FileStorageImplementor,
}


def setup(type, name, options):
    try:
        return implementors[type](type, name, options)
    except KeyError:
        raise ConfigurationError('Unsupported storage type "{}"'.format(type))
