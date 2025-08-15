from abc import abstractmethod
from datetime import datetime, timedelta
from hashlib import sha384
import os
import os.path
import sys
from typing import Sequence

if sys.version_info >= (3, 11):
    from datetime import UTC
else:
    from datetime import timezone

    UTC: timezone = timezone.utc

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from acmems.config import ConfigurationError


class StorageImplementor:
    def __init__(self, type: str, name: str, options: Sequence[tuple[str, str]]) -> None:
        self.type = type
        self.name = name
        self.parse(options)

    @abstractmethod
    def parse(self, options: Sequence[tuple[str, str]]) -> None: ...

    @abstractmethod
    def from_cache(self, csr: bytes) -> str | None: ...

    @abstractmethod
    def add_to_cache(self, csr: bytes, certs: str) -> bool: ...


class NoneStorageImplementor(StorageImplementor):
    def parse(self, options: Sequence[tuple[str, str]]) -> None:
        if len(options) > 0:
            raise ConfigurationError(
                'none storage does not support any options, but found "{}"'.format(
                    '", "'.join(o[0] for o in options)
                )
            )

    def from_cache(self, csr: bytes) -> str | None:
        return None

    def add_to_cache(self, csr: bytes, certs: str) -> bool:
        return False


class FileStorageImplementor(StorageImplementor):
    def parse(self, options: Sequence[tuple[str, str]]) -> None:
        directory: str | None = None
        renew_within = None
        for option, value in options:
            if option == "directory":
                directory = value
            elif option == "renew-within":
                renew_within = timedelta(days=int(value))
            else:
                raise ConfigurationError('FileStorage: unknown option "{}"'.format(option))
        if directory is None:
            raise ConfigurationError("FileStorage: option directory is required")
        else:
            self.directory = directory
        self.renew_within = renew_within or timedelta(days=14)

    def cache_dir(self, csr: bytes) -> str:
        hash = sha384(csr).hexdigest()
        return os.path.join(self.directory, hash[0:2], hash[2:])

    def from_cache(self, csr: bytes) -> str | None:
        dir = self.cache_dir(csr)
        if not os.path.isfile(os.path.join(dir, "csr.pem")):
            return None
        if not os.path.isfile(os.path.join(dir, "cert.pem")):
            return None
        if csr != open(os.path.join(dir, "csr.pem"), "rb").read():
            # should not happen!!
            return None
        certpem = open(os.path.join(dir, "cert.pem"), "rb").read()
        cert = x509.load_pem_x509_certificate(certpem, default_backend())
        current_validation_time = cert.not_valid_after_utc - datetime.now(tz=UTC)
        if current_validation_time < self.renew_within:
            return None
        else:
            return certpem.decode("utf-8")

    def add_to_cache(self, csr: bytes, certs: str) -> bool:
        dir = self.cache_dir(csr)
        os.makedirs(dir, exist_ok=True)
        with open(os.path.join(dir, "csr.pem"), "bw") as f:
            f.write(csr)
        with open(os.path.join(dir, "cert.pem"), "w") as f:
            f.write(certs)
        return True


implementors: dict[str, type[StorageImplementor]] = {
    "none": NoneStorageImplementor,
    "file": FileStorageImplementor,
}


def setup(type: str, name: str, options: Sequence[tuple[str, str]]) -> StorageImplementor:
    try:
        return implementors[type](type, name, options)
    except KeyError:
        raise ConfigurationError('Unsupported storage type "{}"'.format(type)) from None
