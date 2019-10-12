import io
from datetime import datetime, timedelta
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as pem_serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import OpenSSL
import uuid

from acmems import config, manager


def M(configcontent, connect=False, validator=None):
    c = config.Configurator(io.StringIO(configcontent))
    if validator:
        c.default_validator = validator
        for block in c.auth.blocks:
            block.validator = validator
    return manager.ACMEManager(c, connect=connect)


def MA(conf, connect=True, validator=None):
    return M(conf + '''[auth "all"]
        all=yes
        domain=*
        ''', connect=connect, validator=validator)



def gencsrpem(domains, key):
    # Generates a CSR and returns a pyca/cryptography CSR object.
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ]))
    csr = csr.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
        critical=False,
    )
    csr = csr.sign(key, hashes.SHA256(), default_backend())
    return csr.public_bytes(pem_serialization.Encoding.PEM)


def gencsr(domains, key):
    pem = gencsrpem(domains, key)
    return OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, pem)


def signcsr(csrpem, key, period, issued_before=None):
    csr = x509.load_pem_x509_csr(csrpem, default_backend())
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(csr.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    builder = builder.not_valid_before(datetime.now() - (issued_before or timedelta(1, 0, 0)))
    builder = builder.not_valid_after(datetime.now() + period)
    cert = builder.sign(
        private_key=key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    return '\n'.join([
        cert.public_bytes(pem_serialization.Encoding.PEM).decode('utf-8'),
        cert.public_bytes(pem_serialization.Encoding.PEM).decode('utf-8')
    ])


def extract_alt_names(obj):
    try:
        extension = obj.to_cryptography().extensions \
            .get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return extension.value.get_values_for_type(x509.DNSName)
    except x509.extensions.ExtensionNotFound:
        return []

def randomize_domains(*domains, suffix=''):
    rand = random.randint(0, 2**16)
    return [(domain + suffix).format(rand) for domain in domains]
