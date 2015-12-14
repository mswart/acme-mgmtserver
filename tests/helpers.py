import io

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as pem_serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import OpenSSL

from acmems import config, manager


def M(configcontent, connect=False):
    c = config.Configurator(io.StringIO(configcontent))
    return manager.ACMEManager(c, connect=connect)


def MA(dir):
    return M('''[account]
        dir = {}
        acme-server = http://127.0.0.1:4000/directory
        [listeners]'''.format(dir), connect=True)


def gencsrpem(domains, key):
    # Generates a CSR and returns a pyca/cryptography CSR object.
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ]))
    if len(domains) > 1:
        csr = csr.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
            critical=False,
        )
    csr = csr.sign(key, hashes.SHA256(), default_backend())
    return csr.public_bytes(pem_serialization.Encoding.PEM)


def gencsr(domains, key):
    pem = gencsrpem(domains, key)
    return OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, pem)
