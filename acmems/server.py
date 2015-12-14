import socket
import socketserver
import http.server

from OpenSSL import crypto
import pyasn1.type
from pyasn1.codec.der import decoder
from ndg.httpsclient.subj_alt_name import SubjectAltName as BaseSubjectAltName


### Note: This is a slightly bug-fixed version of same from ndg-httpsclient.
class SubjectAltName(BaseSubjectAltName):
    '''ASN.1 implementation for subjectAltNames support'''

    # There is no limit to how many SAN certificates a certificate may have,
    #   however this needs to have some limit so we'll set an arbitrarily high
    #   limit.
    sizeSpec = pyasn1.type.univ.SequenceOf.sizeSpec + \
        pyasn1.type.constraint.ValueSizeConstraint(1, 1024)


class ThreadedACMEServerInet4(socketserver.ThreadingMixIn,
                              http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadedACMEServerInet6(socketserver.ThreadingMixIn,
                              http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET6


ThreadedACMEServerByType = {
    socket.AF_INET: ThreadedACMEServerInet4,
    socket.AF_INET6: ThreadedACMEServerInet6,
}


class ACMEAbstractHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'AcmeManager/0.1'
    manager = None

    def send_data(self, data, content_type='text/plain', response_code=200):
        """ Helper method to send data as HTTP response. The data are
            transfered as :mimetype:`text/plain`.

            :param str data: The text to send as :py:obj:`Python String <str>`.
            :param int response_code: HTTP response code"""
        if type(data) is not bytes:
            data = str(data).encode('utf-8')
        self.send_response(response_code)
        self.send_header('Content-type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ACMEHTTPHandler(ACMEAbstractHandler):
    def do_GET(self):
        """ Handles POST request (upload files). """
        host = self.headers['Host']
        if host.endswith(':5002'):
            host = host[:-5]
        try:
            self.send_data(self.manager.response_for(host, self.path))
        except KeyError:
            self.send_error(404)


class ACMEMgmtHandler(ACMEAbstractHandler):
    def do_POST(self):
        """ Handles POST request (upload files). """
        if self.path != '/sign':
            self.send_error(404)
            return
        csrpem = self.rfile.read(int(self.headers['Content-Length']))
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csrpem)
        common_name, dns_names = self.parse_csr(csr)
        print(self.client_address, common_name, dns_names)
        authzrs = self.manager.acquire_domain_validations(dns_names)
        certs = '\n'.join(self.manager.issue_certificate(csr, authzrs))
        print(certs)
        self.send_data(certs)

    def parse_csr(self, req):
        common_name = req.get_subject().CN
        dns_names = []
        for ext in req.get_extensions():
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
                    dns_names.append(str(component.getComponent()))
        if common_name not in dns_names:
            dns_names.insert(0, common_name)
        return common_name, tuple(dns_names)
