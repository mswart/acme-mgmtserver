import socket
import socketserver
import http.server

from acmems import exceptions


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
    @property
    def auth(self):
        return self.manager.config.auth

    def do_POST(self):
        """ Handles POST request (upload files). """
        if self.path != '/sign':
            self.send_error(404)
            return
        try:
            with self.auth.process(self.client_address, self.headers, self.rfile) as p:
                if not p.acceptable():
                    self.send_error(403)
                    return
                print(self.client_address, p.common_name, p.dns_names)
                authzrs = self.manager.acquire_domain_validations(p.dns_names)
                certs = '\n'.join(self.manager.issue_certificate(p.csr, authzrs))
                print(certs)
                self.send_data(certs)
        except exceptions.PayloadToLarge:
            self.send_error(413)
        except exceptions.PayloadInvalid:
            self.send_error(415)
        except Exception:
            self.send_error(500)
            raise
