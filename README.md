ACME Management Server
======================

[![Build Status](http://img.shields.io/travis/mswart/acme-mgmtserver/master.svg)](https://travis-ci.org/mswart/acme-mgmtserver)


[LetsEncrypt](https://letsencrypt.org) supports issuing free certificates by communication via ACME - the Automatically Certificate Management Evaluation protocol.

This tools is yet another ACME client ... but as a client/server model.


## Why yet another ACME clients

Some aspects are special:

* **Only the server with account information**: It is not that security relevant, but only the ACME Management Server needs access to the account information / key for the ACME server like LetsEncrypt.
* **Only the server requires all the ACME dependencies**: The clients requires only a SSL tool like OpenSSL and a HTTP client like wget or curl, no python, no build tools. Python with python-acme and its dependencies (PyOpenSSL, PyASN.1, ...) is only needed for the server.
* **ACME handling can be put into own VM / container ...**: The server can be placed into a own VM, container, network segment to limit the security risk on compromised systems.
* **Supports distributed web servers**: All `.well-known/acme-challenges` requests from all servers can be served directly by the server. This make it easy to validate domains when using multiple web server in distributed or fail-over fashion.


## Redirect validation requests back to the ACME Management Server.

### Nginx

```
upstream acme-mgmtserver {
   server ...;
}
server {
    # ...
    location /.well-known/acme-challenge {
       proxy_set_header Host $http_host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_pass http://acme-mgmtserver;
       # to support multiple acme mgmt server check challenge on all upstream server:
       proxy_next_upstream error timeout http_404;
    }
    # ...
}
```

This passes all acme challenge to our server. `proxy_next_upstream http_404;` can be used to support multiple ACME management servers and search for the response on all servers.

### Apache

Up to you - I am happy to accept a PR to complete this.


## Installation

My preferred installation is by distribution packages. Due to some new dependencies like `python-acme` and `pyopenssl > 0.15` I use the ACME mgmt-server in a Ubuntu 16.04 LTS xenial container with packages from my own [PPA](https://launchpad.net/~malte.swart/+archive/ubuntu/acme).

But the server and all its dependencies are available on PyPi and can be installed by Python package manager like pip e.g. inside a virtualenv.


## Configuration

The configuration is a basic INI file, with multiple key support. The main parts are a the blocks to define the account direction, listen information for the http interfaces and the configuration which client is allowed to request certificates for which certificates.

```bash
[account]
# the ACME server to talk to; I recommend to first test 
# against the staging system
acme-server = https://acme-staging.api.letsencrypt.org/directory
# account dir; contains
#   account.pem - private key to identify against the ACME server
#   registration.json - the registration resource as JSON dump
dir = /etc/acmems/account/

[listeners]
# listen for HTTP challenge check requests (e.g. from Nginx)
http=192.0.2.80:1380
http=198.51.100.80:1380
http=[fe80::80%eth0]:1380
# Management interface itself, the clients needs to talk to this
mgmt=192.0.2.13:1313
# maximal size for CSR (in bytes)
max-size = 4k

# Define multiple authentification blocks
# a CSR must fulfil all listed authentication methods and must
# only contains listed domains (checks against globs)
[auth "mail"]
# TCP connection must come from one of this IPs
ip=192.0.2.0/24
ip=198.51.100.21
domain=mail.example.org
domain=mail.example.com

# an additional auth block
[auth "ext"]
ip=198.51.100.128/28
domain=*.test.example.org

# CSR must also be signed by HMAC (via a the secret key)
[auth "mail-secure"]
ip=198.51.100.21
hmac_type=sha256
hmac_key=A1YP67armNf3cBrecyJHdb035
domain=mail?.example.org
domain=mail.example.com
```


## Example Client Usage

```
# generate domain private key (once!)
openssl genrsa 4096 > domain.key

# generate csr to create/renew your certificate
# please generate a new csr for to renew your certificate
openssl req -new -sha256 -key domain.key -subj "/CN=example.org" > domain-201512.csr
# or
openssl req -new -sha256 -key domain.key -subj "/CN=example.org" -reqext3 SAN -config $(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.org,DNS:www.example.org")) > domain-201512.csr

# upload sign csr with shared key
wget --post-file=domain-201512.csr --header=`openssl dgst -sha256 -hmac '$KEY' domain-201512.csr | sed -e 's/HMAC-\(.*\)(.*)= *\(.*\)/Authentication: hmac name=\L\1\E, hash=\2/'` http://acmese:1313/sign > domain-201512.pem
# upload csr with out sign
wget --post-file=domain-201512.csr http://acmese:1313/sign > domain-201512.pem
```


## HTTP interface

### Client request

Only POST request to `/sign` are supported.

The body must be a CSR as PEM format; `Content-Length` header is required, `Content-Type` is currently not evaluated.

To authentication the CSR via HMAC, add a header like:

```
Authentication: hmac name=sha256 hash=47d5066525a214c759300d884bdd19d8f461a0ad24a2a0b7b705caee6c912228
```

A complete request could look like:

```
POST /sign HTTP/1.1
Host: 127.0.0.1:4005
Content-Length: 1586
Authentication: hmac name=sha256, hash=47d5066525a214c759300d884bdd19d8f461a0ad24a2a0b7b705caee6c912228

-----BEGIN CERTIFICATE REQUEST-----
MIIEWjCCAkICAQAwFTETMBEGA1UEAwwKZ28uZHh0dC5kZTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAOWXle7/dEo7l/h9O14w2ndsoKmzpHXcfosSyZnK
qrMoJLSKQImm0Y0ACRggs+c4oTbGeyUgm44RmmPjBoFxdL41CHTp5YHOytaYQHUz
A1wCitOzEMuPgRqvLUc4SqgjC7fOk1EP0bUX1YIrGNz40sYy5AsVINp4ZzKFfMoR
KtGrx4j1OrkMOfQNV6f/P8wUyOzoSSN5/XUoxcQ44aeJcfeVY6jHqZtL4BDV3EDq
oFnkHHKNGndYA6e0ov/WxHtXqxKrmsp7IN99sCvtwcoi8Kuf2OWE8/MuebsDRUCI
fhCXCsGU+2+99qan70fL7o+VmZTwBGr3GHtjJ5+QthJ92oH6uXsS+AamyhyLpp1V
3CRi1BO2G746QCIDpMmnXHe4uV49igZsOX75kl8i4dpXkzMe4lvgj4jL2nftFYGy
lv0LOwiiIUovRoTeVJlmD2RIgWz85MdxgHKFHpgBmgbmSoOlM1Uad4yY7WbsvtpT
aoSjbuG6NGa77YJBZ8eAF0FEfhvYpEAN1+3pRtHWiGsHEZ0tbQU8bpy+hOXYCMkv
iwpjyd+kTMBH9oCSeM3pQ8S74grpDV0L/wlfRoii2bImJDNurcRY22RJmPSQSSia
3KDHGZDzKW+uJs07FTa5y9RbavnCNQDrK6oyMMDZW876cQWHrj76U/f/8yuoeIuJ
NdZtAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAgEAOK5sq1dtr8SxSxbhaib+b/hz
F8F0xYpMBLrLpFfoAtoLWXp0a9AM3vqaHN+iPVTkwGri9c2Hi+E3VFltH39i+Ml1
U6I2KtiN1YB5/ARpQXCMT/29c31lPpvR3FfdKjOa078inacY+3bB7qwu3mC5qjrz
ZzkJxMf5c7iQTWhp18ISD0zw2jN9I0OeyFZVfrQleGtlhVBSYemEyuurPu2vlwlq
Xm0WpJ1wZlxNDolGTJ525HjIJEPJhGMnIwGSDKvN8INurfDzcPy1dUlRzxmoeRIs
23xu5D0DTfIPaMFT1yZaCF45nZLCcbNyUbbLK21+TABNwwAlm2UDz1RGsUK8h94x
KeHJunfvtmQ7DB/Y7IfYkGJYt20RovuUniv/ruZtc8xPxcs3Sv8H93ISrKJ1ElmO
Hvj45TYRjKC1Hl4YB30Yi/MQJJgN32Td48miTgyK5Sloc+v60CGWWsxfXC4zrUd9
CxzpbR5AeEOlsrjWBUJx3V1Ri5die1J+j0cutSC42BnFXkL3/W5JGpaiIpqlK1Ha
jTC+FnojbcxDDW+SJpI3HI/Bzv3qAbMJS2WcyVGiN//sX5iuOW5r6fJECFQhCDzE
3f0YiD2Wh6N4xcf41bOVE7gA+TjmlShzSwZQPsEwUO4brRiBErnCbwpgK/T9vCV8
A3IlV6YS/4SoAHraTLA=
-----END CERTIFICATE REQUEST-----
```


### Server response

Error code:

* **200**: CSR was signed. Response body contains the certificate and the intermediate certification in PEM form.
* **403**: Signing is denied, at a look at your auth blocks / authentication methods; are you missing a `Authentication` header?
* **413**: CSR request is too long. You might increase the `max-size` setting
* **415**: CSR could not be parsed
* **500**: Internal exception - take a look at the log and report the bug


## Testing

The server is mostly tests (some boulder error responses are difficult to reproduce). You need `py.test` to run the tests. 

The tests marked as `boulder` needs a local ACME server listening on `127.0.0.1:4000` sends all HTTP01 test challenges to `127.0.0.1:5002`. To install boulder take a look at the [Boulder README](https://github.com/letsencrypt/boulder) and/or at the prepare scripts for travis to setup boulder (`tests/scripts`).


## Contributing

1. Fork it
2. Create your feature branch (git checkout -b my-new-feature)
3. Add tests for your feature.
4. Add your feature.
5. Commit your changes (git commit -am 'Add some feature')
6. Push to the branch (git push origin my-new-feature)
7. Create new Pull Request

## License

GPL License

Copyright (c) 2015, Malte Swart
