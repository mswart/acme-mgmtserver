ACME Management Server
======================

[LetsEncrypt](https://letsencrypt.org) supports issueing free certificates by communication via ACME - the Automatically Certificate Management Evaluation protocol.

This tools is yet another ACME client ... but as a client/server model.


## Why yet another ACME clients

Some aspects are special:

* **Only the server with account information**: It is not that security relevant, but only the ACME Management Server needs access to the account information / key for the ACME server like letsencrypt.
* **Only the server requires all the ACME dependencies**: The clients requires only a SSL tool like OpenSSL and a HTTP client like wget or curl, no python, no build tools. Python with python-acme and its dependencies (pyopenssl, pyasn1, ...) is only needed for the server.
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

You to you - I am happy to accept a PR to complete this.


## Installation

My preferred installation is by distribution packages. Due to some new dependencies like `python-acme` and `pyopenssl > 0.15` I use the ACME mgmt-server in a Ubuntu 16.04 LTS xenial container with packages from my own [PPA](https://launchpad.net/~malte.swart/+archive/ubuntu/acme).

But the server and all its dependencies are available on PyPi and can be installed by every Python package manager like pip e.g. inside a virtual env.


## Configuration

*Implementation is WIP*

The configuration is a basic INI file, with multiple key support. The main parts are a the blocks to define the account direction, listen information for the http interfaces and the configuration which client is allowed to request certificates for which certificates.

```
[account]
dir = /etc/asdf../
acme-server = https://acme-staging.api.letsencrypt.org/directory

[listeners]
http=192.0.2.80:1380
http=198.51.100.80:1380
http=[fe80::80%eth0]:1380
mgmt=192.0.2.13:1313

[auth "mail"]
ip=192.0.2.21
ip=198.51.100.21
domain=mail.example.org
domain=mail.example.com

[auth "ext"]
ip=198.51.100.128/28
domain=*.test.example.org

[auth "mail-secure"]
ip=198.51.100.21
key=AAAAB3NzaC1yc2EAAAADAQABAAABAQDc3vh70dvfJ1NyHLxIdaRP2t3qJhRs0Z+gs2WwCBvGbKuXr6WjqjlQpbHRADMSFVc9XVQSqnk4rmlg16t+3UMGCEmP1RpbJW2IHLTh0W8xabP9diSLhdBISxffrulNf1EFBvUaYblNa8svXhqGIh2IU7tz0ES0OeF+Fjj9B/ANWxljp0ntU/ni4/i/Z2iEjAujhyn+TK1dlyGQaUn8C6bxom5LTlHOZcuIgQq2z7ebRAZESdSrp1I/u5tbu9HHa6RWov+xTg9HAsar4WWiNYwEjQmD5AnSdajg2Zv7VUbWM/BklqJ3Ytpkl5SDpGtVOBJZnImGsBcyGjN8FT6+oDB7
domain=mail.example.org
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
wget --post-file=domain-201512.csr --header=`openssl dgst -sha256 -hmac '$KEY' domain-201512.csr | sed -e 's/(.*)=/:/'` http://acmese:1313/sign > domain-201512.pem
# upload csr with out sign
wget --post-file=domain-201512.csr http://acmese:1313/sign > domain-201512.pem
```
