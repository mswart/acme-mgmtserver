Setup & Configuration
=====================

This is a short overview how to setup, configure and start using this software.

We will start with installing acmems, creating a minimal configuration, register the new ACME
client and start adding verification and auth blocks to allow clients to use this server.


Installation
------------


PyPI
^^^^

The server is available as package via PyPi_.

.. _PyPI: https://pypi.org/project/acme-mgmtserver/


Debian Packages
^^^^^^^^^^^^^^^

My preferred installation method are distribution packages. Current linux-based operation systems ship
all required dependencies in reasonable new versions.
I provide an PPA_ with a packaged version
of this project.
I will try to support the Ubuntu LTS versions as I use Ubuntu LTS myself as operation system for the server.

.. _PPA: https://launchpad.net/~malte.swart/+archive/ubuntu/acme


Minimal Configuration
---------------------

Lets start with a minimal configuration: we configuration which ACME endpoints is used to issue certificates and where to store the account details.


.. code-block:: ini

    [account]
    # the ACME server to talk to; I recommend to first test
    # against the staging system
    acme-server = https://acme-v02.api.letsencrypt.org/directory
    # account dir; contains
    #   account.pem - private key to identify against the ACME server
    #   registration.json - the registration resource as JSON dump
    dir = /etc/acmems/account/

    [mgmt]
    # Management interface itself, the clients needs to talk to this
    mgmt=127.0.0.1:1313
    # maximal size for CSR (in bytes)
    max-size = 4k


Create account
--------------

With this minimal configuration, we can register an ACME account. This is
currently a manuel process:

.. code-block:: shell

    > acme-register --gen-key --register --email test@example.test --accept-terms-of-service config.ini
    asdf
    otto

The basic setup is now finished. It remains to configure client access and
validations.



Validators
----------

Support for `HTTP01` and `DNS01` challenges is implemented. `TLSNS01` is currently not supported and
probably never will as is conflicts with the central architecture of this software.

See :ref:`detailed documentation <conf-validators>` for more information about the specific challenges and how to setup it.


Storages
--------

ACMEMS allows invoking a storage to return previously issued certificate (if it
is for same CSR otherwise the certificate would probably not match to the
private key). The default storage is the null storages that does not store
anything so a new certificate is issued each time.

The feature is designed to manually distribute a private key to multiple
services and manage (and renew) a shared certificate. The first node that
issues or reissues the certificate gets a new one. The certificate is now
storage. Frequently call from the other nodes get the some certificate.
All nodes use the same key and certificate including renewal.

If this feature is not planed, a storage is probably not needed.


Authentications
---------------

Signing requests are validated against a list of valid authorization blocks.
They define:

- How to autorize the client (based on client IP, signing ...)?
- Which domains are allowed to be included in the certificate?
- Which validator should be used to prove this is a valid certificate request against the ACME server?

All authentication blocks are tried in order. The first one that fulfilles
all requirements is used. If no block matches, the request is declined.

The following code example illustrates all currently implemented options:

.. code-block:: ini

    # CSR must also be signed by HMAC (via a the secret key)
    [auth "mail-secure"]
    # use special verification and storage
    verification = dns
    storage = file
    ip=198.51.100.21
    hmac_type=sha256
    hmac_key=A1YP67armNf3cBrecyJHdb035
    domain=mail?.example.org
    domain=mail.example.com

In depth documentation around the implemented authentification methods is described in :ref:`detailed documentation <conf-auths>`
