.. _conf-validators:

How to configure Validators
===========================

HTTP01
------

The normal webserver must be adjusted to forward `.well-known/acme-challenges` requests to the ACME Management Server - this is a prerequirement and will not be checked/enforced/configured by this tool.

The following configuration options are available:


.. code-block:: ini

    # Define verification blocks
    [verification "http"]
    # the challenge type has to be defined first!
    type = http01
    # listen for HTTP challenge check requests (e.g. from Nginx)
    listener=192.0.2.80:1380
    listener=198.51.100.80:1380
    listener=[fe80::80%eth0]:1380



Nginx
^^^^^

.. code-block:: nginx

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

This passes all ACME challenges to the management server. `proxy_next_upstream http_404;` can be used to support multiple ACME management servers and search for the response on all servers.


Apache
^^^^^^

Up to you - I am happy to accept a PR to complete this.


DNS01
-----

DNS01 queries the DNS to ensure control over the DNS setup. There are many ways how to add the challenges in to domain.


DNS01-dnsUpdate
^^^^^^^^^^^^^^^

The current `dns01-dnsUpdate` uses the dynamic DNS update support to apply the changes. The implementation is very basic for now. It does not support apply apply authorization, as the current setups applies changes only to locally running DNS servers that simply do IP based authorization.
But this can easily be extended. I am happy to receive PR.

Further DNS Validators that instrument API of farious DNS service provides can also be implemented, but are currently left out, too.


.. code-block:: ini

    [verification "dns"]
    # the challenge type has to be defined first!
    type = dns01-dnsUpdate
    # which name server needs to be updated now
    dns-server=192.0.2.53
    # time-to-live for the new entries
    ttl=5
    # timeout for dns update requests
    timeout=30


DNS01-boulder
^^^^^^^^^^^^^^^

The current `dns01-boulder` validator is exclusively for testing: it used the deveopment HTTP interface to define DNS responses in boulder. It is only required if this server is tested against boulder.


.. code-block:: ini

    [verification "dns"]
    # the challenge type has to be defined first!
    type = dns01-server
    # the set txt url is called to add a TXT DNS entry
    set_txt_url = 'http://localhost:8055/set-txt'


DNS01-server
^^^^^^^^^^^^^^^

The `dns01-server` implementations a very basic build in DNS server. It is designed to be used testing with `pebble`. It is not designed to be used
in production environments.


.. code-block:: ini

    [verification "dns"]
    # the challenge type has to be defined first!
    type = dns01-server
    # define where to bind IP/port the DNS server
    listener=127.0.0.1:53
