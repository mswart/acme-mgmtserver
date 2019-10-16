Project Goal
============

The ACME Mgmtserver (acmems) tries to encapsulate all validation and administrative tasks around
ACME-based certificate issueing within a dedicated server. The clients itself shall execute the
absolute minimum of tasks and require additional dependencies or accounts.
Five lines of bash commands are enought to implement an example client.


Why yet another ACME client
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some aspects are special:

* **ACME handling can be put into own VM / container ...**: The server can be placed into an own VM, container, network segment to limit the security risk on compromised systems.
* **Only the server requires all the ACME dependencies**: The clients require only a SSL tool like OpenSSL and a HTTP client like wget or curl, no python, no build tools. Python with python-acme and its dependencies (PyOpenSSL, PyASN.1, ...) is only needed for the server.
* **Supports distributed web servers**: All `.well-known/acme-challenges` requests for all domains can be served directly by the server. This makes it easy to validate domains when using multiple web server in distributed or fail-over fashion by forwarding all `.well-known/acme-challenges` requests.
* **Only the server needs the ACME account information**: It is not that security relevant, but only the ACME Management Server needs access to the account information / key for the ACME server like LetsEncrypt.
* **Caching CSR signs**: The returned signed certificate of a CSR is cached until the certificate is nearly expired (per default two week). If two machines have manual shared a key and CSR and they reusing both, they will both get from ACMEMS the same certificate back.


Features
^^^^^^^^

The following main features are currently implemented:

* validator plugin interface to handle setup and cleanup around challenges
	- a `http01` validation plugin to provide a internal HTTP server to deliver the challenges
	- a `dns01` validator to issue DNS updates via Dynamic DNS Update requests as defined in RFC 2136
* auth plugins to ensure only authorized servers can let issue certificates
	- IP based authentificate plugins
	- hmac based authentication via shared secret
* notification plugins to inform administrators about certificate signing and rejects
* storage
