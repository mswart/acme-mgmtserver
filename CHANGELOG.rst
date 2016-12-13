ChangeLog
=========

This page lists all versions with its changes. ACMEMS follows Semantic Versioning.


Version 0
-------------------------

v0.3.1
^^^^^^

Multiple bug fixes:

* Fix auth-block specific storage and verification settings
* IOError when replace certification in file storage
* Fix typos in dns01-dnsUpdate verification


v0.3.0
^^^^^^

(Experimental) support for DNS challenges


v0.2.0
^^^^^^

Reaching base architecture for 1.0 release. This includes:

* Restucture code and! *config* to support multiple verification mechanism
* WIP: experiment / prepare for dns01 challenge support (via dns updates)
* add storage support to not reissue CSRs the same pem, supporting reissue from multiple machines via a once shared key and CSR
* support newer python-acme releases


v0.1.1
^^^^^^

* Fix syntax error in setup.py, preventing to upload to PyPI

v0.1.0
^^^^^^

Implement basic feature set:

* submit CSR
* validate domain via HTTP
* sign certificate
* authenticate clients based on IP and HMAC
