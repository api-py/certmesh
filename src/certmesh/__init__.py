"""
certmesh
========

Automated TLS certificate lifecycle client for DigiCert CertCentral,
Venafi Trust Protection Platform, HashiCorp Vault PKI, and AWS ACM.

Install
-------
::

    pip install certmesh

CLI entry point
---------------
::

    certmesh --help
    certmesh digicert list
    certmesh vault-pki issue --cn myservice.example.com
    certmesh acm request --cn myapp.example.com
    certmesh config show

Supported providers
-------------------
* DigiCert CertCentral (order, list, search, download)
* Venafi TPP (renew, list, search, download)
* HashiCorp Vault PKI (issue, sign)
* AWS ACM (request public certs, export, private CA issue)
"""

__version__ = "3.0.0"
