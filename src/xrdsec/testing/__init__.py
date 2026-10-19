"""Test support for any client's suite: a grid PKI, VOMS fixtures and an HTTPS test server.

* :mod:`.pki` - a throwaway CA directory, host, user and proxy certificates
  of every kind, CRLs and TLS contexts, minted at run time;
* :mod:`.rawpki` - hand-assembled certificates and PKCS#10 requests, for
  the malformed material :mod:`.pki` will not make;
* :mod:`.proxygrid` - a grid laid out on disk (CA directory, ``vomsdir``,
  user credential) and :class:`~xrdsec.testing.proxygrid.FakeVOMS`, for
  proxy-creation and VOMS-client tests;
* :mod:`.voms` - VOMS attribute certificates, ``vomsdir``/``vomses``
  helpers, VOMS proxies and :class:`~xrdsec.testing.voms.FakeVOMSServer`;
* :mod:`.https` - :class:`~xrdsec.testing.https.FakeHTTPSServer`, the route
  table, faults, request log and client identities every in-process HTTP(S)
  fake is built on (range and WebDAV reply helpers are HTTP, so they are
  :mod:`xrdhttp.testing`'s);
* :mod:`.gsi` - the acceptor side of GSI for fake servers: GSS token loops
  and proxy owners, the httpg preamble, and
  :class:`~xrdsec.testing.gsi.SecgsiServer` (XrdSecgsi's server rounds);
* :mod:`.krb5` - Kerberos credential caches, a KCM daemon
  (:class:`~xrdsec.testing.krb5.FakeKcm`) and a python-gssapi stand-in
  (:func:`~xrdsec.testing.krb5.fake_gssapi_module`);
* :mod:`.fixtures` - the pytest plugin every suite on the stack loads
  (``pytest_plugins = ["xrdsec.testing.fixtures"]``): the hermetic
  environment, the ``pytest_xrdsec_hermetic`` hook a suite extends it
  with, and the ``pki``/``grid_env`` fixtures.

Public test API, versioned with the package. Nothing here is imported by
the library itself.
"""
