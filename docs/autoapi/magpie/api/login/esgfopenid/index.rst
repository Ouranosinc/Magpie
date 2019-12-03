:mod:`magpie.api.login.esgfopenid`
==================================

.. py:module:: magpie.api.login.esgfopenid

.. autoapi-nested-parse::

   ESGF OpenID Providers
   ----------------------------------

   Providers which implement the |openid|_ protocol based on the
   `python-openid`_ library.

   .. warning::
       This providers are dependent on the |python-openid|_ package.

   .. _openid: https://openid.net/
   .. _python-openid: https://github.com/openid/python-openid



Module Contents
---------------

.. py:class:: ESGFOpenID(*args, **kwargs)

   Bases: :class:`authomatic.providers.openid.OpenID`

   ESGF - Earth System Grid Federation

   :class:`authomatic.providers.openid.OpenID` provider with a common provider url template :
   ``https://{hostname}/{provider}-idp/idp/{username}``.

   Accepts additional keyword arguments:

   :param hostname:
       The hostname of the ESGF OpenID provider. Default: localhost

   :param provider_url:
       The provider identifier url template. Default: https://{hostname}/{provider}-idp/idp/{username}


