"""
ESGF OpenID Providers
----------------------------------

Providers which implement the |openid|_ protocol based on the
`python-openid`_ library.

.. warning::
    This providers are dependent on the |python-openid|_ package.

.. _openid: https://openid.net/
.. _python-openid: https://github.com/openid/python-openid

"""

from magpie.utils import get_logger
from authomatic.providers.openid import OpenID
from openid.fetchers import Urllib2Fetcher  # noqa: W0212
from six.moves.urllib.request import urlopen
import ssl
LOGGER = get_logger(__name__)

__all__ = ["ESGFOpenID"]


class MyFetcher(Urllib2Fetcher):
    @staticmethod
    def urlopen(req):
        return urlopen(req, context=ssl._create_unverified_context())  # noqa: W0212


class ESGFOpenID(OpenID):
    """
    ESGF - Earth System Grid Federation

    :class:`authomatic.providers.openid.OpenID` provider with a common provider url template :
    ``https://{hostname}/{provider}-idp/idp/{username}``.
    """

    def __init__(self, *args, **kwargs):
        """
        Accepts additional keyword arguments:

        :param hostname:
            The hostname of the ESGF OpenID provider. Default: localhost

        :param provider_url:
            The provider identifier url template. Default: https://{hostname}/{provider}-idp/idp/{username}
        """
        super(ESGFOpenID, self).__init__(*args, **kwargs)

        self.hostname = self._kwarg(kwargs, "hostname", "localhost")
        self.provider_url = self._kwarg(kwargs, "provider_url", "https://{hostname}/providers-idp/openid/{username}")

        # if username is given set provider identifier using the provider url
        if "username" in self.params:
            self.username = self.params.get("username")
            self.identifier = self.provider_url.format(hostname=self.hostname, username=self.username)

        # use fetcher with disabled ssl verification
        # setDefaultFetcher(MyFetcher())


# Authomatic provider type ID is generated from this list's indexes!
# Always append new providers at the end so that ids of existing providers don't change!
PROVIDER_ID_MAP = [ESGFOpenID]
