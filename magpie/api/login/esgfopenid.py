"""
|openid| Providers
----------------------------------
Providers which implement the |openid|_ protocol based on the
`python-openid`_ library.
.. warning::
    This providers are dependent on the |pyopenid|_ package.
"""

import ssl
from six.moves.urllib.request import urlopen
from authomatic.providers.openid import OpenID
from openid.fetchers import setDefaultFetcher, Urllib2Fetcher

import logging

logger = logging.getLogger(__name__)

__all__ = ['ESGFOpenID']


class MyFetcher(Urllib2Fetcher):
    @staticmethod
    def urlopen(req):
        return urlopen(req, context=ssl._create_unverified_context())


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

        self.hostname = self._kwarg(kwargs, 'hostname', 'localhost')
        self.provider = self._kwarg(kwargs, 'provider', 'providers')
        self.provider_url = self._kwarg(kwargs, 'provider_url', 'https://{hostname}/{provider}-idp/openid/{username}')

        # if username is given set provider identifier using the provider url
        if 'username' in self.params:
            self.username = self.params.get('username')
            self.identifier = self.provider_url.format(hostname=self.hostname, username=self.username)

        # use fetcher with disabled ssl verification
        setDefaultFetcher(MyFetcher())


PROVIDER_ID_MAP = [ESGFOpenID]

