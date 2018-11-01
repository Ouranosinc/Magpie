from authomatic.providers.oauth2 import OAuth2
from authomatic.core import SupportedUserAttributes
from os import path
import logging


class WSO2(OAuth2):
    access_token_url = ''
    user_authorization_url = ''
    user_info_url = ''
    url = ''
    # remove headers from oauth2/token request that doesn't want body/header authorization credentials.
    _x_use_authorization_header = False

    def __init__(self, *args, **kwargs):
        super(WSO2, self).__init__(*args, **kwargs)
        self.hostname = self._kwarg(kwargs, 'hostname', 'https://localhost:9443')
        self.url = self._kwarg(kwargs, 'redirect_uri', 'http://localhost:2001/magpie/providers/wso2/signin')
        self.access_token_url = '{}/oauth2/token'.format(self.hostname)
        self.user_authorization_url = '{}/oauth2/authorize'.format(self.hostname)
        self.user_info_url = '{}/oauth2/userinfo'.format(self.hostname)
        self.user_info_scope = self._kwarg(kwargs, 'user_info_scope', ['openid'])
        self.scope = self._kwarg(kwargs, 'scope', ['openid'])
        self.cert = self._kwarg(kwargs, 'certificate_file', None)
        self.verify = self._kwarg(kwargs, 'ssl_verify', True)

        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(logging.DEBUG)

        if self.verify and self.cert and not path.isfile(self.cert):
            raise ValueError("Specified WSO2 certificate file cannot be found. [path: {!r}]".format(self.cert))

    supported_user_attributes = SupportedUserAttributes(
        country=True,
        email=True,
        first_name=True,
        last_name=True,
        id=True,
        link=True,
        name=True,
        phone=True,
        username=True
    )

    @staticmethod
    def _x_user_parser(user, data):
        # first call is with 'access_token' and Authorization credentials, skip
        if data.get('scope') == 'openid':
            return user
        # second call is with validated 'user_info' using credentials of 1st call
        user.first_name = data.get('given_name')
        user.last_name = data.get('family_name')
        user.username = data.get('sub')
        user.id = user.username
        user.name = user.first_name + ' ' + user.last_name if user.first_name and user.last_name else user.id
        user.link = data.get('url')
        return user


# Authomatic provider type ID is generated from this list's indexes!
# Always append new providers at the end so that ids of existing providers don't change!
PROVIDER_ID_MAP = [WSO2]
