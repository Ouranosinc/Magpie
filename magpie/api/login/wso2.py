from authomatic.providers.oauth2 import OAuth2


class WSO2(OAuth2):
    access_token_url = ''
    user_authorization_url = ''
    user_info_url = ''
    url = ''

    def __init__(self, *args, **kwargs):
        super(WSO2, self).__init__(*args, **kwargs)
        self.hostname = self._kwarg(kwargs, 'hostname', 'localhost')
        self.url = self._kwarg(kwargs, 'redirect_uri', 'http://localhost:2001/magpie/providers/wso2/signin')
        self.access_token_url = '{}/oauth2/token'.format(self.hostname)
        self.user_authorization_url = '{}/oauth2/authorize'.format(self.hostname)
        self.user_info_url = '{}/oauth2/userinfo'.format(self.hostname)
        self.user_info_scope = ['openid']
        self.scope = ['openid']

    @classmethod
    def _x_request_elements_filter(cls, request_type, request_elements, credentials):
        """Remove headers from oauth2/token request that doesn't want body/header authorization credentials."""
        if request_type == cls.ACCESS_TOKEN_REQUEST_TYPE:
            request_elements.headers.pop('Authorization', None)

        return request_elements


PROVIDER_ID_MAP = [WSO2]
