from authomatic.providers.oauth2 import OAuth2


class WSO2(OAuth2):

    def __init__(self, *args, **kwargs):
        super(WSO2, self).__init__(*args, **kwargs)
        self.hostname = self._kwarg(kwargs, 'hostname', 'localhost')

    user_info_scope = 'openid'

    def access_token_url(self):
        return '{}/oauth2/token'.format(self.hostname)

    def user_authorization_url(self):
        return '{}/oauth2/authorize'.format(self.hostname)

    def user_info_url(self):
        return '{}/oauth2/userinfo'.format(self.hostname)


PROVIDER_ID_MAP = [WSO2]
