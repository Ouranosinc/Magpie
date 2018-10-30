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

        # settings
        provider_settings = self.settings.config.get(self.name)
        self.cert = self._kwarg(kwargs, 'certificate_file', provider_settings.get('certificate_file', None))
        self.verify = self._kwarg(kwargs, 'ssl_verify', provider_settings.get('ssl_verify', True))

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

    def _fetch(self, url, method='GET', params=None, headers=None,
               body='', max_redirects=5, content_parser=None,
               certificate_file=None, ssl_verify=True):
        import ssl
        import authomatic
        from authomatic.six.moves import urllib_parse as parse, http_client.authomatic
        from authomatic.exceptions import FetchError
        LOGGER = logging.getLogger(__name__)

        # 'magic' using _kwarg method
        # pylint:disable=no-member
        params = params or {}
        params.update(self.access_params)

        headers = headers or {}
        headers.update(self.access_headers)

        url_parsed = parse.urlsplit(url)
        query = parse.urlencode(params)

        if method in ('POST', 'PUT', 'PATCH'):
            if not body:
                # Put querystring to body
                body = query
                query = ''
                headers.update(
                    {'Content-Type': 'application/x-www-form-urlencoded'})
        request_path = parse.urlunsplit(
            ('', '', url_parsed.path or '', query or '', ''))

        LOGGER.warn(u' \u251C\u2500 host: {0}'.format(url_parsed.hostname))
        LOGGER.warn(u' \u251C\u2500 path: {0}'.format(request_path))
        LOGGER.warn(u' \u251C\u2500 method: {0}'.format(method))
        LOGGER.warn(u' \u251C\u2500 body: {0}'.format(body))
        LOGGER.warn(u' \u251C\u2500 params: {0}'.format(params))
        LOGGER.warn(u' \u251C\u2500 headers: {0}'.format(headers))
        LOGGER.warn(u' \u2514\u2500 certificate: {0}'.format(certificate_file))
        LOGGER.warn(u' \u2514\u2500 SSL verify: {0}'.format(ssl_verify))

        # Connect
        if url_parsed.scheme.lower() == 'https':
            context = None if ssl_verify else ssl._create_unverified_context()
            cert_file = certificate_file if ssl_verify else None

            LOGGER.warn(u' \u2514\u2500 cert_file: {0}'.format(cert_file))
            LOGGER.warn(u' \u2514\u2500 context: {0!r}'.format(context))
            connection = http_client.HTTPSConnection(
                url_parsed.hostname,
                port=url_parsed.port,
                cert_file=cert_file,
                context=context)
        else:
            connection = http_client.HTTPConnection(
                url_parsed.hostname,
                port=url_parsed.port)

        try:
            connection.request(method, request_path, body, headers)
        except Exception as e:
            raise FetchError('Fetching URL failed',
                             original_message=str(e),
                             url=request_path)

        response = connection.getresponse()
        location = response.getheader('Location')

        if response.status in (300, 301, 302, 303, 307) and location:
            if location == url:
                raise FetchError('Url redirects to itself!',
                                 url=location,
                                 status=response.status)

            elif max_redirects > 0:
                remaining_redirects = max_redirects - 1

                LOGGER.warn(u'Redirecting to {0}'.format(url))
                LOGGER.warn(u'Remaining redirects: {0}'
                          .format(remaining_redirects))

                # Call this method again.
                response = self._fetch(url=location,
                                       params=params,
                                       method=method,
                                       headers=headers,
                                       max_redirects=remaining_redirects)

            else:
                raise FetchError('Max redirects reached!',
                                 url=location,
                                 status=response.status)
        else:
            LOGGER.warn(u'Got response:')
            LOGGER.warn(u' \u251C\u2500 url: {0}'.format(url))
            LOGGER.warn(u' \u251C\u2500 status: {0}'.format(response.status))
            LOGGER.warn(u' \u2514\u2500 headers: {0}'.format(response.getheaders()))

        return authomatic.core.Response(response, content_parser)


# Authomatic provider type ID is generated from this list's indexes!
# Always append new providers at the end so that ids of existing providers don't change!
PROVIDER_ID_MAP = [WSO2]
