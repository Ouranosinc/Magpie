from authomatic.providers.oauth2 import OAuth2
from authomatic.core import SupportedUserAttributes


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

"""
    # TODO: for debug, remove
    def _fetch(self, url, method='GET', params=None, headers=None, body='', max_redirects=5, content_parser=None):
        try:
            from six.moves.urllib import parse
            from authomatic.six.moves import http_client
            from authomatic.exceptions import FetchError
            import logging
            logger = logging.getLogger('magpie.wso2.fetch')

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

            logger.warn(u' \u251C\u2500 host: {0}'.format(url_parsed.hostname))
            logger.warn(u' \u251C\u2500 path: {0}'.format(request_path))
            logger.warn(u' \u251C\u2500 method: {0}'.format(method))
            logger.warn(u' \u251C\u2500 body: {0}'.format(body))
            logger.warn(u' \u251C\u2500 params: {0}'.format(params))
            logger.warn(u' \u2514\u2500 headers: {0}'.format(headers))

            # Connect
            if url_parsed.scheme.lower() == 'https':
                connection = http_client.HTTPSConnection(
                    url_parsed.hostname,
                    port=url_parsed.port)
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

                    logger.warn(u'Redirecting to {0}'.format(url))
                    logger.warn(u'Remaining redirects: {0}'.format(remaining_redirects))

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
                logger.warn(u'Got response:')
                logger.warn(u' \u251C\u2500 url: {0}'.format(url))
                logger.warn(u' \u251C\u2500 status: {0}'.format(response.status))
                logger.warn(u' \u2514\u2500 headers: {0}'.format(response.getheaders()))
        except Exception as ex:
            import logging
            import traceback
            LOGGER = logging.getLogger(__name__)
            LOGGER.debug(repr(ex))
            LOGGER.exception("Fetch error", exc_info=True)
"""

# Authomatic provider type ID is generated from this list's indexes!
# Always append new providers at the end so that ids of existing providers don't change!
PROVIDER_ID_MAP = [WSO2]
