"""
Store adapters to read data from magpie.
"""

from six.moves.urllib.parse import urlparse
import logging
import requests
import json
LOGGER = logging.getLogger(__name__)

from magpie.definitions.twitcher_definitions import *
from magpie.definitions.pyramid_definitions import ConfigurationError


class MagpieServiceStore(ServiceStore):
    """
    Registry for OWS services. Uses magpie to fetch service url and attributes.
    """
    def __init__(self, registry):
        try:
            # add 'http' scheme to url if omitted from config since further 'requests' calls fail without it
            # mostly for testing when only 'localhost' is specified
            # otherwise twitcher config should explicitly define it in MAGPIE_URL
            url_parsed = urlparse(registry.settings.get('magpie.url').strip('/'))
            if url_parsed.scheme in ['http', 'https']:
                self.magpie_url = url_parsed.geturl()
            else:
                self.magpie_url = 'http://{}'.format(url_parsed.geturl())
                LOGGER.warn("Missing scheme from MagpieServiceStore url, new value: '{}'".format(self.magpie_url))
        except AttributeError:
            #If magpie.url does not exist, calling strip fct over None will raise this issue
            raise ConfigurationError('magpie.url config cannot be found')

    def save_service(self, service, overwrite=True, request=None):
        """
        Magpie store is read-only, use magpie api to add services
        """
        raise NotImplementedError

    def delete_service(self, name, request=None):
        """
        Magpie store is read-only, use magpie api to delete services
        """
        raise NotImplementedError

    def list_services(self, request=None):
        """
        Lists all services registered in magpie.
        """
        my_services = []
        response = requests.get('{url}/users/current/inherited_services'.format(url=self.magpie_url),
                                cookies=request.cookies)
        if response.status_code != 200:
            raise response.raise_for_status()
        services = json.loads(response.text)
        for service_type in services['services']:
            for key, service in services['services'][service_type].items():
                my_services.append(Service(url=service['service_url'],
                                           name=service['service_name'],
                                           type=service['service_type']))
        return my_services

    def fetch_by_name(self, name, request=None):
        """
        Gets service for given ``name`` from magpie.
        """
        services = self.list_services(request=request)
        for service in services:
            if service.name == name:
                return service
        raise ServiceNotFound

    def fetch_by_url(self, url, request=None):
        """
        Gets service for given ``url`` from mongodb storage.
        """
        services = self.list_services(request=request)
        for service in services:
            if service.url == url:
                return service
        raise ServiceNotFound

    def clear_services(self, request=None):
        """
        Magpie store is read-only, use magpie api to delete services
        """
        raise NotImplementedError
