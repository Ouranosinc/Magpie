"""
Store adapters to read data from magpie.
"""

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
            self.magpie_url = registry.settings.get('magpie.url').strip('/')
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

    #TODO Now only wps are returned as well as fetch_by_ulr... fetch_by_name has been patched to support other service_type
    def list_services(self, request=None):
        """
        Lists all services registered in magpie.
        """
        my_services = []
        response = requests.get('{url}/services/types/wps'.format(url=self.magpie_url),
                                cookies=request.cookies)
        if response.status_code != 200:
            raise response.raise_for_status()
        services = json.loads(response.text)
        if 'wps' in services['services']:
            for key, service in services['services']['wps'].items():
                my_services.append(Service(url=service['service_url'],
                                           name=service['service_name'],
                                           type=service['service_type']))
        return my_services

    def fetch_by_name(self, name, request=None):
        """
        Gets service for given ``name`` from magpie.
        """
        response = requests.get('{url}/services/{name}'.format(url=self.magpie_url, name=name),
                                cookies=request.cookies)
        if response.status_code == 404:
            raise ServiceNotFound
        if response.status_code != 200:
            raise response.raise_for_status()
        services = json.loads(response.text)
        if name in services:
            return Service(url=services[name]['service_url'],
                           name=services[name]['service_name'],
                           type=services[name]['service_type'])
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
