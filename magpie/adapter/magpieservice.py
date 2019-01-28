"""
Store adapters to read data from magpie.
"""

from magpie.definitions.twitcher_definitions import *
from magpie.definitions.pyramid_definitions import HTTPOk, asbool
from magpie.utils import get_admin_cookies, get_magpie_url
import requests
import logging
LOGGER = logging.getLogger("TWITCHER")


class MagpieServiceStore(ServiceStore):
    """
    Registry for OWS services. Uses magpie to fetch service url and attributes.
    """
    def __init__(self, registry):
        super(MagpieServiceStore, self).__init__()
        self.magpie_url = get_magpie_url(registry)
        self.twitcher_ssl_verify = asbool(registry.settings.get('twitcher.ows_proxy_ssl_verify', True))
        self.magpie_admin_token = get_admin_cookies(self.magpie_url, self.twitcher_ssl_verify)

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
        # obtain admin access since 'service_url' is only provided on admin routes
        services = []
        path = '{}/services'.format(self.magpie_url)
        resp = requests.get(path, cookies=self.magpie_admin_token, headers={'Accept': 'application/json'})
        if resp.status_code != HTTPOk.code:
            raise resp.raise_for_status()
        json_body = resp.json()
        for service_type in json_body['services']:
            for key, service in json_body['services'][service_type].items():
                services.append(Service(url=service['service_url'],
                                        name=service['service_name'],
                                        type=service['service_type']))
        return services

    def fetch_by_name(self, name, visibility=None, request=None):
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
