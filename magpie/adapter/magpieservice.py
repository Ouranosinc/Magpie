"""
Store adapters to read data from magpie.
"""
from typing import TYPE_CHECKING

import requests
from beaker.cache import cache_region, cache_regions
from pyramid.httpexceptions import HTTPOk
from pyramid.settings import asbool

from magpie.api.schemas import ServicesAPI
from magpie.models import Service as MagpieService
from magpie.services import invalidate_service
from magpie.utils import CONTENT_TYPE_JSON, get_admin_cookies, get_logger, get_magpie_url, get_settings

# WARNING:
#   Twitcher available only when this module is imported from it.
#   It is installed during tests for evaluation.
#   Module 'magpie.adapter' should not be imported from 'magpie' package.
from twitcher.datatype import Service as TwithcerService  # noqa
from twitcher.exceptions import ServiceNotFound  # noqa
from twitcher.store import ServiceStoreInterface  # noqa

if TYPE_CHECKING:
    from pyramid.request import Request

    from magpie.typedefs import Str

LOGGER = get_logger("TWITCHER")


class MagpieServiceStore(ServiceStoreInterface):
    """
    Registry for OWS services.

    Uses magpie to fetch service url and attributes.
    """
    # pylint: disable=W0221

    def __init__(self, request):
        # type: (Request) -> None
        super(MagpieServiceStore, self).__init__(request)
        self.settings = get_settings(request)
        self.session_factory = request.registry["dbsession_factory"]
        self.magpie_url = get_magpie_url(request)
        self.twitcher_ssl_verify = asbool(self.settings.get("twitcher.ows_proxy_ssl_verify", True))
        self.magpie_admin_token = get_admin_cookies(self.settings, self.twitcher_ssl_verify)

    def save_service(self, service, overwrite=True, request=None):
        """
        Magpie store is read-only, use magpie api to add services.
        """
        raise NotImplementedError

    def delete_service(self, name, request=None):
        """
        Magpie store is read-only, use magpie api to delete services.
        """
        raise NotImplementedError

    def list_services(self, request=None):  # noqa: F811
        """
        Lists all services registered in magpie.
        """
        # obtain admin access since 'service_url' is only provided on admin routes
        services = []
        path = "{}{}".format(self.magpie_url, ServicesAPI.path)
        resp = requests.get(path, cookies=self.magpie_admin_token, headers={"Accept": CONTENT_TYPE_JSON},
                            verify=self.twitcher_ssl_verify)
        if resp.status_code != HTTPOk.code:
            raise resp.raise_for_status()
        json_body = resp.json()
        for service_type in json_body["services"]:
            for service in json_body["services"][service_type].values():
                services.append(TwithcerService(url=service["service_url"],
                                                name=service["service_name"],
                                                type=service["service_type"]))
        return services

    @cache_region("service")
    def _fetch_by_name_cached(self, service_name):
        # type: (Str) -> TwithcerService
        """
        Cache this method with :py:mod:`beaker` based on the provided caching key parameters.

        If the cache is not hit (expired timeout or new key entry), calls :meth:`fetch_by_name` to retrieve the actual
        :class:`twitcher.datatype.Service` definition. Otherwise, returns the cached item to avoid SQL queries.

        .. note::
            Function arguments are required to generate caching keys by which cached elements will be retrieved.

        .. note::
            Method :meth:`fetch_by_name` gets triggered by :meth:`twitcher.owsproxy.owsproxy_view` after successful
            validation of granted access for :term:`Logged User` to the service / resources following call to
            :meth:`magpie.adapter.magpieowssecurity.MagpieOWSSecurity.check_request` in order to send and retrieve
            the actual response of that proxied service and forward it back to the requesting user.
            Caching helps greatly reduce recurrent SQL queries to convert `Twitcher` to `Magpie` service.

        .. seealso::
            - :meth:`magpie.adapter.magpieowssecurity.MagpieOWSSecurity.get_service`
            - :meth:`magpie.adapter.magpieservice.MagpieServiceStore.fetch_by_name`
        """
        session = self.session_factory()

        try:
            service = MagpieService.by_service_name(service_name, db_session=session)
            if service is None:
                raise ServiceNotFound("Service name not found.")

            return TwithcerService(url=service.url,
                                   name=service.resource_name,
                                   type=service.type,
                                   verify=self.twitcher_ssl_verify)
        finally:
            session.close()

    def fetch_by_name(self, name):
        # type: (Str) -> TwithcerService
        """
        Gets :class:`twitcher.datatype.Service` corresponding to :class:`magpie.models.Service` by ``name``.
        """
        # make sure the cache is invalidated to retrieve 'fresh' service from database if requested or cache disabled
        if "service" not in cache_regions:
            cache_regions["service"] = {"enabled": False}
        if self.request.headers.get("Cache-Control") == "no-cache":
            invalidate_service(name)
        return self._fetch_by_name_cached(name)

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
        Magpie store is read-only, use magpie api to delete services.
        """
        raise NotImplementedError
