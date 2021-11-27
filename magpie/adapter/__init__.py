import warnings
from distutils.version import LooseVersion
from typing import TYPE_CHECKING

import requests
import six
from pyramid.authentication import IAuthenticationPolicy
from pyramid.httpexceptions import HTTPForbidden, HTTPOk
from pyramid_beaker import set_cache_regions_from_settings

from magpie.__meta__ import __version__ as magpie_version
from magpie.adapter.magpieowssecurity import MagpieOWSSecurity
from magpie.adapter.magpieservice import MagpieServiceStore
from magpie.api.exception import raise_http, valid_http
from magpie.api.schemas import SigninAPI
from magpie.security import get_auth_config
from magpie.utils import (
    CONTENT_TYPE_JSON,
    SingletonMeta,
    get_logger,
    get_magpie_url,
    get_settings,
    setup_cache_settings,
    setup_session_config
)

# WARNING:
#   Twitcher available only when this module is imported from it.
#   It is installed during tests for evaluation.
#   Module 'magpie.adapter' should not be imported from 'magpie' package.
from twitcher.__version__ import __version__ as twitcher_version  # noqa
from twitcher.adapter.base import AdapterInterface  # noqa
from twitcher.owsproxy import owsproxy_defaultconfig  # noqa

if LooseVersion(twitcher_version) >= LooseVersion("0.6.0"):
    from twitcher.owsregistry import OWSRegistry  # noqa  # pylint: disable=E0611  # Twitcher >= 0.6.x

    if LooseVersion(twitcher_version) >= LooseVersion("0.7.0"):
        warnings.warn(
            "Magpie version is not guaranteed to work with newer versions of Twitcher. "
            "This Magpie version offers compatibility with Twitcher 0.6.x. "
            "Current package versions are (Twitcher: {}, Magpie: {})".format(twitcher_version, magpie_version),
            ImportWarning
        )

if LooseVersion(twitcher_version) < LooseVersion("0.6.0"):
    warnings.warn(
        "Magpie version is not guaranteed to work with versions prior to Twitcher 0.6.x. "
        "It is recommended to either use more recent Twitcher 0.6.x version or revert back "
        "to older Magpie < 3.18 in order to use Twitcher 0.5.x versions. "
        "Current package versions are (Twitcher: {}, Magpie: {})".format(twitcher_version, magpie_version),
        ImportWarning
    )
if LooseVersion(twitcher_version) == LooseVersion("0.6.0"):
    warnings.warn(
        "Twitcher 0.6.0 exact version does not have complete compatibility support for MagpieAdapter. "
        "It is recommended to either revert to Twitcher 0.5.x and previous Magpie < 3.18 version, "
        "or use an higher Twitcher 0.6.x version. "
        "Current package versions are (Twitcher: {}, Magpie: {})".format(twitcher_version, magpie_version),
        ImportWarning
    )

if TYPE_CHECKING:
    from typing import Optional

    from pyramid.config import Configurator
    from pyramid.httpexceptions import HTTPException
    from pyramid.request import Request

    from magpie.typedefs import JSON, AnySettingsContainer, Str

    from twitcher.store import AccessTokenStoreInterface  # noqa  # pylint: disable=E0611  # Twitcher <= 0.5.x

LOGGER = get_logger("TWITCHER|{}".format(__name__))


def verify_user(request):
    # type: (Request) -> HTTPException
    """
    Verifies that a valid user authentication on the pointed ``Magpie`` instance (via configuration) also results into a
    valid user authentication with the current ``Twitcher`` instance to ensure settings match between them.

    :param request: an HTTP request with valid authentication token/cookie credentials.
    :return: appropriate HTTP success or error response with details about the result.
    """
    magpie_url = get_magpie_url(request)
    resp = requests.post(magpie_url + SigninAPI.path, json=request.json,
                         headers={"Content-Type": CONTENT_TYPE_JSON, "Accept": CONTENT_TYPE_JSON})
    if resp.status_code != HTTPOk.code:
        content = {"response": resp.json()}
        return raise_http(HTTPForbidden, detail="Failed Magpie login.", content=content, nothrow=True)  # noqa
    authn_policy = request.registry.queryUtility(IAuthenticationPolicy)  # noqa
    result = authn_policy.cookie.identify(request)
    if result is None:
        return raise_http(HTTPForbidden, detail="Twitcher login incompatible with Magpie login.", nothrow=True)  # noqa
    return valid_http(HTTPOk, detail="Twitcher login verified successfully with Magpie login.")


@six.add_metaclass(SingletonMeta)
class MagpieAdapter(AdapterInterface):
    # pylint: disable: W0223,W0612

    def __init__(self, container):
        self._servicestore = None
        self._owssecurity = None
        super(MagpieAdapter, self).__init__(container)  # pylint: disable=E1101,no-member

    @property
    def name(self):
        # type: () -> Str
        # pylint: disable=E1101,no-member
        return AdapterInterface.name.fget(self)  # noqa

    def describe_adapter(self):
        # type: () -> JSON
        return {"name": self.name, "version": magpie_version}

    def servicestore_factory(self, request):
        # type: (Request) -> MagpieServiceStore
        if self._servicestore is None:
            self._servicestore = MagpieServiceStore(request)
        return self._servicestore

    def tokenstore_factory(self, request):
        # type: (Request) -> AccessTokenStoreInterface
        """
        Unused token store implementation.

        .. versionchanged:: 3.18
            Available only in ``Twitcher <= 0.5.x``.
        """
        raise NotImplementedError

    def owsregistry_factory(self, request):
        # type: (Request) -> OWSRegistry
        """
        Creates the :class:`OWSRegistry` implementation derived from :class:`MagpieServiceStore`.

        .. versionadded:: 3.18
            Available only in ``Twitcher >= 0.6.x``.
        """
        return OWSRegistry(self.servicestore_factory(request))

    def owssecurity_factory(self, request=None):  # noqa  # pylint: disable=W0221  # diff between Twitcher 0.5.x/0.6.x
        # type: (Optional[AnySettingsContainer]) -> MagpieOWSSecurity
        """
        Creates the :class:`OWSSecurity` implementation derived from :class:`MagpieOWSSecurity`.

        .. versionchanged:: 3.18
            Method :paramref:`request` does not exist starting in ``Twitcher >= 0.6.x``.
        """
        if self._owssecurity is None:
            self._owssecurity = MagpieOWSSecurity(request or self.settings)
        return self._owssecurity

    def owsproxy_config(self, container):
        # type: (AnySettingsContainer) -> None
        LOGGER.info("Loading MagpieAdapter owsproxy config")
        config = self.configurator_factory(container)
        owsproxy_defaultconfig(config)  # let Twitcher configure the rest normally

    def configurator_factory(self, container):  # noqa: N805, R0201
        # type: (AnySettingsContainer) -> Configurator
        LOGGER.debug("Preparing database session.")

        settings = get_settings(container)
        setup_cache_settings(settings)  # default 'cache=off' if missing since 'pyramid_beaker' enables it otherwise
        set_cache_regions_from_settings(settings)  # parse/convert cache settings into regions understood by beaker

        # disable rpcinterface which is conflicting with postgres db
        settings["twitcher.rpcinterface"] = False

        LOGGER.info("Loading Magpie AuthN/AuthZ configuration for adapter.")
        config = get_auth_config(container)
        config.include("pyramid_beaker")
        setup_session_config(config)

        # add route to verify user token matching between Magpie/Twitcher
        config.add_route("verify-user", "/verify")
        config.add_view(verify_user, route_name="verify-user")

        return config
