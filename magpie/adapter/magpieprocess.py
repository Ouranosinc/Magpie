"""
Store adapters to read data from magpie.
"""

from six.moves.urllib.parse import urlparse
import logging
import requests
import json
LOGGER = logging.getLogger("TWITCHER")

from magpie.definitions.twitcher_definitions import *
from magpie.definitions.pyramid_definitions import ConfigurationError, HTTPOk, HTTPCreated, HTTPNotFound, HTTPConflict

# import 'process' elements separately than 'twitcher_definitions' because not defined in master
from twitcher.config import get_twitcher_configuration, TWITCHER_CONFIGURATION_EMS
from twitcher.exceptions import ProcessNotFound
from twitcher.store import processstore_defaultfactory
from twitcher.store.base import ProcessStore
from twitcher.visibility import VISIBILITY_PUBLIC, VISIBILITY_PRIVATE


class MagpieProcessStore(ProcessStore):
    """
    Registry for OWS processes.
    Uses default process store for most operations.
    Uses magpie to update process access and visibility.
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

            self.twitcher_config = get_twitcher_configuration(registry.settings)
        except AttributeError:
            #If magpie.url does not exist, calling strip fct over None will raise this issue
            raise ConfigurationError('magpie.url config cannot be found')

    def save_process(self, process, overwrite=True, request=None):
        """Delegate execution to default twitcher process store."""
        return processstore_defaultfactory(request.registry).save_process(process, overwrite, request)

    def delete_process(self, process_id, request=None):
        """Delegate execution to default twitcher process store."""
        return processstore_defaultfactory(request.registry).delete_process(process_id, request)

    def list_processes(self, request=None):
        """Delegate execution to default twitcher process store."""
        return processstore_defaultfactory(request.registry).list_processes(request)

    def fetch_by_id(self, process_id, request=None):
        """Delegate execution to default twitcher process store."""
        return processstore_defaultfactory(request.registry).fetch_by_id(process_id, request)

    def _get_process_resource_id(self, process_id, request):
        resp = requests.get('{host}/groups/users/resources'.format(host=self.magpie_url), cookies=request.cookies)
        if resp.status_code != HTTPOk.code:
            raise resp.raise_for_status()
        try:
            ems_resources = resp.json()['resources']['api']['ems']['resources']
            ems_processes = None
            for res_id in ems_resources:
                if ems_resources[res_id]['resource_name'] == 'processes':
                    ems_processes = ems_resources[res_id]['children']
                    break
            if not ems_processes:
                raise ProcessNotFound("Could not find processes resource endpoint for visibility retrieval.")
            for process_res_id in ems_processes:
                if ems_processes[process_res_id]['resource_name'] == process_id:
                    return ems_processes[process_res_id]['resource_id']
        except KeyError:
            raise ProcessNotFound('Could not find process `{}` resource for visibility retrieval.'.format(process_id))
        return None

    def get_visibility(self, process_id, request=None):
        """
        Get visibility of a process.

        If twitcher is not in EMS mode, simply delegate execution to default twitcher process store.
        If twitcher is in EMS mode, return the magpie visibility status according to user permissions.
        """
        if self.twitcher_config != TWITCHER_CONFIGURATION_EMS:
            return processstore_defaultfactory(request.registry).get_visibility(process_id, request)

        process_res_id = self._get_process_resource_id(process_id, request)
        return VISIBILITY_PUBLIC if process_res_id is not None else VISIBILITY_PRIVATE

    def set_visibility(self, process_id, visibility, request=None):
        """
        Set visibility of a process.

        Delegate change of process visibility to default twitcher process store.
        If twitcher is in EMS mode, also modify magpie permissions of corresponding process access point.
        """
        # write visibility to store to remain consistent in processes structures even if using magpie permissions
        processstore_defaultfactory(request.registry).set_visibility(process_id, visibility, request)

        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            process_res_id = self._get_process_resource_id(process_id, request)
            if not process_res_id:
                raise ProcessNotFound('Could not find process `{}` resource to change visibility.'.format(process_id))

            if visibility == VISIBILITY_PRIVATE:
                path = '{host}/groups/users/resources/{id}/permissions/{perm}' \
                       .format(host=self.magpie_url, id=process_res_id, perm='read')
                reps = requests.delete(path, cookies=request.cookies)
                # permission is not set if deleted or non existing
                if reps.status_code not in (HTTPOk.code, HTTPNotFound.code):
                    raise reps.raise_for_status()

            elif visibility == VISIBILITY_PUBLIC:
                path = '{host}/groups/users/resources/{id}/permissions'.format(host=self.magpie_url, id=process_res_id)
                reps = requests.post(path, cookies=request.cookies, data={u'permission_name': u'read'})
                # permission is set if created or already exists
                if reps.status_code not in (HTTPCreated.code, HTTPConflict.code):
                    raise reps.raise_for_status()
