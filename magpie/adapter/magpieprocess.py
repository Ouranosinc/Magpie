"""
Store adapters to read data from magpie.
"""

from six.moves.urllib.parse import urlparse
import logging
import requests
import json
import six
LOGGER = logging.getLogger("TWITCHER")

from magpie.definitions.twitcher_definitions import *
from magpie.definitions.pyramid_definitions import (
    ConfigurationError,
    HTTPOk,
    HTTPCreated,
    HTTPNotFound,
    HTTPConflict,
    HTTPUnauthorized,
)

# import 'process' elements separately than 'twitcher_definitions' because not defined in master
from twitcher.config import get_twitcher_configuration, TWITCHER_CONFIGURATION_EMS
from twitcher.exceptions import ProcessNotFound, ProcessRegistrationError
from twitcher.store import processstore_defaultfactory
from twitcher.store.base import ProcessStore
from twitcher.visibility import VISIBILITY_PUBLIC, VISIBILITY_PRIVATE


json_headers = {'Accept': 'application/json'}


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

    def _get_process_resources(self, request):
        """
        Gets all 'process' resources corresponding to results under 'ems/processes/{id}'.
        Only visible processes (resources with 'read' permissions of group 'users') are returned.

        :return: list of twitcher 'process' instances filtered by relevant magpie resources with permissions set.
        """
        path = '{host}/groups/users/resources'.format(host=self.magpie_url)
        resp = requests.get(path, cookies=request.cookies, headers=json_headers)
        LOGGER.debug('Looking for resources on: `{}`.'.format(path))
        if resp.status_code != HTTPOk.code:
            raise resp.raise_for_status()
        ems_resources = None
        try:
            ems_resources = resp.json()['resources']['api']['ems']['resources']
            for res_id in ems_resources:
                if ems_resources[res_id]['resource_name'] == 'processes':
                    ems_processes = ems_resources[res_id]['children']
                    return ems_processes
        except KeyError:
            LOGGER.debug("Content of ems service resources: `{!r}`.".format(ems_resources))
            raise ProcessNotFound("Could not find resource `processes` endpoint for visibility retrieval.")
        LOGGER.debug("Could not find resource: `processes`.")
        return list()

    def _get_process_resource_id(self, process_id, ems_processes_resources):
        """
        Searches for a 'process' resource corresponding to 'ems/processes/{id}'.
        Only visible processes (resources with 'read' permissions of group 'users') are returned.

        :returns: id of the found 'process' resource, or None.
        """
        if not ems_processes_resources:
            raise ProcessNotFound("Could not parse undefined processes resource endpoint for visibility retrieval.")
        try:
            for process_res_id in ems_processes_resources:
                if ems_processes_resources[process_res_id]['resource_name'] == process_id:
                    return ems_processes_resources[process_res_id]['resource_id']
        except KeyError:
            LOGGER.debug("Content of ems processes resources: `{!r}`.".format(ems_processes_resources))
            raise ProcessNotFound("Could not find process `{}` resource for visibility retrieval.".format(process_id))
        LOGGER.debug("Could not find resource: `{}`.".format(process_id))
        return None

    def _create_resource(self, resource_name, resource_parent_id, permission_names, request):
        """
        Creates a resource under another parent resource, and sets basic user permissions on it.

        :param resource_name: (str) name of the resource to create.
        :param resource_parent_id: (int) id of the parent resource under which to create `resource_name`.
        :param permission_names: (None, str, iterator) permissions to apply to the created resource, if any.
        :param request: calling request for headers and credentials
        :returns: id of the created resource
        """
        try:
            data = {u'parent_id': resource_parent_id, u'resource_name': resource_name, u'resource_type': u'route'}
            path = '{host}/resources'.format(host=self.magpie_url)
            resp = requests.post(path, data=data, cookies=request.cookies, headers=json_headers)
            if resp.status_code != HTTPCreated.code:
                raise resp.raise_for_status()
            res_id = resp.json()['resource']['resource_id']

            if permission_names is None:
                permission_names = []
            if isinstance(permission_names, six.string_types):
                permission_names = [permission_names]

            for perm in permission_names:
                data = {u'permission_name': perm}
                path = '{host}/users/current/resources/{id}/permissions'.format(host=self.magpie_url, id=res_id)
                resp = requests.post(path, data=data, cookies=request.cookies, headers=json_headers)
                if resp.status_code not in (HTTPCreated.code, HTTPConflict.code):
                    raise resp.raise_for_status()

            return res_id
        except KeyError:
            raise ProcessRegistrationError('Failed adding process resource route `{}`.'.format(resource_name))

    def save_process(self, process, overwrite=True, request=None):
        """
        Save a new process.

        If twitcher is not in EMS mode, simply delegate execution to default twitcher process store.
        If twitcher is in EMS mode, user requesting creation must have sufficient permissions in magpie to do so.
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            try:
                # get resource id of ems service
                path = '{host}/services/ems'.format(host=self.magpie_url)
                resp = requests.get(path, cookies=request.cookies, headers=json_headers)
                if resp.status_code != HTTPOk.code:
                    raise resp.raise_for_status()
                ems_res_id = resp.json()['ems']['resource_id']
            except KeyError:
                raise ProcessRegistrationError('Failed retrieving EMS service resource.')

            try:
                # get resource id of route '/processes', create it as necessary
                path = '{host}/resources/{id}'.format(host=self.magpie_url, id=ems_res_id)
                resp = requests.get(path, cookies=request.cookies, headers=json_headers)
                if resp.status_code != HTTPOk.code:
                    raise resp.raise_for_status()
                processes_res_id = None
                ems_resources = resp.json()[str(ems_res_id)]['children']
                for child_resource in ems_resources:
                    if ems_resources[child_resource]['resource_name'] == 'processes':
                        processes_res_id = ems_resources[child_resource]['resource_id']
                        break
                if not processes_res_id:
                    # all members of 'users' group can query '/ems/processes' (read exact route match),
                    # but visibility of each process will be filtered by specific '/ems/processes/{id}' permissions
                    processes_res_id = self._create_resource(u'processes', ems_res_id, u'read-match', request)
                    data = {u'permission_name': u'read-match'}
                    path = '{host}/groups/users/resources/{id}'.format(host=self.magpie_url, id=processes_res_id)
                    resp = requests.post(path, data=data, cookies=request.cookies, headers=json_headers)
                    if resp.status_code not in (HTTPCreated.code, HTTPConflict.code):
                        raise resp.raise_for_status()
            except KeyError:
                raise ProcessRegistrationError('Failed retrieving EMS processes resource.')

            # create resource id of route '/ems/processes/{id}' and set minimal permissions
            # use (read/write) permissions so that user creating the process can execute any sub-route request on it
            self._create_resource(process.id, processes_res_id, [u'read', u'write'], request)

        return processstore_defaultfactory(request.registry).save_process(process, overwrite, request)

    def delete_process(self, process_id, request=None):
        """
        Delete a process.

        If twitcher is not in EMS mode, simply delegate execution to default twitcher process store.
        If twitcher is in EMS mode, user requesting deletion must have sufficient permissions in magpie to do so.
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            resources = self._get_process_resources(request)
            resource_id = self._get_process_resource_id(process_id, resources)
            if not resource_id:
                raise ProcessNotFound('Could not find process `{}` resource for deletion.'.format(process_id))

            path = '{host}/resources/{id}'.format(host=self.magpie_url, id=resource_id)
            resp = requests.delete(path, cookies=request.cookies, headers=json_headers)
            if resp.status_code != HTTPOk.code:
                raise resp.raise_for_status()

        return processstore_defaultfactory(request.registry).delete_process(process_id, request)

    def list_processes(self, request=None):
        """
        List processes.

        If twitcher is not in EMS mode, simply delegate execution to default twitcher process store.
        If twitcher is in EMS mode, filter by corresponding resources with read permissions.
        """
        process_list = processstore_defaultfactory(request.registry).list_processes(request)
        LOGGER.debug('Found processes: {!r}.'.format(process_list))
        if self.twitcher_config != TWITCHER_CONFIGURATION_EMS:
            return process_list

        ems_processes = self._get_process_resources(request)
        ems_processes_visible = list()
        for process in process_list:
            # if id is returned, filtered group resource permission was set, therefore visibility is permitted
            if self._get_process_resource_id(process.id, ems_processes):
                ems_processes_visible.append(process)
        return ems_processes_visible

    def fetch_by_id(self, process_id, request=None):
        """
        Get a process if visible for user.

        If twitcher is not in EMS mode, simply delegate execution to default twitcher process store.
        If twitcher is in EMS mode, return the process if visible based on magpie user permissions.
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            if self.get_visibility(process_id, request) != VISIBILITY_PUBLIC:
                raise HTTPUnauthorized()
        return processstore_defaultfactory(request.registry).fetch_by_id(process_id, request)

    def get_visibility(self, process_id, request=None):
        """
        Get visibility of a process.

        If twitcher is not in EMS mode, simply delegate execution to default twitcher process store.
        If twitcher is in EMS mode, return the process visibility based on magpie user permissions.
        """
        if self.twitcher_config != TWITCHER_CONFIGURATION_EMS:
            return processstore_defaultfactory(request.registry).get_visibility(process_id, request)

        ems_processes = self._get_process_resources(request)
        process_res_id = self._get_process_resource_id(process_id, ems_processes)
        return VISIBILITY_PUBLIC if process_res_id is not None else VISIBILITY_PRIVATE

    def set_visibility(self, process_id, visibility, request=None):
        """
        Set visibility of a process.

        Delegate change of process visibility to default twitcher process store.
        If twitcher is in EMS mode, also modify magpie permissions of corresponding process access point.
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            ems_processes = self._get_process_resources(request)
            process_res_id = self._get_process_resource_id(process_id, ems_processes)
            if not process_res_id:
                raise ProcessNotFound('Could not find process `{}` resource to change visibility.'.format(process_id))

            if visibility == VISIBILITY_PRIVATE:
                path = '{host}/groups/users/resources/{id}/permissions/{perm}' \
                       .format(host=self.magpie_url, id=process_res_id, perm='read')
                reps = requests.delete(path, cookies=request.cookies, headers=json_headers)
                # permission is not set if deleted or non existing
                if reps.status_code not in (HTTPOk.code, HTTPNotFound.code):
                    raise reps.raise_for_status()

            elif visibility == VISIBILITY_PUBLIC:
                path = '{host}/groups/users/resources/{id}/permissions'.format(host=self.magpie_url, id=process_res_id)
                data = {u'permission_name': u'read'}
                reps = requests.post(path, data=data, cookies=request.cookies, headers=json_headers)
                # permission is set if created or already exists
                if reps.status_code not in (HTTPCreated.code, HTTPConflict.code):
                    raise reps.raise_for_status()

        # write visibility to store to remain consistent in processes structures even if using magpie permissions
        processstore_defaultfactory(request.registry).set_visibility(process_id, visibility, request)
