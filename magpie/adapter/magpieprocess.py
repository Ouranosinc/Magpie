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
            self.twitcher_ssl_verify = registry.settings.get('twitcher.ows_proxy_ssl_verify', True)
            self.json_headers = {'Accept': 'application/json'}
            self.twitcher_service_url = None
        except AttributeError:
            #If magpie.url does not exist, calling strip fct over None will raise this issue
            raise ConfigurationError('magpie.url config cannot be found')

    def _get_service_public_url(self, request):
        if not self.twitcher_service_url and self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            # use generic 'current' user route to fetch service URL to ensure that even
            # a user with minimal privileges will still return a match
            path = '{host}/users/current/services?inherit=true&cascade=true'.format(host=self.magpie_url)
            resp = requests.get(path, cookies=request.cookies,
                                headers=self.json_headers, verify=self.twitcher_ssl_verify)
            if resp.status_code != HTTPOk.code:
                raise resp.raise_for_status()
            try:
                self.twitcher_service_url = resp.json()['services']['api']['ems']['public_url']
            except KeyError:
                raise ProcessNotFound("Could not find resource `processes` endpoint for visibility retrieval.")
            LOGGER.debug("Could not find resource: `processes`.")
        return self.twitcher_service_url

    def _get_process_resources(self, request):
        """
        Gets all 'process' resources corresponding to results under '/ems/processes'.
        Resources are not filtered by user permissions.
        """
        path = '{host}/resources'.format(host=self.magpie_url)
        resp = requests.get(path, cookies=request.cookies,
                            headers=self.json_headers, verify=self.twitcher_ssl_verify)
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

    def _get_process_resource_id(self, process_id, ems_processes_resources, request):
        """
        Searches for a 'process' resource corresponding to 'ems/processes/{id}'.
        Only visible processes are returned (resources with reading permission assigned to request user).

        :returns: id of the found 'process' resource, or None.
        :raises:
            HTTPException if not matching Ok or Unauthorized statuses.
            ProcessNotFound if some response parsing error occurred.
        """
        if not ems_processes_resources:
            raise ProcessNotFound("Could not parse undefined processes resource endpoint for visibility retrieval.")
        try:
            for process_res_id in ems_processes_resources:
                # find the requested process resource by matching ids
                if ems_processes_resources[process_res_id]['resource_name'] == process_id:
                    LOGGER.debug("Found process resource: `{}`.".format(process_id))

                    # if read permission is granted on corresponding magpie resource route, twitcher
                    # '/ems/process/{process_id}' will be accessible, otherwise unauthorized on private process
                    # NB:
                    #   - cannot test directly GET '/ems/process/{process_id}' for 401 because it causes circular calls
                    #   - must test with current user (not '/resources') because he might not have administrator access
                    path = '{host}/users/current/resources/{id}/permissions?inherit=true' \
                           .format(host=self.magpie_url, id=process_res_id)
                    resp = requests.get(path, cookies=request.cookies,
                                        headers=self.json_headers, verify=self.twitcher_ssl_verify)
                    if resp.status_code != HTTPOk.code:
                        raise resp.raise_for_status()
                    user_process_permissions = resp.json()['permission_names']
                    if 'read' in user_process_permissions or 'read-match' in user_process_permissions:
                        return ems_processes_resources[process_res_id]['resource_id']
                    return None
        except KeyError:
            LOGGER.debug("Content of ems processes resources: `{!r}`.".format(ems_processes_resources))
            raise ProcessNotFound("Could not find process `{}` resource for visibility retrieval.".format(process_id))
        LOGGER.debug("Could not find resource: `{}`.".format(process_id))
        return None

    def _create_resource(self, resource_name, resource_parent_id, group_name, permission_names, request):
        """
        Creates a resource under another parent resource, and sets basic user permissions on it.

        :param resource_name: (str) name of the resource to create.
        :param resource_parent_id: (int) id of the parent resource under which to create `resource_name`.
        :param group_name: (str) name of the group for which to apply permissions to the created resource, if any.
        :param permission_names: (None, str, iterator) group permissions to apply to the created resource, if any.
        :param request: calling request for headers and credentials
        :returns: id of the created resource
        """
        try:
            data = {u'parent_id': resource_parent_id, u'resource_name': resource_name, u'resource_type': u'route'}
            path = '{host}/resources'.format(host=self.magpie_url)
            resp = requests.post(path, data=data, cookies=request.cookies,
                                 headers=self.json_headers, verify=self.twitcher_ssl_verify)
            if resp.status_code != HTTPCreated.code:
                raise resp.raise_for_status()
            res_id = resp.json()['resource']['resource_id']

            if isinstance(group_name, six.string_types):
                if permission_names is None:
                    permission_names = []
                if isinstance(permission_names, six.string_types):
                    permission_names = [permission_names]

                for perm in permission_names:
                    data = {u'permission_name': perm}
                    path = '{host}/groups/{grp}/resources/{id}/permissions' \
                           .format(host=self.magpie_url, grp=group_name, id=res_id)
                    resp = requests.post(path, data=data, cookies=request.cookies,
                                         headers=self.json_headers, verify=self.twitcher_ssl_verify)
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
                resp = requests.get(path, cookies=request.cookies,
                                    headers=self.json_headers, verify=self.twitcher_ssl_verify)
                if resp.status_code != HTTPOk.code:
                    raise resp.raise_for_status()
                ems_res_id = resp.json()['ems']['resource_id']
            except KeyError:
                raise ProcessRegistrationError('Failed retrieving EMS service resource.')

            try:
                # get resource id of route '/ems/processes', create it as necessary
                path = '{host}/resources/{id}'.format(host=self.magpie_url, id=ems_res_id)
                resp = requests.get(path, cookies=request.cookies,
                                    headers=self.json_headers, verify=self.twitcher_ssl_verify)
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
                    processes_res_id = self._create_resource(u'processes', ems_res_id, u'users', u'read-match', request)
            except KeyError:
                raise ProcessRegistrationError('Failed retrieving EMS processes resource.')

            # create resource id of route '/ems/processes/{id}' and set minimal permissions
            # use read permission so that users can execute any sub-route GET request on it
            process_res_id = self._create_resource(process.id, processes_res_id, u'users', u'read', request)
            # create resource id of route '/ems/processes/{id}/jobs' and set minimal permissions
            # use write-match permission so that users can ONLY execute a job (cannot DELETE process, job, etc.)
            self._create_resource(u'jobs', process_res_id, u'users', u'write-match', request)

        return processstore_defaultfactory(request.registry).save_process(process, overwrite, request)

    def delete_process(self, process_id, request=None):
        """
        Delete a process.

        If twitcher is not in EMS mode, simply delegate execution to default twitcher process store.
        If twitcher is in EMS mode, user requesting deletion must have sufficient permissions in magpie to do so.
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            resources = self._get_process_resources(request)
            resource_id = self._get_process_resource_id(process_id, resources, request)
            if not resource_id:
                raise ProcessNotFound('Could not find process `{}` resource for deletion.'.format(process_id))

            path = '{host}/resources/{id}'.format(host=self.magpie_url, id=resource_id)
            resp = requests.delete(path, cookies=request.cookies,
                                   headers=self.json_headers, verify=self.twitcher_ssl_verify)
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
            if self._get_process_resource_id(process.id, ems_processes, request):
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
        process_res_id = self._get_process_resource_id(process_id, ems_processes, request)
        return VISIBILITY_PUBLIC if process_res_id is not None else VISIBILITY_PRIVATE

    def set_visibility(self, process_id, visibility, request=None):
        """
        Set visibility of a process.

        Delegate change of process visibility to default twitcher process store.
        If twitcher is in EMS mode, also modify magpie permissions of corresponding process access point.
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            ems_processes = self._get_process_resources(request)
            process_res_id = self._get_process_resource_id(process_id, ems_processes, request)
            if not process_res_id:
                raise ProcessNotFound('Could not find process `{}` resource to change visibility.'.format(process_id))

            if visibility == VISIBILITY_PRIVATE:
                path = '{host}/groups/users/resources/{id}/permissions/{perm}' \
                       .format(host=self.magpie_url, id=process_res_id, perm='read')
                reps = requests.delete(path, cookies=request.cookies,
                                       headers=self.json_headers, verify=self.twitcher_ssl_verify)
                # permission is not set if deleted or non existing
                if reps.status_code not in (HTTPOk.code, HTTPNotFound.code):
                    raise reps.raise_for_status()

            elif visibility == VISIBILITY_PUBLIC:
                path = '{host}/groups/users/resources/{id}/permissions'.format(host=self.magpie_url, id=process_res_id)
                data = {u'permission_name': u'read'}
                reps = requests.post(path, data=data, cookies=request.cookies,
                                     headers=self.json_headers, verify=self.twitcher_ssl_verify)
                # permission is set if created or already exists
                if reps.status_code not in (HTTPCreated.code, HTTPConflict.code):
                    raise reps.raise_for_status()

        # write visibility to store to remain consistent in processes structures even if using magpie permissions
        processstore_defaultfactory(request.registry).set_visibility(process_id, visibility, request)
