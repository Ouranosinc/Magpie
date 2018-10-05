"""
Store adapters to read data from magpie.
"""

from six.moves.urllib.parse import urlparse
import logging
import requests
import six
LOGGER = logging.getLogger("TWITCHER")

from magpie.constants import get_constant
from magpie.definitions.twitcher_definitions import *
from magpie.definitions.pyramid_definitions import (
    ConfigurationError,
    HTTPOk,
    HTTPCreated,
    HTTPNotFound,
    HTTPConflict,
    HTTPUnauthorized,
    HTTPInternalServerError,
    asbool
)

# import 'process' elements separately than 'twitcher_definitions' because not defined in master
from twitcher.config import get_twitcher_configuration, TWITCHER_CONFIGURATION_EMS
from twitcher.exceptions import ProcessNotFound, ProcessRegistrationError
from twitcher.store import processstore_defaultfactory
from twitcher.store.base import ProcessStore
from twitcher.visibility import VISIBILITY_PUBLIC, VISIBILITY_PRIVATE, visibility_values


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
            self.magpie_users = get_constant('MAGPIE_USERS_GROUP')
            self.magpie_admin = get_constant('MAGPIE_ADMIN_GROUP')
            self.magpie_current = get_constant('MAGPIE_LOGGED_USER')
            self.magpie_service = 'ems'
            self.twitcher_config = get_twitcher_configuration(registry.settings)
            self.twitcher_ssl_verify = asbool(registry.settings.get('twitcher.ows_proxy_ssl_verify', True))
            self.twitcher_service_url = None
            self.json_headers = {'Accept': 'application/json'}
        except AttributeError:
            #If magpie.url does not exist, calling strip fct over None will raise this issue
            raise ConfigurationError('magpie.url config cannot be found')

    def _get_service_public_url(self, request):
        if not self.twitcher_service_url and self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            # use generic 'current' user route to fetch service URL to ensure that even
            # a user with minimal privileges will still return a match
            path = '{host}/users/{usr}/services?inherit=true&cascade=true' \
                   .format(host=self.magpie_url, usr=self.magpie_current)
            resp = requests.get(path, cookies=request.cookies,
                                headers=self.json_headers, verify=self.twitcher_ssl_verify)
            if resp.status_code != HTTPOk.code:
                raise resp.raise_for_status()
            try:
                self.twitcher_service_url = resp.json()['services']['api'][self.magpie_service]['public_url']
                LOGGER.debug("Found service proxy url: {}".format(self.twitcher_service_url))
            except KeyError:
                raise ProcessNotFound("Could not find service `{}` endpoint.".format(self.magpie_service))
            except Exception as ex:
                LOGGER.debug("Exception during ems service url retrieval: [{}]".format(repr(ex)))
                raise
        return self.twitcher_service_url

    def _get_process_resources(self, request):
        """
        Gets all 'process' magpie resources corresponding to results under '/ems/processes'.
        Resources are filtered by user/groups permissions (only processes visible by this user).

        :returns: list of magpie resources.
        """
        path = '{host}/users/{usr}/resources?inherit=true'.format(host=self.magpie_url, usr=self.magpie_current)
        resp = requests.get(path, cookies=request.cookies,
                            headers=self.json_headers, verify=self.twitcher_ssl_verify)
        LOGGER.debug("Looking for resources on: `{}`.".format(path))
        if resp.status_code != HTTPOk.code:
            raise resp.raise_for_status()
        ems_resources = None
        try:
            ems_resources = resp.json()['resources']['api'][self.magpie_service]['resources']
            for res_id in ems_resources:
                if ems_resources[res_id]['resource_name'] == 'processes':
                    ems_processes = ems_resources[res_id]['children']
                    return ems_processes
        except KeyError:
            LOGGER.debug("Content of ems service resources: `{!r}`.".format(ems_resources))
            raise ProcessNotFound("Could not find resource `processes` endpoint for visibility retrieval.")
        except Exception as ex:
            LOGGER.debug("Exception during ems resources retrieval: [{}]".format(repr(ex)))
            raise
        LOGGER.debug("Could not find resource: `processes`.")
        return list()

    def _get_process_resource_id(self, process_id, ems_processes_resources, request):
        """
        Requests for a 'process' resource corresponding to '/ems/processes/{id}' and returns its corresponding
        magpie resource id if reading permission was granted to requesting user.

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
                    path = '{host}/processes/{id}'.format(host=self._get_service_public_url(request), id=process_id)
                    resp = requests.get(path, cookies=request.cookies,
                                        headers=self.json_headers, verify=self.twitcher_ssl_verify)
                    if resp.status_code == HTTPUnauthorized:
                        return None
                    elif resp.status_code == HTTPOk.code:
                        return ems_processes_resources[process_res_id]['resource_id']
                    raise resp.raise_for_status()
        except KeyError:
            LOGGER.debug("Content of processes resources: `{!r}`.".format(ems_processes_resources))
            raise ProcessNotFound("Could not find process `{}` resource for visibility retrieval.".format(process_id))
        except Exception as ex:
            LOGGER.debug("Exception during process resource retrieval: [{}]".format(repr(ex)))
            raise
        LOGGER.debug("Could not find resource: `{}`.".format(process_id))
        return None

    def _set_resource_permissions(self, resource_id, group_name, permission_names, request):
        """
        Sets group permissions on a resource.

        :param resource_id: (int) magpie id of the resource to apply permissions on.
        :param group_name: (str) name of the group for which to apply permissions, if any.
        :param permission_names: (None, str, iterator) group permissions to apply to the resource, if any.
        :param request: calling request for headers and credentials
        """
        if isinstance(group_name, six.string_types):
            if permission_names is None:
                permission_names = []
            if isinstance(permission_names, six.string_types):
                permission_names = [permission_names]

            for perm in permission_names:
                data = {u'permission_name': perm}
                path = '{host}/groups/{grp}/resources/{id}/permissions' \
                    .format(host=self.magpie_url, grp=group_name, id=resource_id)
                resp = requests.post(path, data=data, cookies=request.cookies,
                                     headers=self.json_headers, verify=self.twitcher_ssl_verify)
                # permission is set if created or already exists
                if resp.status_code not in (HTTPCreated.code, HTTPConflict.code):
                    raise resp.raise_for_status()

    def _create_resource(self, resource_name, resource_parent_id, group_name, permission_names, request):
        """
        Creates a resource under another parent resource, and sets basic group permissions on it.

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
            self._set_resource_permissions(res_id, group_name, permission_names, request)
            return res_id
        except KeyError:
            raise ProcessRegistrationError("Failed adding process resource route `{}`.".format(resource_name))
        except Exception as ex:
            LOGGER.debug("Exception during process resource creation: [{}]".format(repr(ex)))
            raise

    def save_process(self, process, overwrite=True, request=None):
        """
        Save a new process.

        If twitcher is not in EMS mode, delegate execution to default twitcher process store.
        If twitcher is in EMS mode:
            - user requesting creation must have sufficient administrator permissions in magpie to do so.
            - assign any pre-requirement routes permissions to allow admins to edit '/ems/processes/...'

            Requirements:
                - service 'ems' of type 'api' must exist
                - group 'administrators' must have ['read', 'write'] permissions on 'ems' service
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            try:
                # get resource id of ems service
                path = '{host}/services/{svc}'.format(host=self.magpie_url, svc=self.magpie_service)
                resp = requests.get(path, cookies=request.cookies,
                                    headers=self.json_headers, verify=self.twitcher_ssl_verify)
                if resp.status_code != HTTPOk.code:
                    raise resp.raise_for_status()
                ems_res_id = resp.json()[self.magpie_service]['resource_id']
            except KeyError:
                raise ProcessRegistrationError("Failed retrieving service resource.")
            except Exception as ex:
                LOGGER.debug("Exception during `{0}` resource retrieval: [{1}]".format(self.magpie_service, repr(ex)))
                raise

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
                    # members of 'administrators' automatically inherit read/write permissions from 'ems' service
                    processes_res_id = self._create_resource(u'processes', ems_res_id,
                                                             self.magpie_users, u'read-match', request)
            except KeyError:
                raise ProcessRegistrationError("Failed retrieving processes resource.")
            except Exception as ex:
                LOGGER.debug("Exception during `processes` resource retrieval: [{}]".format(repr(ex)))
                raise

            # create resources of route '/ems/processes/{id}' and '/ems/processes/{id}/jobs'
            # do not apply any permissions at first, so that the process is 'private' by default
            process_res_id = self._create_resource(process.id, processes_res_id, None, None, request)
            self._create_resource(u'jobs', process_res_id, None, None, request)

        return processstore_defaultfactory(request.registry).save_process(process, overwrite, request)

    def delete_process(self, process_id, request=None):
        """
        Delete a process.

        Delegate execution to default twitcher process store.
        If twitcher is in EMS mode:
            - user requesting deletion must have administrator permissions in magpie (delete route blocked otherwise).
            - also delete magpie resources tree corresponding to the process
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            resources = self._get_process_resources(request)
            resource_id = self._get_process_resource_id(process_id, resources, request)
            if not resource_id:
                raise ProcessNotFound("Could not find process `{}` for resource for deletion.".format(process_id))

            path = '{host}/resources/{id}'.format(host=self.magpie_url, id=resource_id)
            resp = requests.delete(path, cookies=request.cookies,
                                   headers=self.json_headers, verify=self.twitcher_ssl_verify)
            if resp.status_code != HTTPOk.code:
                raise resp.raise_for_status()

        return processstore_defaultfactory(request.registry).delete_process(process_id, request)

    def list_processes(self, visibility=None, request=None):
        """
        List publicly visible processes.

        Delegate execution to default twitcher process store.
        If twitcher is not in EMS mode, filter by only visible processes.
        If twitcher is in EMS mode, filter according to magpie user group memberships:
            - administrators: return everything
            - any other group: return only visible processes
        """
        visibility_filter = visibility
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            path = '{host}/users/{usr}/groups'.format(host=self.magpie_url, usr=self.magpie_current)
            resp = requests.get(path, cookies=request.cookies,
                                headers=self.json_headers, verify=self.twitcher_ssl_verify)
            if resp.status_code != HTTPOk.code:
                raise resp.raise_for_status()
            try:
                groups_memberships = resp.json()['group_names']
                if self.magpie_admin in groups_memberships:
                    visibility_filter = visibility_values
                else:
                    visibility_filter = VISIBILITY_PUBLIC
            except KeyError:
                raise ProcessNotFound("Failed retrieving processes read permissions for listing.")
            except Exception as ex:
                LOGGER.debug("Exception during processes listing: [{}]".format(repr(ex)))
                raise

        store = processstore_defaultfactory(request.registry)
        process_list = store.list_processes(visibility=visibility_filter, request=request)
        LOGGER.debug("Found visible processes: {!s}.".format(process_list))
        return process_list

    def fetch_by_id(self, process_id, request=None):
        """
        Get a process if visible for user.

        Delegate operation to default twitcher process store.
        If twitcher is in EMS mode:
            using twitcher proxy, magpie user/group permissions on corresponding resource (/ems/processes/{process_id})
            will automatically handle Ok/Unauthorized responses using the API route's read access.
        """
        return processstore_defaultfactory(request.registry).fetch_by_id(process_id, request=request)

    def get_visibility(self, process_id, request=None):
        """
        Get visibility of a process.

        Delegate operation to default twitcher process store.
        If twitcher is in EMS mode:
            using twitcher proxy, only administrators get read permissions on '/ems/processes/{process_id}/visibility'
            any other level user will get unauthorized on this route
        """
        return processstore_defaultfactory(request.registry).get_visibility(process_id, request=request)

    def set_visibility(self, process_id, visibility, request=None):
        """
        Set visibility of a process.

        Delegate change of process visibility to default twitcher process store.
        If twitcher is in EMS mode:
            using twitcher proxy, only administrators get write permissions on '/ems/processes/{process_id}/visibility'
            modify magpie permissions of corresponding process access points according to desired visibility.
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            ems_processes = self._get_process_resources(request)
            process_res_id = self._get_process_resource_id(process_id, ems_processes, request)
            if not process_res_id:
                raise ProcessNotFound("Could not find process `{}` resource to change visibility.".format(process_id))

            if visibility == VISIBILITY_PRIVATE:
                path = '{host}/groups/{usr}/resources/{id}/permissions/{perm}' \
                       .format(host=self.magpie_url, usr=self.magpie_users, id=process_res_id, perm=u'read')
                reps = requests.delete(path, cookies=request.cookies,
                                       headers=self.json_headers, verify=self.twitcher_ssl_verify)
                # permission is not set if deleted or non existing
                if reps.status_code not in (HTTPOk.code, HTTPNotFound.code):
                    raise reps.raise_for_status()

            elif visibility == VISIBILITY_PUBLIC:
                # read permission so that users can make any sub-route GET requests (ex: GET '/ems/processes/{id}/jobs')
                self._set_resource_permissions(process_res_id, self.magpie_users, u'read', request)

                # find resource corresponding to '/ems/processes/{id}/jobs'
                path = '{host}/resources/{id}'.format(host=self.magpie_url, id=process_res_id)
                resp = requests.get(path, cookies=request.cookies,
                                    headers=self.json_headers, verify=self.twitcher_ssl_verify)
                if resp.status_code != HTTPOk.code:
                    raise resp.raise_for_status()
                jobs_res_id = None
                process_resources = resp.json()[str(process_res_id)]['children']
                for res_id in process_resources:
                    if process_resources[res_id]['resource_name'] == 'jobs':
                        jobs_res_id = process_resources[res_id]['resource_id']
                        break
                if not jobs_res_id:
                    raise ProcessNotFound("Could not find process `{}` jobs resource to set visibility."
                                          .format(process_id))

                # use write-match permission so that users can ONLY execute a job (cannot DELETE process, job, etc.)
                self._set_resource_permissions(jobs_res_id, self.magpie_users, u'write-match', request)

        processstore_defaultfactory(request.registry).set_visibility(process_id, visibility=visibility, request=request)
