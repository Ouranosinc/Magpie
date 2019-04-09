"""
Store adapters to read data from magpie.
"""
from magpie.api.api_except import raise_http
from magpie.constants import get_constant
from magpie.definitions.pyramid_definitions import (
    HTTPOk,
    HTTPCreated,
    HTTPNotFound,
    HTTPConflict,
    HTTPNotImplemented,
    asbool,
)
from magpie.permissions import Permission
from magpie.services import ServiceAPI
from magpie.utils import get_magpie_url, get_admin_cookies, get_logger, CONTENT_TYPE_JSON

# import 'process' elements separately than 'twitcher_definitions' because not defined in master
# noinspection PyUnresolvedReferences
from twitcher.utils import get_twitcher_url
# noinspection PyUnresolvedReferences
from twitcher.config import get_twitcher_configuration, TWITCHER_CONFIGURATION_EMS
# noinspection PyUnresolvedReferences
from twitcher.exceptions import ProcessNotFound, ProcessRegistrationError
# noinspection PyUnresolvedReferences
from twitcher.adapter.default import DefaultAdapter
# noinspection PyUnresolvedReferences
from twitcher.store.base import ProcessStore
# noinspection PyUnresolvedReferences
from twitcher.visibility import VISIBILITY_PUBLIC, VISIBILITY_PRIVATE, visibility_values
# noinspection PyUnresolvedReferences
from twitcher.datatype import Process  # noqa: F401
from typing import TYPE_CHECKING
import six
import requests
if TYPE_CHECKING:
    from typing import List, Optional, Iterable, Union, AnyStr  # noqa: F401
    from magpie.definitions.pyramid_definitions import Registry  # noqa: F401
LOGGER = get_logger("TWITCHER")


class MagpieProcessStore(ProcessStore):
    """
    Registry for OWS processes.
    Uses default process store for most operations.
    Uses magpie to update process access and visibility.
    """

    def __init__(self, registry):
        # type: (Registry) -> None
        super(MagpieProcessStore, self).__init__()
        self.magpie_url = get_magpie_url(registry)
        self.twitcher_ssl_verify = asbool(registry.settings.get("twitcher.ows_proxy_ssl_verify", True))
        self.magpie_admin_token = get_admin_cookies(self.magpie_url, self.twitcher_ssl_verify)
        self.magpie_admin_group = get_constant("MAGPIE_ADMIN_GROUP")
        self.magpie_users = get_constant("MAGPIE_USERS_GROUP")
        self.magpie_editors = get_constant("MAGPIE_EDITOR_GROUP")
        self.magpie_current = get_constant("MAGPIE_LOGGED_USER")
        self.magpie_service = "ems"
        self.default_process_store = DefaultAdapter().processstore_factory(registry)
        self.twitcher_config = get_twitcher_configuration(registry.settings)
        self.twitcher_url = get_twitcher_url(registry.settings)
        self.json_headers = {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON}

        # setup basic configuration ("/ems" service of type "api", "/ems/processes" resource, admin full permissions)
        ems_data = {"service_type": ServiceAPI.service_type, "service_url": self.twitcher_url}
        ems_res_id = self._create_resource(self.magpie_service, resource_parent_id=None, resource_type="service",
                                           group_names=self.magpie_admin_group,
                                           permissions=[Permission.READ, Permission.WRITE],
                                           extra_data=ems_data)
        proc_res_id = self._create_resource("processes", ems_res_id)  # admins inherit from parent service permissions

        # editors can read/write processes, but will only be able to modify visibility for "their" (per user) process
        # permissions of each corresponding process have to be added for the requesting user when created
        editor_perms = [Permission.READ_MATCH, Permission.WRITE_MATCH]
        self._create_group(self.magpie_editors)  # create in case it doesn't exist (non-standard group)
        self._create_resource_permissions(ems_res_id, editor_perms, group_names=self.magpie_editors)
        self._create_resource_permissions(proc_res_id, editor_perms, group_names=self.magpie_editors)

        # users can only read processes, but not edit/deploy/remove them (no PUT/POST/DELETE requests)
        self._create_resource_permissions(ems_res_id, Permission.READ_MATCH, group_names=self.magpie_users)
        self._create_resource_permissions(proc_res_id, Permission.READ_MATCH, group_names=self.magpie_users)

    def _find_resource_id(self, parent_resource_id, resource_name):
        # type: (int, AnyStr) -> int
        """
        Finds the resource id corresponding to a child ``resource_name`` of ``parent_resource_id``.
        If ``parent_resource_id`` is ``None``, suppose the resource is a ``service``, search by ``resource_name``.

        :param parent_resource_id: id of the resource from which to search children resources.
        :param resource_name: name of the sub resource to find.
        :return: found resource id
        """
        if not parent_resource_id:
            path = "{host}/services/{svc}".format(host=self.magpie_url, svc=resource_name)
            resp = requests.get(path, cookies=self.magpie_admin_token,
                                headers=self.json_headers, verify=self.twitcher_ssl_verify)
            resp.raise_for_status()
            return resp.json()["service"]["resource_id"]

        path = "{host}/resources/{id}".format(host=self.magpie_url, id=parent_resource_id)
        resp = requests.get(path, cookies=self.magpie_admin_token,
                            headers=self.json_headers, verify=self.twitcher_ssl_verify)
        resp.raise_for_status()
        child_res_id = None
        parent_resource_info = resp.json()["resource"]
        children_resources = parent_resource_info["children"]
        for res_id in children_resources:
            if children_resources[res_id]["resource_name"] == resource_name:
                child_res_id = children_resources[res_id]["resource_id"]
                return child_res_id
        if not child_res_id:
            detail = "Could not find resource '{}' under resource '{}'." \
                     .format(resource_name, parent_resource_info["resource_name"])
            raise_http(httpError=HTTPNotFound, detail=detail)

    def _get_service_processes_resource(self):
        # type: () -> Optional[int]
        """
        Finds the magpie resource 'processes' corresponding to '/ems/processes'.

        :returns: id of the 'processes' resource.
        """
        path = "{host}/resources".format(host=self.magpie_url)
        resp = requests.get(path, cookies=self.magpie_admin_token,
                            headers=self.json_headers, verify=self.twitcher_ssl_verify)
        resp.raise_for_status()
        ems_resources = None
        try:
            ems_resources = resp.json()["resources"]["api"][self.magpie_service]["resources"]
            for res_id in ems_resources:
                if ems_resources[res_id]["resource_name"] == "processes":
                    ems_processes_id = ems_resources[res_id]["resource_id"]
                    return ems_processes_id
        except KeyError:
            LOGGER.debug("Content of '{}' service resources: `{!r}`.".format(self.magpie_service, ems_resources))
            raise ProcessNotFound("Could not find resource `processes` endpoint.")
        except Exception as ex:
            LOGGER.debug("Exception during '{}' resources retrieval: [{}]".format(self.magpie_service, repr(ex)))
            raise
        LOGGER.debug("Could not find resource: `processes`.")
        return None

    def _create_group(self, group_name):
        # type: (str) -> None
        """Creates group if it doesn't exist."""

        path = "{host}/groups".format(host=self.magpie_url)
        resp = requests.post(path, cookies=self.magpie_admin_token, json={u"group_name": group_name},
                             headers=self.json_headers, verify=self.twitcher_ssl_verify)
        if resp.status_code not in (HTTPCreated.code, HTTPConflict.code):
            LOGGER.debug("Group '{}' creation or validation failed.".format(group_name))
            resp.raise_for_status()

    def _create_resource_permissions(self,
                                     resource_id,       # type: int
                                     permissions,       # type: Union[Permission, Iterable[Permission]]
                                     group_names=None,  # type: Optional[Union[AnyStr, List[AnyStr]]]
                                     user_names=None,   # type: Optional[Union[AnyStr, List[AnyStr]]]
                                     ):                 # type: (...) -> None
        """
        Creates group permission(s) on a resource.

        :param resource_id: magpie id of the resource to apply permissions on.
        :param permissions: permission(s) to apply to the resource.
        :param group_names: name of the group(s) for which to apply permissions, if Any.
        :param user_names: name of the user(s) for which to apply permissions, if Any.
        """
        if not user_names:
            user_names = list()
        if not group_names:
            group_names = list()
        if isinstance(user_names, six.string_types):
            user_names = [user_names]
        if isinstance(group_names, six.string_types):
            group_names = [group_names]
        if isinstance(permissions, six.string_types):
            permissions = [permissions]
        user_group_tuples = [("users", user) for user in user_names] + [("groups", group) for group in group_names]
        for perm in permissions:
            data = {u"permission_name": perm.value}
            for usr_grp, usr_grp_id in user_group_tuples:
                path = "{host}/{usr_grp}/{id}/resources/{res_id}/permissions" \
                       .format(host=self.magpie_url, usr_grp=usr_grp, id=usr_grp_id, res_id=resource_id)
                resp = requests.post(path, json=data, cookies=self.magpie_admin_token,
                                     headers=self.json_headers, verify=self.twitcher_ssl_verify)
                # permission is set if created or already exists
                if resp.status_code not in (HTTPCreated.code, HTTPConflict.code):
                    resp.raise_for_status()

    def _delete_resource_permissions(self,
                                     resource_id,       # type: int
                                     permissions,       # type: Union[Permission, List[Permission]]
                                     group_names=None,  # type: Optional[Union[AnyStr, List[AnyStr]]]
                                     user_names=None,   # type: Optional[Union[AnyStr, List[AnyStr]]]
                                     ):                 # type: (...) -> None
        """
        Deletes group permission(s) on a resource.

        :param resource_id: magpie id of the resource to remove permissions from.
        :param permissions: group permission(s) to apply to the resource.
        :param group_names: name of the group(s) for which to apply permissions, if Any.
        :param user_names: name of the user(s) for which to apply permissions, if Any.
        """
        if not user_names:
            user_names = list()
        if not group_names:
            group_names = list()
        if isinstance(user_names, six.string_types):
            user_names = [user_names]
        if isinstance(group_names, six.string_types):
            group_names = [group_names]
        if isinstance(permissions, six.string_types):
            permissions = [permissions]
        user_group_tuples = [("users", user) for user in user_names] + [("groups", group) for group in group_names]
        for perm in permissions:
            for usr_grp, usr_grp_id in user_group_tuples:
                path = "{host}/{usr_grp}/{id}/resources/{res_id}/permissions/{perm}" \
                       .format(host=self.magpie_url, usr_grp=usr_grp, id=usr_grp_id,
                               res_id=resource_id, perm=perm.value)
                reps = requests.delete(path, cookies=self.magpie_admin_token,
                                       headers=self.json_headers, verify=self.twitcher_ssl_verify)
                # permission is not set if deleted or non existing
                if reps.status_code not in (HTTPOk.code, HTTPNotFound.code):
                    reps.raise_for_status()

    def _create_resource(self,
                         resource_name,             # type: AnyStr
                         resource_parent_id,        # type: int, None
                         group_names=None,          # type: Optional[Union[AnyStr, Iterable[AnyStr]]]
                         permissions=None,          # type: Optional[Union[Permission, Iterable[Permission]]]
                         resource_type="route",     # type: Optional[AnyStr]
                         extra_data=None,           # type: Optional[dict]
                         ):                         # type: (...) -> int
        """
        Creates a resource under another parent resource, and sets basic group permissions on it.
        If the resource already exists for some reason, use it instead of the created one, and apply permissions.

        :param resource_name: name of the resource to create.
        :param resource_parent_id: id of the parent resource under which to create `resource_name`.
        :param group_names: group name(s) for which to apply permissions to the created resource, if any.
        :param permissions: group permissions to apply to the created resource, if any.
        :param resource_type: type of resource to be created.
        :returns: id of the created resource
        """
        try:
            data = {u"parent_id": resource_parent_id, u"resource_name": resource_name, u"resource_type": resource_type}
            post_type = "resources"
            if resource_type == "service":
                post_type = "services"
                data.update(extra_data or {})
                data.update({"service_name": resource_name})
            path = "{host}/{type}".format(host=self.magpie_url, type=post_type)
            resp = requests.post(path, json=data, cookies=self.magpie_admin_token,
                                 headers=self.json_headers, verify=self.twitcher_ssl_verify)
            res_id = None
            if resp.status_code == HTTPCreated.code:
                if resource_type == "service":
                    res_id = self._find_resource_id(resource_parent_id, resource_name)
                else:
                    res_id = resp.json()["resource"]["resource_id"]
            elif resp.status_code == HTTPConflict.code:
                res_id = self._find_resource_id(resource_parent_id, resource_name)
            else:
                resp.raise_for_status()
            if group_names is not None and permissions is not None:
                self._create_resource_permissions(res_id, permissions, group_names=group_names)
            return res_id
        except KeyError:
            raise ProcessRegistrationError("Failed adding process resource route '{}'.".format(resource_name))
        except Exception as ex:
            LOGGER.debug("Exception during process resource creation: [{}]".format(repr(ex)))
            raise

    def save_process(self, process, overwrite=True, request=None):
        # type: (Process, bool, Optional[requests.Request]) -> None
        """
        Save a new process.

        If twitcher is not in EMS mode, delegate execution to default twitcher process store.
        If twitcher is in EMS mode:
            - user requesting creation must have sufficient user/group permissions in magpie to do so.
              (otherwise, this code won't be reached because of :class:`MagpieOWSSecurity` blocking the create route.
            - assign any pre-required routes permissions to allow admins and current user to edit ``/ems/processes/...``

            Requirements:
                - service ``self.magpie_service`` of type ``api`` must exist (see ``__init__``)
                - group ``'administrators'`` must have ``[READ, WRITE]`` permissions on ``magpie_service``
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            try:
                # get resource id of ems service
                path = "{host}/services/{svc}".format(host=self.magpie_url, svc=self.magpie_service)
                resp = requests.get(path, cookies=self.magpie_admin_token,
                                    headers=self.json_headers, verify=self.twitcher_ssl_verify)
                resp.raise_for_status()
                ems_res_id = resp.json()["service"]["resource_id"]
            except KeyError:
                raise ProcessRegistrationError("Failed retrieving service resource.")
            except Exception as ex:
                LOGGER.debug("Exception during `{0}` resource retrieval: [{1}]".format(self.magpie_service, repr(ex)))
                raise

            # create resources of sub-routes "/{process_id}", "/{process_id}/jobs", "/{process_id}/quotations"
            # do not apply any users/editors permissions at first, so that the process is "private" by default
            proc_res_id = self._find_resource_id(ems_res_id, "processes")
            process_res_id = self._create_resource(process.id, proc_res_id)
            self._create_resource(u"jobs", process_res_id)
            self._create_resource(u"quotations", process_res_id)

            # current editor user is the only one allowed to edit his process (except admins), get is name from session
            resp = requests.get("{host}/session".format(host=self.magpie_url), cookies=request.cookies,  # current user
                                headers=self.json_headers, verify=self.twitcher_ssl_verify)
            resp.raise_for_status()
            try:
                user_name = resp.json()["user"]["user_name"]
                user_perm = [Permission.READ, Permission.WRITE]
                self._create_resource_permissions(process_res_id, user_perm, user_names=user_name)
            except KeyError:
                # If the request is anonymous do not create the permission
                pass

        return self.default_process_store.save_process(process, overwrite, request)

    def delete_process(self, process_id, visibility=None, request=None):
        # type: (AnyStr, Optional[AnyStr], Optional[requests.Request]) -> bool
        """
        Delete a process.

        Delegate execution to default twitcher process store.
        If twitcher is in EMS mode:
            - user requesting deletion must have user/group permissions in magpie to do so.
              (otherwise, this code won't be reached because of :class:`MagpieOWSSecurity` blocking the delete route.
            - also delete magpie resources tree corresponding to the process
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            ems_processes_id = None
            try:
                ems_processes_id = self._get_service_processes_resource()
            except (ProcessNotFound, HTTPNotFound):
                pass
            try:
                if self.is_visible_by_user(ems_processes_id, process_id, request):
                    # override to allow deletion of process if accessible by user regardless of 'visibility' setting
                    visibility = None

                    # search for resource, skip cleanup with raised http if not found
                    process_res_id = self._find_resource_id(ems_processes_id, process_id)

                    # delete top-resource, magpie should automatically handle deletion of all sub-resources/permissions
                    path = "{host}/resources/{id}".format(host=self.magpie_url, id=process_res_id)
                    resp = requests.delete(path, cookies=self.magpie_admin_token,
                                           headers=self.json_headers, verify=self.twitcher_ssl_verify)
                    resp.raise_for_status()
            except HTTPNotFound:
                # If for any reason the resource that we want to delete does not exist silently ignore it
                pass

        return self.default_process_store.delete_process(process_id, visibility=visibility, request=request)

    def list_processes(self, visibility=None, request=None):
        # type: (Optional[AnyStr], Optional[requests.Request]) -> List[Process]
        """
        List publicly visible processes according to the requesting user's user/group permissions.

        Delegate execution to default twitcher process store to retrieve visibility values per process.
        If twitcher is not in EMS mode, filter by only visible processes using specified ``visibility``.
        If twitcher is in EMS mode, filter processes according to magpie user and inherited group permissions.
        """
        visibility_filter = visibility if self.twitcher_config != TWITCHER_CONFIGURATION_EMS else visibility_values
        processes = self.default_process_store.list_processes(visibility=visibility_filter, request=request)

        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            try:
                ems_processes_id = self._get_service_processes_resource()
                processes = list(filter(lambda p: self.is_visible_by_user(ems_processes_id, p.id, request), processes))
            except KeyError:
                raise ProcessNotFound("Failed retrieving processes read permissions for listing.")
            except Exception as ex:
                LOGGER.debug("Exception during processes listing: [{}]".format(repr(ex)))
                raise

        LOGGER.debug("Found visible processes: {!s}.".format([process.id for process in processes]))
        return processes

    def fetch_by_id(self, process_id, visibility=None, request=None):
        # type: (AnyStr, Optional[AnyStr], Optional[requests.Request]) -> Optional[Process]
        """
        Get a process if visible for user.

        Delegate operation to default twitcher process store.
        If twitcher is in EMS mode:
          - using twitcher proxy, magpie user/group permissions on corresponding resource (/ems/processes/{process_id})
            will automatically handle Ok/Unauthorized responses using the API route's read access.
          - ignore passed `visibility` if any and infer it from magpie user/group permissions instead
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS and visibility:
            ems_processes_id = self._get_service_processes_resource()

            # override to allow retrieval of process if accessible by user regardless of 'visibility' setting
            if self.is_visible_by_user(ems_processes_id, process_id, request):
                visibility = None

        return self.default_process_store.fetch_by_id(process_id, visibility=visibility, request=request)

    def is_admin_user(self, request):
        # type: (requests.Request) -> bool
        """Verifies if a user has administrator level permissions."""
        resp = requests.get("{host}/session".format(host=self.magpie_url), cookies=request.cookies,
                            headers=self.json_headers, verify=self.twitcher_ssl_verify)
        return self.magpie_admin_group in resp.json().get("user", {}).get("group_names", [])

    def is_visible_by_user(self, ems_processes_id, process_id, request):
        # type: (int, AnyStr, requests.Request) -> bool
        """
        Verifies if the user (according to cookies from the request) can see a given process by id.

        :param ems_processes_id: Magpie resource id corresponding to '/ems/processes'.
        :param process_id: identifier of the WPS process.
        :param request: request to identify which user the visibility permissions has to be tested for.
        """
        # if the resource cannot be found, permissions are definitely not set, so it is not visible
        try:
            process_res_id = self._find_resource_id(ems_processes_id, process_id)
        except HTTPNotFound:
            return False

        # use inherited flag to consider both user and group permissions on the resource
        # use effective flag to ensure that permissions set on parent resources are cascaded down onto this process
        path = "{host}/users/{usr}/resources/{res}/permissions?inherit=true&effective=true" \
               .format(host=self.magpie_url, usr=self.magpie_current, res=process_res_id)
        resp = requests.get(path, cookies=request.cookies, headers=self.json_headers, verify=self.twitcher_ssl_verify)
        resp.raise_for_status()
        perms = resp.json()["permission_names"]

        # user/group must have inherited read/read-match permissions, or
        # be an administrator even if permissions are not set explicitly
        if all(p.value not in perms for p in [Permission.READ, Permission.READ_MATCH]):
            return self.is_admin_user(request)
        return True

    def get_visibility(self, process_id, request=None):
        # type: (AnyStr, Optional[requests.Request]) -> AnyStr
        """
        Get visibility of a process.

        Delegate operation to default twitcher process store.
        If twitcher is in EMS mode:
            using twitcher proxy, only allowed users/groups can read "/ems/processes/{process_id}/visibility"
            any other level user will get unauthorized on this route
        """
        return self.default_process_store.get_visibility(process_id, request=request)

    def set_visibility(self, process_id, visibility, request=None):
        # type: (AnyStr, AnyStr, Optional[requests.Request]) -> None
        """
        Set visibility of a process.

        Delegate change of process visibility to default twitcher process store.
        If twitcher is in EMS mode:
            using twitcher proxy, only allowed users/groups can write to "/ems/processes/{process_id}/visibility"
            modify magpie permissions of corresponding process access points according to desired visibility.
        """
        if self.twitcher_config == TWITCHER_CONFIGURATION_EMS:
            try:
                # find resources corresponding to each route part of "/ems/processes/{id}/[jobs|quotations]"
                ems_processes_id = self._get_service_processes_resource()
                process_res_id = self._find_resource_id(ems_processes_id, process_id)
                jobs_res_id = self._find_resource_id(process_res_id, "jobs")
                quotes_res_id = self._find_resource_id(process_res_id, "quotations")
                groups = [self.magpie_users, self.magpie_editors]

                if visibility == VISIBILITY_PRIVATE:
                    # remove write-match permissions of groups on the process, cannot execute POST /jobs
                    self._delete_resource_permissions(jobs_res_id, Permission.WRITE_MATCH, group_names=groups)
                    # remove write permissions of groups, cannot request POST /quotations & /quotations/{id}
                    self._delete_resource_permissions(quotes_res_id, Permission.WRITE, group_names=groups)
                    # remove group read permissions on the process, cannot GET any info from it, not even see it in list
                    self._delete_resource_permissions(process_res_id, Permission.READ, group_names=groups)

                elif visibility == VISIBILITY_PUBLIC:
                    # read permission to groups to allow any sub-route GET requests (ex: "/ems/processes/{id}/jobs")
                    self._create_resource_permissions(process_res_id, Permission.READ, group_names=groups)
                    # write permissions to groups to allow request POST /quotations & /quotations/{id}
                    self._create_resource_permissions(quotes_res_id, Permission.WRITE, group_names=groups)
                    # write-match group permission so they can ONLY execute a job (cannot DELETE process, job, etc.)
                    self._create_resource_permissions(jobs_res_id, Permission.WRITE_MATCH, group_names=groups)

            except HTTPNotFound:
                raise ProcessNotFound("Could not find process '{}' jobs resource to set visibility.".format(process_id))
            except Exception as ex:
                LOGGER.debug("Exception when trying to set process visibility: [{}]".format(repr(ex)))
                raise

        # update visibility of process, which will also reflect changes to route permissions during 'list_processes'
        self.default_process_store.set_visibility(process_id, visibility=visibility, request=request)

    # noinspection PyMethodMayBeStatic, PyUnusedLocal
    def clear_processes(self, request=None):
        raise_http(httpError=HTTPNotImplemented, detail="Clear processes not supported via MagpieAdapter.")
