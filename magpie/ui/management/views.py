import json
from collections import OrderedDict
from datetime import datetime
from typing import TYPE_CHECKING

import humanize
import transaction
import yaml
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPException,
    HTTPFound,
    HTTPMovedPermanently,
    HTTPNotFound,
    HTTPUnprocessableEntity
)
from pyramid.settings import asbool
from pyramid.view import view_config

from magpie import register
from magpie.api import schemas
from magpie.cli import sync_resources
from magpie.cli.sync_resources import OUT_OF_SYNC
from magpie.constants import get_constant
# FIXME: remove (REMOTE_RESOURCE_TREE_SERVICE, RESOURCE_TYPE_DICT), implement getters via API
from magpie.models import REMOTE_RESOURCE_TREE_SERVICE, RESOURCE_TYPE_DICT, UserGroupStatus, UserStatuses
from magpie.permissions import Permission, PermissionSet
# FIXME: remove (SERVICE_TYPE_DICT), implement getters via API
from magpie.services import SERVICE_TYPE_DICT
from magpie.ui.utils import AdminRequests, BaseViews, check_response, handle_errors, request_api
from magpie.utils import CONTENT_TYPE_JSON, get_json, get_logger, is_json_body

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional, Tuple

    from sqlalchemy.orm.session import Session

    from magpie.typedefs import JSON, Str

LOGGER = get_logger(__name__)


class ManagementViews(AdminRequests, BaseViews):
    @handle_errors
    def goto_service(self, resource_id):
        path = schemas.ResourceAPI.path.format(resource_id=resource_id)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        body = get_json(resp)
        svc_name = body["resource"]["resource_name"]
        # get service type instead of 'cur_svc_type' in case of 'default' ('cur_svc_type' not set yet)
        path = schemas.ServiceAPI.path.format(service_name=svc_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        body = get_json(resp)
        svc_type = body["service"]["service_type"]
        return HTTPFound(self.request.route_url("edit_service", service_name=svc_name, cur_svc_type=svc_type))

    @view_config(route_name="view_users", renderer="templates/view_users.mako")
    def view_users(self):
        user_name = self.request.POST.get("user_name")

        if "delete" in self.request.POST:
            path = schemas.UserAPI.path.format(user_name=user_name)
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)

        if "edit" in self.request.POST:
            return HTTPFound(self.request.route_url("edit_user", user_name=user_name, cur_svc_type="default"))

        if "delete-pending" in self.request.POST:
            path = schemas.RegisterUserAPI.path.format(user_name=user_name)
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)

        if "view-pending" in self.request.POST:
            return HTTPFound(self.request.route_url("view_pending_user", user_name=user_name))

        users = self.get_user_details(status="all")
        non_error = UserStatuses.OK | UserStatuses.Pending  # use combine in case more error types gets added later on
        user_names = [user["user_name"] for user in users]
        user_error = [user["user_name"] for user in users if UserStatuses.get(user["status"]) not in non_error]
        pending = [user["user_name"] for user in users if UserStatuses.get(user["status"]) == UserStatuses.Pending]
        return self.add_template_data({"users": user_names, "users_with_error": user_error, "users_pending": pending})

    @view_config(route_name="add_user", renderer="templates/add_user.mako")
    def add_user(self):
        """
        User creation by a logged administrator.

        .. note::
            The template employed for this form is reused for user self-registration as the fields and validation
            of inputs are essentially the same. Their actual processing is different though, as the administrator
            user is already logged in this case, and nobody is logged in the other.

        .. seealso::
            :meth:`magpie.ui.login.views.LoginViews.register_user`
        """
        groups = self.get_all_groups(first_default_group=self.MAGPIE_ANONYMOUS_GROUP)
        return_data = {"user_groups": groups, "is_registration": False}
        return_data = self.create_user_default_template_data(return_data)

        if "create" in self.request.POST:
            # delegate form submission to validation and creation
            return_data = self.create_user(return_data)
            if return_data["is_error"]:
                return self.add_template_data(return_data)
            # successful user creation, redirect to list of users since logged administrator
            # initiated this process from there by clicking the 'add user' button
            return HTTPFound(self.request.route_url("view_users"))
        # first page load or refresh
        return self.add_template_data(return_data)

    @view_config(route_name="edit_user", renderer="templates/edit_user.mako")
    def edit_user(self):
        """
        Edit the fields of any referenced user profile by an administrator.

        .. seealso::
            - :meth:`magpie.ui.user.views.UserViews.edit_current_user` for corresponding operation by user self-update
        """
        user_name = self.request.matchdict["user_name"]  # keep reference to original name in case of update request
        cur_svc_type = self.request.matchdict["cur_svc_type"]
        inherit_grp_perms = self.request.matchdict.get("inherit_groups_permissions", False)

        own_groups = self.get_user_groups(user_name)
        pending_groups = self.get_user_groups(user_name, user_group_status=UserGroupStatus.PENDING)
        all_groups = self.get_all_groups(first_default_group=get_constant("MAGPIE_USERS_GROUP", self.request))

        # TODO:
        #   Until the api is modified to make it possible to request from the RemoteResource table,
        #   we have to access the database directly here
        session = self.request.db

        svc_types, cur_svc_type, services = self.get_services(cur_svc_type)

        user_path = schemas.UserAPI.path.format(user_name=user_name)
        user_resp = request_api(self.request, user_path, "GET")
        check_response(user_resp)

        # set default values needed by the page in case of early return due to error
        user_info = get_json(user_resp)["user"]
        user_info["user_edit_email"] = True  # always allowed by administrators
        user_info["user_with_error"] = UserStatuses.get(user_info["status"]) != UserStatuses.OK
        user_info["edit_mode"] = "no_edit"
        user_info["own_groups"] = own_groups
        user_info["pending_groups"] = pending_groups
        user_info["groups"] = all_groups
        user_info["cur_svc_type"] = cur_svc_type
        user_info["svc_types"] = svc_types
        user_info["inherit_groups_permissions"] = inherit_grp_perms
        user_info["error_message"] = ""
        user_info["last_sync"] = "Never"
        user_info["ids_to_clean"] = []
        user_info["out_of_sync"] = []
        user_info["sync_implemented"] = False
        param_fields = ["password", "user_name", "user_email"]

        for field in param_fields:
            user_info["invalid_{}".format(field)] = False
            user_info["reason_{}".format(field)] = ""

        if self.request.method == "POST":
            res_id = self.request.POST.get("resource_id")
            is_edit_group_membership = False
            is_save_user_info = False
            requires_update_name = False

            if "inherit_groups_permissions" in self.request.POST:
                inherit_grp_perms = asbool(self.request.POST["inherit_groups_permissions"])
                user_info["inherit_groups_permissions"] = inherit_grp_perms

            if "delete" in self.request.POST:
                resp = request_api(self.request, user_path, "DELETE")
                check_response(resp)
                return HTTPFound(self.request.route_url("view_users"))
            if "goto_service" in self.request.POST:
                return self.goto_service(res_id)

            if "clean_resource" in self.request.POST:
                # "clean_resource" must be above "edit_permissions" because they"re in the same form.
                self.delete_resource(res_id)
            elif "edit_permissions" in self.request.POST and not inherit_grp_perms:
                # FIXME:
                #   Add remote does not make sense anymore because we batch update resources (instead of one-by-one).
                #   Also not necessary because recursive permission don't require to actually have the sub-resources.
                #   If resources are needed to apply permissions on them, they are either added manually or via sync.
                # if not res_id or res_id == "None":
                #     remote_id = int(self.request.POST.get("remote_id"))
                #     services_names = [s["service_name"] for s in services.values()]
                #     res_id = self.add_remote_resource(cur_svc_type, services_names, user_name,
                #                                       remote_id, is_user=True)
                self.edit_user_or_group_resource_permissions(user_name, is_user=True)
            elif "edit_group_membership" in self.request.POST:
                is_edit_group_membership = True
            elif "edit_username" in self.request.POST:
                user_info["edit_mode"] = "edit_username"
            elif "edit_password" in self.request.POST:
                user_info["edit_mode"] = "edit_password"
            elif "edit_email" in self.request.POST:
                user_info["edit_mode"] = "edit_email"
            elif "save_username" in self.request.POST:
                user_info["user_name"] = self.request.POST.get("new_user_name")
                is_save_user_info = True
                requires_update_name = True
            elif "save_password" in self.request.POST:
                user_info["password"] = self.request.POST.get("new_user_password")
                is_save_user_info = True
            elif "save_email" in self.request.POST:
                user_info["email"] = self.request.POST.get("new_user_email")
                is_save_user_info = True
            elif "force_sync" in self.request.POST:
                _, errmsg = self.sync_services(services)
                user_info["error_message"] += errmsg or ""
            elif "clean_all" in self.request.POST:
                ids_to_clean = self.request.POST.get("ids_to_clean").split(";")
                for id_ in ids_to_clean:
                    self.delete_resource(id_)

            if is_save_user_info:
                resp = request_api(self.request, user_path, "PATCH", data=user_info)
                if resp.status_code in (HTTPBadRequest.code, HTTPUnprocessableEntity.code):
                    requires_update_name = False  # revoke fetch new name because failure occurred
                    # attempt to retrieve the API more-specific reason why the operation is invalid
                    body = get_json(resp)
                    param_name = body.get("param", {}).get("name")
                    reason = body.get("detail", "Invalid")
                    for field in param_fields:
                        if param_name == field:
                            user_info["invalid_{}".format(field)] = True
                            user_info["reason_{}".format(field)] = reason
                            break  # cannot return early because we are still missing other resources/permissions info
                else:
                    check_response(resp)
                    # FIXME: need to commit updates since we are using the same session
                    #        otherwise, updated user doesn't exist yet in the db for next calls
                    self.request.tm.commit()

            # ensure remove password from output (just in case)
            user_info.pop("password", None)

            if requires_update_name:
                # re-fetch user groups as current user-group will have changed on new user_name
                user_name = user_info["user_name"]
                user_info["own_groups"] = self.get_user_groups(user_name)
                # return immediately with updated URL to user with new name
                users_url = self.request.route_url("edit_user", user_name=user_name, cur_svc_type=cur_svc_type)
                return HTTPMovedPermanently(location=users_url)

            # edits to groups checkboxes
            if is_edit_group_membership:
                selected_groups = self.request.POST.getall("member")
                removed_groups = list(set(own_groups) - set(selected_groups) - {self.MAGPIE_ANONYMOUS_GROUP})
                new_groups = list(set(selected_groups) - set(own_groups))
                for group in removed_groups:
                    path = schemas.UserGroupAPI.path.format(user_name=user_name, group_name=group)
                    resp = request_api(self.request, path, "DELETE")
                    check_response(resp)

                user_info["edit_new_membership_error"] = set()
                successful_new_groups = set()
                for group in new_groups:
                    try:
                        path = schemas.UserGroupsAPI.path.format(user_name=user_name)
                        data = {"group_name": group}
                        resp = request_api(self.request, path, "POST", data=data)
                        check_response(resp)
                    except HTTPException as exc:
                        detail = "{} ({}), {!s}".format(type(exc).__name__, exc.code, exc)
                        LOGGER.error("Unexpected API error under UI operation. [%s]", detail)
                        user_info["edit_new_membership_error"].add(group)
                    else:
                        successful_new_groups.add(group)
                user_info["own_groups"] = self.get_user_groups(user_name)
                user_info["pending_groups"] = self.get_user_groups(user_name, user_group_status=UserGroupStatus.PENDING)

                user_info["edit_membership_pending_success"] = successful_new_groups & set(user_info["pending_groups"])

        # display resources permissions per service type tab
        try:
            res_perm_names, res_perms = self.get_user_or_group_resources_permissions_dict(
                user_name, services, cur_svc_type, is_user=True, is_inherit_groups_permissions=inherit_grp_perms
            )
        except Exception as exc:
            raise HTTPBadRequest(detail=repr(exc))

        sync_types = [s["service_sync_type"] for s in services.values()]
        sync_implemented = any(s in sync_resources.SYNC_SERVICES_TYPES for s in sync_types)

        info = self.get_remote_resources_info(res_perms, services, session)
        res_perms, ids_to_clean, last_sync_humanized, out_of_sync = info

        if out_of_sync:
            user_info["error_message"] = self.make_sync_error_message(out_of_sync)

        user_info["ids_to_clean"] = ";".join(ids_to_clean)
        user_info["last_sync"] = last_sync_humanized
        user_info["sync_implemented"] = sync_implemented
        user_info["out_of_sync"] = out_of_sync
        user_info["cur_svc_type"] = cur_svc_type
        user_info["svc_types"] = svc_types
        user_info["resources"] = res_perms
        user_info["permissions"] = res_perm_names
        user_info["permission_titles"] = [Permission(perm).title for perm in res_perm_names]
        return self.add_template_data(data=user_info)

    def view_pending_user(self):
        """
        Displays a pending user registration profile details.

        .. note::
            View configuration is added dynamically because this page it should be available only when the
            corresponding feature is activated with configuration settings.
        """
        user_name = self.request.matchdict["user_name"]
        path = schemas.RegisterUserAPI.path.format(user_name=user_name)

        # process removal of pending user registration the same way with either button
        if "delete" in self.request.POST or "decline" in self.request.POST:
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)
            return HTTPFound(self.request.route_url("view_users"))

        resp = request_api(self.request, path)
        check_response(resp)
        data = get_json(resp)["registration"]

        # approval must be done with the explicit URL, user should exist afterwards
        if "approve" in self.request.POST and data["approve_url"]:
            path = data["approve_url"]
            resp = request_api(self.request, path, "GET")
            check_response(resp)
            return HTTPFound(self.request.route_url("edit_user", user_name=user_name, cur_svc_type="default"))

        return self.add_template_data(data=data)

    @view_config(route_name="view_groups", renderer="templates/view_groups.mako")
    def view_groups(self):
        if "delete" in self.request.POST:
            group_name = self.request.POST.get("group_name")
            path = schemas.GroupAPI.path.format(group_name=group_name)
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)

        if "edit" in self.request.POST:
            group_name = self.request.POST.get("group_name")
            return HTTPFound(self.request.route_url("edit_group", group_name=group_name, cur_svc_type="default"))

        groups_info = {}
        groups = sorted(self.get_all_groups())
        for grp in groups:
            if grp != "":
                groups_info.setdefault(grp, {"members": len(self.get_group_users(grp))})
        return self.add_template_data({"group_names": groups_info})

    @view_config(route_name="add_group", renderer="templates/add_group.mako")
    def add_group(self):
        return_data = {"invalid_group_name": False, "invalid_description": False, "invalid_terms": False,
                       "reason_group_name": "Invalid", "reason_description": "Invalid", "reason_terms": "Invalid",
                       "form_group_name": "", "form_discoverable": False, "form_description": "", "form_terms": ""}

        if "create" in self.request.POST:
            group_name = self.request.POST.get("group_name")
            description = self.request.POST.get("description")
            discoverable = asbool(self.request.POST.get("discoverable"))
            terms = self.request.POST.get("terms")
            return_data["form_group_name"] = group_name
            return_data["form_description"] = description
            return_data["form_discoverable"] = discoverable
            return_data["form_terms"] = terms
            if not group_name:
                return_data["invalid_group_name"] = True
                return self.add_template_data(return_data)

            data = {
                "group_name": group_name,
                "description": return_data["form_description"],
                "discoverable": return_data["form_discoverable"],
                "terms": return_data["form_terms"],
            }
            resp = request_api(self.request, schemas.GroupsAPI.path, "POST", data=data)
            if resp.status_code == HTTPConflict.code:
                return_data["invalid_group_name"] = True
                return_data["reason_group_name"] = "Conflict"
                return self.add_template_data(return_data)
            if resp.status_code == HTTPBadRequest.code:
                # attempt to retrieve the API more-specific reason why the operation is invalid
                body = get_json(resp)
                param_name = body.get("param", {}).get("name")
                reason = body.get("detail", "Invalid")
                if param_name == "group_name":
                    return_data["invalid_group_name"] = True
                    return_data["reason_group_name"] = reason
                    return self.add_template_data(return_data)
                if param_name == "description":
                    return_data["invalid_description"] = True
                    return_data["reason_description"] = reason
                    return self.add_template_data(return_data)
                if param_name == "terms":
                    return_data["invalid_terms"] = True
                    return_data["reason_terms"] = reason
                    return self.add_template_data(return_data)
            check_response(resp)  # check for any other exception than checked use-cases
            return HTTPFound(self.request.route_url("view_groups"))

        return self.add_template_data(return_data)

    def resource_tree_parser(self, raw_resources_tree, permission):
        resources_tree = {}
        for r_id, resource in raw_resources_tree.items():
            perms = permission.get(r_id, [])
            perm_names = [PermissionSet(perm_json).explicit_permission for perm_json in perms]
            children = self.resource_tree_parser(resource["children"], permission)
            children = OrderedDict(sorted(children.items()))
            resources_tree[resource["resource_name"]] = dict(
                id=r_id,
                permissions=perms,
                permission_names=perm_names,
                resource_type=resource["resource_type"],
                resource_display_name=resource["resource_display_name"],
                children=children
            )
        return resources_tree

    def perm_tree_parser(self, raw_perm_tree):
        permission = {}
        for r_id, resource in raw_perm_tree.items():
            permission[r_id] = resource["permissions"]
            permission.update(self.perm_tree_parser(resource["children"]))
        return permission

    def edit_group_users(self, group_name):
        current_members = self.get_group_users(group_name)
        selected_members = self.request.POST.getall("member")
        removed_members = list(set(current_members) - set(selected_members))
        new_members = list(set(selected_members) - set(current_members))

        for user_name in removed_members:
            path = schemas.UserGroupAPI.path.format(user_name=user_name, group_name=group_name)
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)

        report_info = {"edit_new_membership_success": set(),
                       "edit_new_membership_error": set()}
        for user_name in new_members:
            try:
                path = schemas.UserGroupsAPI.path.format(user_name=user_name)
                data = {"group_name": group_name}
                resp = request_api(self.request, path, "POST", data=data)
                check_response(resp)
            except HTTPException as exc:
                detail = "{} ({}), {!s}".format(type(exc).__name__, exc.code, exc)
                LOGGER.error("Unexpected API error under UI operation. [%s]", detail)
                report_info["edit_new_membership_error"].add(user_name)
            else:
                report_info["edit_new_membership_success"].add(user_name)
        return report_info

    def edit_user_or_group_resource_permissions(self, user_or_group_name, is_user=False):
        posted = self.request.POST.dict_of_lists().items()

        # retrieve all selectors that have a value during apply (either added, same or modified)
        # (note: could have N times the resource ID per available permissions for it)
        res_applied_perms = {perm_res_id.replace("permission_resource_", ""): set(permissions) - {""}
                             for perm_res_id, permissions in posted if perm_res_id.startswith("permission_resource")}
        # retrieve all resources that previously had permissions (last apply or when generated page)
        res_with_perms = {res_id.replace("resource_", ""): set(permissions) - {""}
                          for res_id, permissions in posted if res_id.startswith("resource_")}
        res_with_perms.pop("id")  # remove invalid entry used for redirects

        updated_perms = {}
        for res_id, applied in res_applied_perms.items():
            prev_perms = res_with_perms.get(res_id, set())
            removed = prev_perms - applied
            updated = applied - prev_perms
            if not (removed or updated):
                continue
            updated_perms[res_id] = applied
            if is_user:
                res_perms_path = schemas.UserResourcePermissionsAPI.path \
                    .format(user_name=user_or_group_name, resource_id=res_id)
            else:
                res_perms_path = schemas.GroupResourcePermissionsAPI.path \
                    .format(group_name=user_or_group_name, resource_id=res_id)
            for perm in removed:
                data = {"permission": perm}
                resp = request_api(self.request, res_perms_path, "DELETE", data=data)
                check_response(resp)
            for perm in updated:
                data = {"permission": perm}
                resp = request_api(self.request, res_perms_path, "PUT", data=data)
                check_response(resp)

    def get_user_or_group_resources_permissions_dict(self, user_or_group_name, services, service_type,
                                                     is_user=False, is_inherit_groups_permissions=False):
        """
        Get the user or group applied permissions as well as applicable permissions for corresponding services.

        Result is a :class:`tuple` of:
            - combined :term:`Allowed Permissions <Applied Permission>` (*names only*) for services and their children
              :term:`Resources <Resource>`.
            - dictionary of key-service-name, each with recursive map value of children resource details including
              the :term:`Applied Permissions <Applied Permission>` or :term:`Inherited Resources` for the corresponding
              :term:`User` or :term:`Group` accordingly to specified arguments.
        """
        if is_user:
            # because page can only show a single permission (per name/resource) at a time, apply resolution
            # on top of inheritance in order to display the highest priority permission in the tree hierarchy
            query = "inherited=true&resolve=true" if is_inherit_groups_permissions else ""
            path = schemas.UserResourcesAPI.path.format(user_name=user_or_group_name)
        else:
            query = ""
            path = schemas.GroupResourcesAPI.path.format(group_name=user_or_group_name)

        query_type = "type={}".format(service_type)  # try to limit results for faster processing time
        query_sep = "&" if query else ""
        path += "?{}{}{}".format(query, query_sep, query_type)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        body = get_json(resp)

        path = schemas.ServiceTypeAPI.path.format(service_type=service_type)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        resp_available_svc_types = get_json(resp)["services"][service_type]

        # remove possible duplicate permissions from different services
        resources_permission_names = set()
        for svc in resp_available_svc_types:
            perm_names = {perm["name"] for perm in resp_available_svc_types[svc]["permissions"]}
            resources_permission_names.update(perm_names)
        resources_permission_names = sorted(resources_permission_names)

        resources = OrderedDict()
        for service in sorted(services):
            if not service:
                continue

            permission = OrderedDict()
            try:
                raw_perms = body["resources"][service_type][service]
                permission[raw_perms["resource_id"]] = raw_perms["permissions"]
                permission.update(self.perm_tree_parser(raw_perms["resources"]))
            except KeyError:
                pass

            path = schemas.ServiceResourcesAPI.path.format(service_name=service)
            resp = request_api(self.request, path, "GET")
            check_response(resp)
            raw_resources = get_json(resp)[service]
            perms = permission.get(raw_resources["resource_id"], [])
            perm_names = [PermissionSet(perm_json).explicit_permission for perm_json in perms]
            resources[service] = OrderedDict(
                id=raw_resources["resource_id"],
                resource_type="service",
                permissions=perms,
                permission_names=perm_names,
                children=self.resource_tree_parser(raw_resources["resources"], permission))
        return resources_permission_names, resources

    @view_config(route_name="edit_group", renderer="templates/edit_group.mako")
    def edit_group(self):
        group_name = self.request.matchdict["group_name"]
        cur_svc_type = self.request.matchdict["cur_svc_type"]
        group_info = {"edit_mode": "no_edit", "group_name": group_name, "cur_svc_type": cur_svc_type}
        error_message = ""
        edit_grp_users_info = {}

        # TODO:
        #   Until the api is modified to make it possible to request from the RemoteResource table,
        #   we have to access the database directly here
        session = self.request.db

        # when service type is 'default', this function replaces 'cur_svc_type' with the first one available
        svc_types, cur_svc_type, services = self.get_services(cur_svc_type)

        # move to service or edit requested group/permission changes
        if self.request.method == "POST":
            is_edit_group_members = False
            res_id = self.request.POST.get("resource_id")

            if "delete" in self.request.POST:
                self.delete_group(group_name)
                return HTTPFound(self.request.route_url("view_groups"))

            if "goto_service" in self.request.POST:
                return self.goto_service(res_id)

            if "edit_group_name" in self.request.POST:
                group_info["edit_mode"] = "edit_group_name"
            elif "save_group_name" in self.request.POST:
                group_info["group_name"] = self.request.POST.get("new_group_name")
                group_info = self.update_group_info(group_name, group_info)
                # return immediately with updated URL to group with new name (reprocess this template from scratch)
                return HTTPFound(self.request.route_url("edit_group", **group_info))

            if "edit_description" in self.request.POST:
                group_info["edit_mode"] = "edit_description"
            elif "save_description" in self.request.POST:
                group_info["description"] = self.request.POST.get("new_description")
                group_info.update(self.update_group_info(group_name, group_info))
            elif "clean_resource" in self.request.POST:
                # "clean_resource" must be above "edit_permissions" because they"re in the same form.
                self.delete_resource(res_id)
            elif "is_discoverable" in self.request.POST:
                group_info["discoverable"] = not asbool(self.request.POST.get("is_discoverable"))
                group_info.update(self.update_group_info(group_name, group_info))
            elif "edit_permissions" in self.request.POST:
                # FIXME:
                #   Add remote does not make sense anymore because we batch update resources (instead of one-by-one).
                #   Also not necessary because recursive permission don't require to actually have the sub-resources.
                #   If resources are needed to apply permissions on them, they are either added manually or via sync.
                # if not res_id or res_id == "None":
                #     remote_id = int(self.request.POST.get("remote_id"))
                #     services_names = [s["service_name"] for s in services.values()]
                #     res_id = self.add_remote_resource(cur_svc_type, services_names, group_name,
                #                                       remote_id, is_user=False)
                self.edit_user_or_group_resource_permissions(group_name, is_user=False)
            elif "edit_group_members" in self.request.POST:
                is_edit_group_members = True
            elif "force_sync" in self.request.POST:
                _, errmsg = self.sync_services(services)
                error_message += errmsg or ""
            elif "clean_all" in self.request.POST:
                ids_to_clean = self.request.POST.get("ids_to_clean").split(";")
                for id_ in ids_to_clean:
                    self.delete_resource(id_)
            elif "no_edit" not in self.request.POST:
                raise HTTPBadRequest(detail="Invalid POST request for group edit.")

            # edits to group members checkboxes
            if is_edit_group_members:
                edit_grp_users_info = self.edit_group_users(group_name)

        # display resources permissions per service type tab
        try:
            res_perm_names, res_perms = self.get_user_or_group_resources_permissions_dict(
                group_name, services, cur_svc_type, is_user=False
            )
        except Exception as exc:
            raise HTTPBadRequest(detail=repr(exc))

        sync_types = [s["service_sync_type"] for s in services.values()]
        sync_implemented = any(s in sync_resources.SYNC_SERVICES_TYPES for s in sync_types)

        info = self.get_remote_resources_info(res_perms, services, session)
        res_perms, ids_to_clean, last_sync_humanized, out_of_sync = info

        if out_of_sync:
            error_message = self.make_sync_error_message(out_of_sync)

        group_info.update(self.get_group_info(group_name))
        group_info["members"] = group_info.pop("user_names")
        group_info["pending_users"] = self.get_group_users(group_name, user_group_status=UserGroupStatus.PENDING)
        group_info["error_message"] = error_message
        group_info["ids_to_clean"] = ";".join(ids_to_clean)
        group_info["last_sync"] = last_sync_humanized
        group_info["sync_implemented"] = sync_implemented
        group_info["out_of_sync"] = out_of_sync
        group_info["users"] = self.get_user_names()
        group_info["svc_types"] = svc_types
        group_info["cur_svc_type"] = cur_svc_type
        group_info["resources"] = res_perms
        group_info["permissions"] = res_perm_names
        group_info["permission_titles"] = [Permission(perm).title for perm in res_perm_names]

        if edit_grp_users_info:
            group_info["edit_membership_pending_success"] = (
                edit_grp_users_info["edit_new_membership_success"] & set(group_info["pending_users"])
            )
            group_info["edit_new_membership_error"] = edit_grp_users_info["edit_new_membership_error"]
        return self.add_template_data(data=group_info)

    @staticmethod
    def make_sync_error_message(service_names):
        this = "this service" if len(service_names) == 1 else "these services"
        error_message = ("There seems to be an issue synchronizing resources from "
                         "{}: {}".format(this, ", ".join(service_names)))
        return error_message

    def sync_services(self, services):
        # type: (Dict[Str, JSON]) -> Tuple[List[Str], Optional[Str]]
        """
        Syncs specified services.

        :returns: names of services that produced a sync error and corresponding sync message (if any).
        """
        errors = []
        session = self.request.db
        for service_info in services.values():
            try:
                sync_resources.fetch_single_service(service_info["resource_id"], session)
                transaction.commit()
            except Exception:  # noqa: W0703 # nosec: B110
                errors.append(service_info["service_name"])
        if errors:
            return errors, self.make_sync_error_message(errors)
        return errors, None

    def get_remote_resources_info(self, res_perms, services, session):
        last_sync_humanized = "Never"
        ids_to_clean, out_of_sync = [], []
        now = datetime.now()

        service_ids = [s["resource_id"] for s in services.values()]
        last_sync_datetimes = list(filter(bool, self.get_last_sync_datetimes(service_ids, session)))

        if any(last_sync_datetimes):
            last_sync_datetime = min(last_sync_datetimes)
            last_sync_humanized = humanize.naturaltime(now - last_sync_datetime)
            res_perms = self.merge_remote_resources(res_perms, services, session)

        for last_sync, service_name in zip(last_sync_datetimes, services):
            if last_sync:
                ids_to_clean += self.get_ids_to_clean(res_perms[service_name]["children"])
                if now - last_sync > OUT_OF_SYNC:
                    out_of_sync.append(service_name)
        return res_perms, ids_to_clean, last_sync_humanized, out_of_sync

    @staticmethod
    def merge_remote_resources(res_perms, services, session):
        merged_resources = {}
        for service_name, service_values in services.items():
            service_id = service_values["resource_id"]
            merge = sync_resources.merge_local_and_remote_resources
            resources_for_service = merge(res_perms, service_values["service_sync_type"], service_id, session)
            merged_resources[service_name] = resources_for_service[service_name]
        return merged_resources

    @staticmethod
    def get_last_sync_datetimes(service_ids, session):
        # type: (List[int], Session) -> List[Optional[datetime]]
        return [sync_resources.get_last_sync(s, session) for s in service_ids]

    def delete_resource(self, res_id):
        try:
            path = schemas.ResourceAPI.path.format(resource_id=res_id)
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)
        except HTTPNotFound:
            # Some resource ids are already deleted because they were a child
            # of another just deleted parent resource.
            # We just skip them.
            pass

    def get_ids_to_clean(self, resources):
        ids = []
        for _, values in resources.items():
            if "matches_remote" in values and not values["matches_remote"]:
                ids.append(values["id"])
            ids += self.get_ids_to_clean(values["children"])
        return ids

    def add_remote_resource(self, service_type, services_names, user_or_group, remote_id, is_user=False):
        try:
            _, res_perms = self.get_user_or_group_resources_permissions_dict(
                user_or_group, services=services_names, service_type=service_type, is_user=is_user
            )
        except Exception as exc:
            raise HTTPBadRequest(detail=repr(exc))

        # get the parent resources for this remote_id
        # TODO:
        #   Until the api is modified to make it possible to request from the RemoteResource table,
        #   we have to access the database directly here
        session = self.request.db
        parents = REMOTE_RESOURCE_TREE_SERVICE.path_upper(remote_id, db_session=session)
        parents = list(reversed(list(parents)))

        parent_id = None
        current_resources = res_perms
        for remote_resource in parents:
            name = remote_resource.resource_name
            if name in current_resources:
                parent_id = int(current_resources[name]["id"])
                current_resources = current_resources[name]["children"]
            else:
                data = {
                    "resource_name": name,
                    "resource_display_name": remote_resource.resource_display_name,
                    "resource_type": remote_resource.resource_type,
                    "parent_id": parent_id,
                }
                resp = request_api(self.request, schemas.ResourcesAPI.path, "POST", data=data)
                check_response(resp)
                parent_id = get_json(resp)["resource"]["resource_id"]

        return parent_id

    @handle_errors
    def get_service_resources(self, service_name):
        resources = {}
        path = schemas.ServiceResourcesAPI.path.format(service_name=service_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        raw_resources = get_json(resp)[service_name]
        resources[service_name] = dict(
            id=raw_resources["resource_id"],
            permissions=[],
            resource_type="service",
            children=self.resource_tree_parser(raw_resources["resources"], {}))
        resources_id_type = self.get_resource_types()
        return resources, resources_id_type

    @view_config(route_name="view_services", renderer="templates/view_services.mako")
    def view_services(self):
        if "delete" in self.request.POST:
            service_name = self.request.POST.get("service_name")
            service_data = {"service_push": self.request.POST.get("service_push")}
            path = schemas.ServiceAPI.path.format(service_name=service_name)
            data = json.dumps(service_data)
            resp = request_api(self.request, path, "DELETE", data=data)
            check_response(resp)

        cur_svc_type = self.request.matchdict["cur_svc_type"]
        svc_types, cur_svc_type, services = self.get_services(cur_svc_type)
        service_names = services.keys()

        success_sync = None
        if "phoenix_push" in self.request.POST:
            if cur_svc_type in register.SERVICES_PHOENIX_ALLOWED:
                success_sync = register.sync_services_phoenix(services, services_as_dicts=True)

        if "edit" in self.request.POST:
            service_name = self.request.POST.get("service_name")
            return HTTPFound(self.request.route_url("edit_service",
                                                    service_name=service_name, cur_svc_type=cur_svc_type))

        data = {
            "cur_svc_type": cur_svc_type,
            "svc_types": svc_types,
            "service_names": service_names,
            "service_push_show": cur_svc_type in register.SERVICES_PHOENIX_ALLOWED,
            "service_push_success": success_sync
        }
        return self.add_template_data(data)

    @view_config(route_name="add_service", renderer="templates/add_service.mako")
    def add_service(self):
        cur_svc_type = self.request.matchdict["cur_svc_type"]
        svc_types, cur_svc_type, _ = self.get_services(cur_svc_type)
        services_keys_sorted = self.get_service_types()
        services_phoenix_enabled = [
            (1 if services_keys_sorted[i] in register.SERVICES_PHOENIX_ALLOWED else 0)
            for i in range(len(services_keys_sorted))
        ]
        # FIXME: retrieve from API
        services_config_enabled = [
            int(SERVICE_TYPE_DICT[svc_type].configurable)
            for svc_type in services_keys_sorted
        ]
        data = {
            "service_name": "",
            "service_url": "",
            "service_config": "",
            "invalid_config": False,
            "cur_svc_type": cur_svc_type,
            "service_types": svc_types,
            "services_phoenix": register.SERVICES_PHOENIX_ALLOWED,
            "services_phoenix_enabled": services_phoenix_enabled,
            "services_config_enabled": services_config_enabled,
        }

        if "register" in self.request.POST:
            service_name = self.request.POST.get("service_name")
            service_url = self.request.POST.get("service_url")
            service_type = self.request.POST.get("service_type")
            service_push = self.request.POST.get("service_push")
            service_config = self.request.POST.get("service_config")
            json_config = None
            if service_type in svc_types and SERVICE_TYPE_DICT[service_type].configurable:
                json_config = None
                if service_config:
                    json_config = is_json_body(service_config, return_body=True)
                    if json_config is None:
                        data.update({
                            # forward any fields to avoid dropping values filled by user
                            "service_name": service_name,
                            "service_type": service_type,
                            "service_url": service_url,
                            "service_config": service_config,
                            "service_push": service_push,
                            "invalid_config": True,
                        })
                        return self.add_template_data(data)

            body = {
                "service_name": service_name,
                "service_url": service_url,
                "service_type": service_type,
                "service_push": service_push,
                "configuration": json_config,
            }
            resp = request_api(self.request, schemas.ServicesAPI.path, "POST", data=body)
            check_response(resp)
            return HTTPFound(self.request.route_url("view_services", cur_svc_type=service_type))

        return self.add_template_data(data)

    @view_config(route_name="edit_service", renderer="templates/edit_service.mako")
    def edit_service(self):
        cur_svc_type = self.request.matchdict["cur_svc_type"]
        service_name = self.request.matchdict["service_name"]
        service_data = self.get_service_data(service_name)
        service_url = service_data["service_url"]
        service_perm = {perm["name"] for perm in service_data["permissions"]}
        service_id = service_data["resource_id"]
        # apply default state if arriving on the page for the first time
        # future editions on the page will transfer the last saved state
        service_push_show = cur_svc_type in register.SERVICES_PHOENIX_ALLOWED
        service_push = asbool(self.request.POST.get("service_push", False))
        service_info = {
            "edit_mode": "no_edit",
            "public_url": register.get_twitcher_protected_service_url(service_name),
            "service_name": service_name,
            "service_url": service_url,
            "service_perm": service_perm,
            "service_id": service_id,
            "service_push": service_push,
            "service_push_show": service_push_show,
            "cur_svc_type": cur_svc_type,
        }  # type: Dict[str, Any]

        svc_config = service_data["configuration"]
        if not svc_config:
            service_info["service_configuration"] = None
            service_info["service_config_json"] = None
            service_info["service_config_yaml"] = None
        else:
            svc_cfg_json = json.dumps(svc_config, ensure_ascii=False, indent=4).strip()
            svc_cfg_yaml = yaml.safe_dump(svc_config, allow_unicode=True, indent=4, sort_keys=False).strip()
            service_info["service_configuration"] = True
            service_info["service_config_json"] = svc_cfg_json
            service_info["service_config_yaml"] = svc_cfg_yaml

        if "edit_name" in self.request.POST:
            service_info["edit_mode"] = "edit_name"

        if "save_name" in self.request.POST:
            new_svc_name = self.request.POST.get("new_svc_name")
            if service_name not in (new_svc_name, ""):
                self.update_service_name(service_name, new_svc_name, service_push)
                service_info["service_name"] = new_svc_name
                service_info["public_url"] = register.get_twitcher_protected_service_url(new_svc_name)
            service_info["edit_mode"] = "no_edit"
            # return directly to "regenerate" the URL with the modified name
            return HTTPFound(self.request.route_url("edit_service", **service_info))

        if "edit_url" in self.request.POST:
            service_info["edit_mode"] = "edit_url"

        if "save_url" in self.request.POST:
            new_svc_url = self.request.POST.get("new_svc_url")
            if service_url not in (new_svc_url, ""):
                self.update_service_url(service_name, new_svc_url, service_push)
                service_info["service_url"] = new_svc_url
            service_info["edit_mode"] = "no_edit"

        if "delete" in self.request.POST:
            service_data = json.dumps({"service_push": service_push})
            path = schemas.ServiceAPI.path.format(service_name=service_name)
            resp = request_api(self.request, path, "DELETE", data=service_data)
            check_response(resp)
            return HTTPFound(self.request.route_url("view_services", **service_info))

        if "delete_child" in self.request.POST:
            resource_id = self.request.POST.get("resource_id")
            path = schemas.ResourceAPI.path.format(resource_id=resource_id)
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)

        if "add_child" in self.request.POST:
            service_info["resource_id"] = self.request.POST.get("resource_id")
            return HTTPFound(self.request.route_url("add_resource", **service_info))

        resources, resources_id_type = self.get_service_resources(service_name)
        path = schemas.ServiceAPI.path.format(service_name=service_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        svc_body = get_json(resp)["service"]

        # TODO: use an API request instead of direct access to `RESOURCE_TYPE_DICT`
        service_info["resources"] = resources
        service_info["resources_id_type"] = resources_id_type
        service_info["resources_no_child"] = [res for res in RESOURCE_TYPE_DICT
                                              if not RESOURCE_TYPE_DICT[res].child_resource_allowed]
        service_info["service_no_child"] = not svc_body["resource_child_allowed"]
        return self.add_template_data(service_info)

    @view_config(route_name="add_resource", renderer="templates/add_resource.mako")
    def add_resource(self):
        cur_svc_type = self.request.matchdict["cur_svc_type"]
        service_name = self.request.matchdict["service_name"]
        resource_id = self.request.matchdict["resource_id"]

        if "add_child" in self.request.POST:
            resource_name = self.request.POST.get("resource_name")
            resource_type = self.request.POST.get("resource_type")

            data = {"resource_name": resource_name,
                    "resource_type": resource_type,
                    "parent_id": int(resource_id) if resource_id else None}
            resp = request_api(self.request, schemas.ResourcesAPI.path, "POST", data=data,
                               headers={"Content-Type": CONTENT_TYPE_JSON})
            check_response(resp)

            return HTTPFound(self.request.route_url("edit_service",
                                                    service_name=service_name,
                                                    cur_svc_type=cur_svc_type))

        path = schemas.ResourceTypesAPI.path.format(resource_id=resource_id)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        svc_res_types = get_json(resp)["children_resource_types"]
        data = {
            "service_name": service_name,
            "cur_svc_type": cur_svc_type,
            "resource_id": resource_id,
            "cur_svc_res": svc_res_types,
        }
        return self.add_template_data(data)
