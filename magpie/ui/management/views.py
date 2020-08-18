import json
from collections import OrderedDict
from datetime import datetime
from typing import TYPE_CHECKING

import humanize
import six
import transaction
from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict, HTTPFound, HTTPMovedPermanently, HTTPNotFound
from pyramid.settings import asbool
from pyramid.view import view_config

from magpie import register
from magpie.api import schemas
from magpie.constants import get_constant
from magpie.cli import sync_resources
from magpie.cli.sync_resources import OUT_OF_SYNC
from magpie.models import REMOTE_RESOURCE_TREE_SERVICE, RESOURCE_TYPE_DICT  # TODO: remove, implement getters via API
from magpie.ui.utils import BaseViews, check_response, error_badrequest, request_api
from magpie.utils import CONTENT_TYPE_JSON, get_json, get_logger

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from sqlalchemy.orm.session import Session
    from magpie.typedefs import List, Optional  # noqa: F401
LOGGER = get_logger(__name__)


class ManagementViews(BaseViews):
    @error_badrequest
    def get_all_groups(self, first_default_group=None):
        resp = request_api(self.request, schemas.GroupsAPI.path, "GET")
        check_response(resp)
        groups = list(get_json(resp)["group_names"])
        if isinstance(first_default_group, six.string_types) and first_default_group in groups:
            groups.remove(first_default_group)
            groups.insert(0, first_default_group)
        return groups

    @error_badrequest
    def get_group_info(self, group_name):
        path = schemas.GroupAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        return get_json(resp)["group"]

    @error_badrequest
    def get_group_users(self, group_name):
        path = schemas.GroupUsersAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        return get_json(resp)["user_names"]

    @error_badrequest
    def update_group_info(self, group_name, group_info):
        path = schemas.GroupAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "PUT", data=group_info)
        check_response(resp)
        return get_json(resp)["group"]

    @error_badrequest
    def get_user_groups(self, user_name):
        path = schemas.UserGroupsAPI.path.format(user_name=user_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        return get_json(resp)["group_names"]

    @error_badrequest
    def get_user_names(self):
        resp = request_api(self.request, schemas.UsersAPI.path, "GET")
        check_response(resp)
        return get_json(resp)["user_names"]

    @error_badrequest
    def get_user_emails(self):
        user_names = self.get_user_names()
        emails = list()
        for user in user_names:
            path = schemas.UserAPI.path.format(user_name=user)
            resp = request_api(self.request, path, "GET")
            check_response(resp)
            user_email = get_json(resp)["user"]["email"]
            emails.append(user_email)
        return emails

    def get_resource_types(self):
        """
        :return: dictionary of all resources as {id: 'resource_type'}
        :rtype: dict
        """
        resp = request_api(self.request, schemas.ResourcesAPI.path, "GET")
        check_response(resp)
        res_dic = self.default_get(get_json(resp), "resources", dict())
        res_ids = dict()
        self.flatten_tree_resource(res_dic, res_ids)
        return res_ids

    @error_badrequest
    def get_services(self, cur_svc_type):
        resp = request_api(self.request, schemas.ServicesAPI.path, "GET")
        check_response(resp)
        all_services = get_json(resp)["services"]
        svc_types = sorted(all_services.keys())
        if cur_svc_type not in svc_types:
            cur_svc_type = svc_types[0]
        services = all_services[cur_svc_type]
        return svc_types, cur_svc_type, services

    @error_badrequest
    def get_service_data(self, service_name):
        path = schemas.ServiceAPI.path.format(service_name=service_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        return get_json(resp)["service"]

    def get_service_types(self):
        svc_types_resp = request_api(self.request, schemas.ServiceTypesAPI.path, "GET")
        return get_json(svc_types_resp)["service_types"]

    @error_badrequest
    def update_service_name(self, old_service_name, new_service_name, service_push):
        svc_data = self.get_service_data(old_service_name)
        svc_data["service_name"] = new_service_name
        svc_data["resource_name"] = new_service_name
        svc_data["service_push"] = service_push
        svc_id = str(svc_data["resource_id"])
        path = schemas.ResourceAPI.path.format(resource_id=svc_id)
        resp = request_api(self.request, path, "PUT", data=svc_data)
        check_response(resp)

    @error_badrequest
    def update_service_url(self, service_name, new_service_url, service_push):
        svc_data = self.get_service_data(service_name)
        svc_data["service_url"] = new_service_url
        svc_data["service_push"] = service_push
        path = schemas.ServiceAPI.path.format(service_name=service_name)
        resp = request_api(self.request, path, "PUT", data=svc_data)
        check_response(resp)

    @error_badrequest
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

    @staticmethod
    def flatten_tree_resource(resource_node, resource_dict):
        """
        :param resource_node: any-level dictionary composing the resources tree
        :param resource_dict: reference of flattened dictionary across levels
        :return: flattened dictionary `resource_dict` of all {id: 'resource_type'}
        :rtype: dict
        """
        if not isinstance(resource_node, dict):
            return
        if not len(resource_node) > 0:
            return
        for res in resource_node.values():
            ManagementViews.flatten_tree_resource(res, resource_dict)
        if "resource_id" in resource_node.keys() and "resource_type" in resource_node.keys():
            resource_dict[resource_node["resource_id"]] = resource_node["resource_type"]

    @view_config(route_name="view_users", renderer="templates/view_users.mako")
    def view_users(self):
        if "delete" in self.request.POST:
            user_name = self.request.POST.get("user_name")
            path = schemas.UserAPI.path.format(user_name=user_name)
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)

        if "edit" in self.request.POST:
            user_name = self.request.POST.get("user_name")
            return HTTPFound(self.request.route_url("edit_user", user_name=user_name, cur_svc_type="default"))

        return self.add_template_data({"users": self.get_user_names()})

    @view_config(route_name="add_user", renderer="templates/add_user.mako")
    def add_user(self):
        users_group = get_constant("MAGPIE_USERS_GROUP")
        return_data = {"conflict_group_name": False, "conflict_user_name": False, "conflict_user_email": False,
                       "invalid_user_name": False, "invalid_user_email": False, "invalid_password": False,
                       "mismatch_password": False, "too_long_user_name": False,
                       "form_user_name": "", "form_user_email": "",
                       "user_groups": self.get_all_groups(first_default_group=users_group)}
        check_data = ["conflict_group_name", "conflict_user_name", "conflict_email",
                      "invalid_user_name", "invalid_email", "invalid_password", "mismatch_password"]

        if "create" in self.request.POST:
            groups = self.get_all_groups()
            user_name = self.request.POST.get("user_name")
            group_name = self.request.POST.get("group_name")
            user_email = self.request.POST.get("email")
            password = self.request.POST.get("password")
            confirm = self.request.POST.get("confirm")
            return_data["form_user_name"] = user_name
            return_data["form_user_email"] = user_email

            if group_name not in groups:
                data = {"group_name": group_name}
                resp = request_api(self.request, schemas.GroupsAPI.path, "POST", data=data)
                if resp.status_code == HTTPConflict.code:
                    return_data["conflict_group_name"] = True
            if user_email in self.get_user_emails():
                return_data["conflict_user_email"] = True
            if user_email == "":
                return_data["invalid_user_email"] = True
            if len(user_name) > get_constant("MAGPIE_USER_NAME_MAX_LENGTH"):
                return_data["too_long_user_name"] = True
            if user_name in self.get_user_names():
                return_data["conflict_user_name"] = True
            if user_name == "":
                return_data["invalid_user_name"] = True
            if password is None or isinstance(password, six.string_types) and len(password) < 1:
                return_data["invalid_password"] = True
            elif password != confirm:
                return_data["mismatch_password"] = True

            for check_fail in check_data:
                if return_data.get(check_fail, False):
                    return self.add_template_data(return_data)

            data = {"user_name": user_name,
                    "email": user_email,
                    "password": password,
                    "group_name": group_name}
            resp = request_api(self.request, schemas.UsersAPI.path, "POST", data=data)
            check_response(resp)
            return HTTPFound(self.request.route_url("view_users"))

        return self.add_template_data(return_data)

    @view_config(route_name="edit_user", renderer="templates/edit_user.mako")
    def edit_user(self):
        user_name = self.request.matchdict["user_name"]
        cur_svc_type = self.request.matchdict["cur_svc_type"]
        inherit_grp_perms = self.request.matchdict.get("inherit_groups_permissions", False)

        own_groups = self.get_user_groups(user_name)
        all_groups = self.get_all_groups(first_default_group=get_constant("MAGPIE_USERS_GROUP"))

        # TODO:
        #   Until the api is modified to make it possible to request from the RemoteResource table,
        #   we have to access the database directly here
        session = self.request.db

        try:
            # The service type is "default". This function replaces cur_svc_type with the first service type.
            svc_types, cur_svc_type, services = self.get_services(cur_svc_type)
        except Exception as exc:
            raise HTTPBadRequest(detail=repr(exc))

        user_path = schemas.UserAPI.path.format(user_name=user_name)
        user_resp = request_api(self.request, user_path, "GET")
        check_response(user_resp)
        user_info = get_json(user_resp)["user"]
        user_info["edit_mode"] = "no_edit"
        user_info["own_groups"] = own_groups
        user_info["groups"] = all_groups
        user_info["inherit_groups_permissions"] = inherit_grp_perms
        error_message = ""

        # In case of update, changes are not reflected when calling
        # get_user_or_group_resources_permissions_dict so we must take care
        # of them
        res_id = None
        removed_perms = None
        new_perms = None

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
            elif "edit_permissions" in self.request.POST:
                if not res_id or res_id == "None":
                    remote_id = int(self.request.POST.get("remote_id"))
                    services_names = [s["service_name"] for s in services.values()]
                    res_id = self.add_remote_resource(cur_svc_type, services_names, user_name, remote_id, is_user=True)

                removed_perms, new_perms = \
                    self.edit_user_or_group_resource_permissions(user_name, res_id, is_user=True)
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
                errors = []
                for service_info in services.values():
                    try:
                        sync_resources.fetch_single_service(service_info["resource_id"], session)
                        transaction.commit()
                    except Exception:  # noqa
                        errors.append(service_info["service_name"])
                if errors:
                    error_message += self.make_sync_error_message(errors)
            elif "clean_all" in self.request.POST:
                ids_to_clean = self.request.POST.get("ids_to_clean").split(";")
                for id_ in ids_to_clean:
                    self.delete_resource(id_)

            if is_save_user_info:
                resp = request_api(self.request, user_path, "PUT", data=user_info)
                check_response(resp)
                # need to commit updates since we are using the same session
                # otherwise, updated user doesn't exist yet in the db for next calls
                self.request.tm.commit()

            # always remove password from output
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
                removed_groups = list(set(own_groups) - set(selected_groups))
                new_groups = list(set(selected_groups) - set(own_groups))
                for group in removed_groups:
                    path = schemas.UserGroupAPI.path.format(user_name=user_name, group_name=group)
                    resp = request_api(self.request, path, "DELETE")
                    check_response(resp)
                for group in new_groups:
                    path = schemas.UserGroupsAPI.path.format(user_name=user_name)
                    data = {"group_name": group}
                    resp = request_api(self.request, path, "POST", data=data)
                    check_response(resp)
                user_info["own_groups"] = self.get_user_groups(user_name)

        # display resources permissions per service type tab
        try:
            res_perm_names, res_perms = self.get_user_or_group_resources_permissions_dict(
                user_name, services, cur_svc_type, is_user=True, is_inherit_groups_permissions=inherit_grp_perms
            )
        except Exception as exc:
            raise HTTPBadRequest(detail=repr(exc))

        if res_id and (removed_perms or new_perms):
            self.update_user_or_group_resources_permissions_dict(res_perms, res_id, removed_perms, new_perms)

        sync_types = [s["service_sync_type"] for s in services.values()]
        sync_implemented = any(s in sync_resources.SYNC_SERVICES_TYPES for s in sync_types)

        info = self.get_remote_resources_info(res_perms, services, session)
        res_perms, ids_to_clean, last_sync_humanized, out_of_sync = info

        if out_of_sync:
            error_message = self.make_sync_error_message(out_of_sync)

        user_info["error_message"] = error_message
        user_info["ids_to_clean"] = ";".join(ids_to_clean)
        user_info["last_sync"] = last_sync_humanized
        user_info["sync_implemented"] = sync_implemented
        user_info["out_of_sync"] = out_of_sync
        user_info["cur_svc_type"] = cur_svc_type
        user_info["svc_types"] = svc_types
        user_info["resources"] = res_perms
        user_info["permissions"] = res_perm_names
        return self.add_template_data(data=user_info)

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
        return_data = {"conflict_group_name": False, "invalid_group_name": False, "form_group_name": ""}

        if "create" in self.request.POST:
            group_name = self.request.POST.get("group_name")
            return_data["form_group_name"] = group_name
            if group_name == "":
                return_data["invalid_group_name"] = True
                return self.add_template_data(return_data)

            data = {"group_name": group_name}
            resp = request_api(self.request, schemas.GroupsAPI.path, "POST", data=data)
            if resp.status_code == HTTPConflict.code:
                return_data["conflict_group_name"] = True
                return self.add_template_data(return_data)

            check_response(resp)  # check for any other exception than conflict
            return HTTPFound(self.request.route_url("view_groups"))

        return self.add_template_data(return_data)

    def resource_tree_parser(self, raw_resources_tree, permission):
        resources_tree = {}
        for r_id, resource in raw_resources_tree.items():
            perm_names = self.default_get(permission, r_id, [])
            children = self.resource_tree_parser(resource["children"], permission)
            children = OrderedDict(sorted(children.items()))
            resources_tree[resource["resource_name"]] = dict(id=r_id,
                                                             permission_names=perm_names,
                                                             resource_display_name=resource["resource_display_name"],
                                                             children=children)
        return resources_tree

    def perm_tree_parser(self, raw_perm_tree):
        permission = {}
        for r_id, resource in raw_perm_tree.items():
            permission[r_id] = resource["permission_names"]
            permission.update(self.perm_tree_parser(resource["children"]))
        return permission

    @staticmethod
    def default_get(dictionary, key, default):
        try:
            return dictionary[key]
        except KeyError:
            return default

    def edit_group_users(self, group_name):
        current_members = self.get_group_users(group_name)
        selected_members = self.request.POST.getall("member")
        removed_members = list(set(current_members) - set(selected_members))
        new_members = list(set(selected_members) - set(current_members))

        for user_name in removed_members:
            path = schemas.UserGroupAPI.path.format(user_name=user_name, group_name=group_name)
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)
        for user_name in new_members:
            path = schemas.UserGroupsAPI.path.format(user_name=user_name)
            data = {"group_name": group_name}
            resp = request_api(self.request, path, "POST", data=data)
            check_response(resp)

    def edit_user_or_group_resource_permissions(self, user_or_group_name, resource_id, is_user=False):
        if is_user:
            res_perms_path = schemas.UserResourcePermissionsAPI.path \
                .format(user_name=user_or_group_name, resource_id=resource_id)
        else:
            res_perms_path = schemas.GroupResourcePermissionsAPI.path \
                .format(group_name=user_or_group_name, resource_id=resource_id)
        try:
            resp = request_api(self.request, res_perms_path, "GET")
            res_perms = get_json(resp)["permission_names"]
        except Exception as exc:
            raise HTTPBadRequest(detail=repr(exc))

        selected_perms = self.request.POST.getall("permission")

        removed_perms = list(set(res_perms) - set(selected_perms))
        new_perms = list(set(selected_perms) - set(res_perms))

        for perm in removed_perms:
            path = "{path}/{perm}".format(path=res_perms_path, perm=perm)
            resp = request_api(self.request, path, "DELETE")
            check_response(resp)
        for perm in new_perms:
            data = {"permission_name": perm}
            resp = request_api(self.request, res_perms_path, "POST", data=data)
            check_response(resp)
        return removed_perms, new_perms

    def get_user_or_group_resources_permissions_dict(self, user_or_group_name, services, service_type,
                                                     is_user=False, is_inherit_groups_permissions=False):
        if is_user:
            query = "?inherit=true" if is_inherit_groups_permissions else ""
            path = schemas.UserResourcesAPI.path.format(user_name=user_or_group_name) + query
        else:
            path = schemas.GroupResourcesAPI.path.format(group_name=user_or_group_name)

        resp_group_perms = request_api(self.request, path, "GET")
        check_response(resp_group_perms)
        resp_group_perms_json = get_json(resp_group_perms)

        path = schemas.ServiceTypeAPI.path.format(service_type=service_type)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        resp_available_svc_types = get_json(resp)["services"][service_type]

        # remove possible duplicate permissions from different services
        resources_permission_names = set()
        for svc in resp_available_svc_types:
            resources_permission_names.update(set(resp_available_svc_types[svc]["permission_names"]))
        # inverse sort so that displayed permissions are sorted, since added from right to left in tree view
        resources_permission_names = sorted(resources_permission_names, reverse=True)

        resources = OrderedDict()
        for service in sorted(services):
            if not service:
                continue

            permission = OrderedDict()
            try:
                raw_perms = resp_group_perms_json["resources"][service_type][service]
                permission[raw_perms["resource_id"]] = raw_perms["permission_names"]
                permission.update(self.perm_tree_parser(raw_perms["resources"]))
            except KeyError:
                pass

            path = schemas.ServiceResourcesAPI.path.format(service_name=service)
            resp = request_api(self.request, path, "GET")
            check_response(resp)
            raw_resources = get_json(resp)[service]
            resources[service] = OrderedDict(
                id=raw_resources["resource_id"],
                permission_names=self.default_get(permission, raw_resources["resource_id"], []),
                children=self.resource_tree_parser(raw_resources["resources"], permission))
        return resources_permission_names, resources

    def update_user_or_group_resources_permissions_dict(self, res_perms, res_id, removed_perms, new_perms):
        for res in res_perms.values():
            if int(res["id"]) == int(res_id):
                res["permission_names"] = sorted(res["permission_names"] + new_perms)
                res["permission_names"] = [perm for perm in res["permission_names"] if perm not in removed_perms]
                return True
            if self.update_user_or_group_resources_permissions_dict(res["children"], res_id, removed_perms, new_perms):
                return True
        return False

    @view_config(route_name="edit_group", renderer="templates/edit_group.mako")
    def edit_group(self):
        group_name = self.request.matchdict["group_name"]
        cur_svc_type = self.request.matchdict["cur_svc_type"]
        group_info = {"edit_mode": "no_edit", "group_name": group_name, "cur_svc_type": cur_svc_type}

        error_message = ""

        # TODO:
        #   Until the api is modified to make it possible to request from the RemoteResource table,
        #   we have to access the database directly here
        session = self.request.db

        try:
            # The service type is 'default'. This function replaces cur_svc_type with the first service type.
            svc_types, cur_svc_type, services = self.get_services(cur_svc_type)
        except Exception as exc:
            raise HTTPBadRequest(detail=repr(exc))

        # In case of update, changes are not reflected when calling
        # get_user_or_group_resources_permissions_dict so we must take care
        # of them
        res_id = None
        removed_perms = None
        new_perms = None

        # move to service or edit requested group/permission changes
        if self.request.method == "POST":
            res_id = self.request.POST.get("resource_id")
            group_path = schemas.GroupAPI.path.format(group_name=group_name)

            if "delete" in self.request.POST:
                resp = request_api(self.request, group_path, "DELETE")
                check_response(resp)
                return HTTPFound(self.request.route_url("view_groups"))

            if "goto_service" in self.request.POST:
                return self.goto_service(res_id)

            if "edit_group_name" in self.request.POST:
                group_info["edit_mode"] = "edit_group_name"
            elif "save_group_name" in self.request.POST:
                group_info["group_name"] = self.request.POST.get("new_group_name")
                resp = request_api(self.request, group_path, "PUT", data=group_info)
                check_response(resp)
                # return immediately with updated URL to group with new name (reprocess this template from scratch)
                return HTTPFound(self.request.route_url("edit_group", **group_info))

            if "edit_description" in self.request.POST:
                group_info["edit_mode"] = "edit_description"
            elif "save_description" in self.request.POST:
                group_info["description"] = self.request.POST.get("new_description")
                resp = request_api(self.request, group_path, "PUT", data=group_info)
                check_response(resp)

            if "clean_resource" in self.request.POST:
                # "clean_resource" must be above "edit_permissions" because they"re in the same form.
                self.delete_resource(res_id)
            elif "edit_discoverable" in self.request.POST:

                self.update_group(group_info)
            elif "edit_permissions" in self.request.POST:
                if not res_id or res_id == "None":
                    remote_id = int(self.request.POST.get("remote_id"))
                    services_names = [s["service_name"] for s in services.values()]
                    res_id = self.add_remote_resource(cur_svc_type, services_names, group_name,
                                                      remote_id, is_user=False)
                removed_perms, new_perms = \
                    self.edit_user_or_group_resource_permissions(group_name, res_id, is_user=False)
            elif "member" in self.request.POST:
                self.edit_group_users(group_name)
            elif "force_sync" in self.request.POST:
                errors = []
                for service_info in services.values():
                    try:
                        sync_resources.fetch_single_service(service_info["resource_id"], session)
                        transaction.commit()
                    except Exception:  # noqa: W0703 # nosec: B110
                        errors.append(service_info["service_name"])
                if errors:
                    error_message += self.make_sync_error_message(errors)

            elif "clean_all" in self.request.POST:
                ids_to_clean = self.request.POST.get("ids_to_clean").split(";")
                for id_ in ids_to_clean:
                    self.delete_resource(id_)
            else:
                return HTTPBadRequest(detail="Invalid POST request.")

        # display resources permissions per service type tab
        try:
            res_perm_names, res_perms = self.get_user_or_group_resources_permissions_dict(
                group_name, services, cur_svc_type, is_user=False
            )
        except Exception as exc:
            raise HTTPBadRequest(detail=repr(exc))

        if res_id and (removed_perms or new_perms):
            self.update_user_or_group_resources_permissions_dict(res_perms, res_id, removed_perms, new_perms)

        sync_types = [s["service_sync_type"] for s in services.values()]
        sync_implemented = any(s in sync_resources.SYNC_SERVICES_TYPES for s in sync_types)

        info = self.get_remote_resources_info(res_perms, services, session)
        res_perms, ids_to_clean, last_sync_humanized, out_of_sync = info

        if out_of_sync:
            error_message = self.make_sync_error_message(out_of_sync)

        group_info.update(self.get_group_info(group_name))
        group_info["members"] = group_info.pop("user_names")
        group_info["error_message"] = error_message
        group_info["ids_to_clean"] = ";".join(ids_to_clean)
        group_info["last_sync"] = last_sync_humanized
        group_info["sync_implemented"] = sync_implemented
        group_info["out_of_sync"] = out_of_sync
        group_info["cur_svc_type"] = cur_svc_type
        group_info["users"] = self.get_user_names()
        group_info["svc_types"] = svc_types
        group_info["cur_svc_type"] = cur_svc_type
        group_info["resources"] = res_perms
        group_info["permissions"] = res_perm_names
        return self.add_template_data(data=group_info)

    @staticmethod
    def make_sync_error_message(service_names):
        this = "this service" if len(service_names) == 1 else "these services"
        error_message = ("There seems to be an issue synchronizing resources from "
                         "{}: {}".format(this, ", ".join(service_names)))
        return error_message

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

    @error_badrequest
    def get_service_resources(self, service_name):
        resources = {}
        path = schemas.ServiceResourcesAPI.path.format(service_name=service_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        raw_resources = get_json(resp)[service_name]
        resources[service_name] = dict(
            id=raw_resources["resource_id"],
            permission_names=[],
            children=self.resource_tree_parser(raw_resources["resources"], {}))
        resources_id_type = self.get_resource_types()
        return resources, resources_id_type

    @view_config(route_name="view_services", renderer="templates/view_services.mako")
    def view_services(self):
        if "delete" in self.request.POST:
            service_name = self.request.POST.get("service_name")
            service_data = {"service_push": self.request.POST.get("service_push")}
            path = schemas.ServiceAPI.path.format(service_name=service_name)
            resp = request_api(self.request, path, "DELETE", data=json.dumps(service_data))
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

        if "register" in self.request.POST:
            service_name = self.request.POST.get("service_name")
            service_url = self.request.POST.get("service_url")
            service_type = self.request.POST.get("service_type")
            service_push = self.request.POST.get("service_push")
            data = {"service_name": service_name,
                    "service_url": service_url,
                    "service_type": service_type,
                    "service_push": service_push}
            resp = request_api(self.request, schemas.ServicesAPI.path, "POST", data=data)
            check_response(resp)
            return HTTPFound(self.request.route_url("view_services", cur_svc_type=service_type))

        services_keys_sorted = self.get_service_types()
        services_phoenix_indices = [(1 if services_keys_sorted[i] in register.SERVICES_PHOENIX_ALLOWED else 0)
                                    for i in range(len(services_keys_sorted))]
        data = {
            "cur_svc_type": cur_svc_type,
            "service_types": svc_types,
            "services_phoenix": register.SERVICES_PHOENIX_ALLOWED,
            "services_phoenix_indices": services_phoenix_indices
        }
        return self.add_template_data(data)

    @view_config(route_name="edit_service", renderer="templates/edit_service.mako")
    def edit_service(self):
        cur_svc_type = self.request.matchdict["cur_svc_type"]
        service_name = self.request.matchdict["service_name"]
        service_data = self.get_service_data(service_name)
        service_url = service_data["service_url"]
        service_perm = service_data["permission_names"]
        service_id = service_data["resource_id"]
        # apply default state if arriving on the page for the first time
        # future editions on the page will transfer the last saved state
        service_push_show = cur_svc_type in register.SERVICES_PHOENIX_ALLOWED
        service_push = asbool(self.request.POST.get("service_push", service_push_show))

        service_info = {"edit_mode": "no_edit", "service_name": service_name, "service_url": service_url,
                        "public_url": register.get_twitcher_protected_service_url(service_name),
                        "service_perm": service_perm, "service_id": service_id, "service_push": service_push,
                        "service_push_show": service_push_show, "cur_svc_type": cur_svc_type}

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

        path = schemas.ServiceTypeResourceTypesAPI.path.format(service_type=cur_svc_type)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        svc_res_types = get_json(resp)["resource_types"]
        data = {
            "service_name": service_name,
            "cur_svc_type": cur_svc_type,
            "resource_id": resource_id,
            "cur_svc_res": svc_res_types,
        }
        return self.add_template_data(data)
