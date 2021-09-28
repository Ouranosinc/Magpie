from typing import TYPE_CHECKING

from pyramid.authentication import Authenticated
from pyramid.httpexceptions import HTTPBadRequest, HTTPFound, HTTPUnprocessableEntity
from pyramid.settings import asbool
from pyramid.view import view_config

from magpie.api import schemas
from magpie.constants import get_constant
from magpie.models import UserGroupStatus
from magpie.ui.utils import BaseViews, check_response, handle_errors, request_api
from magpie.utils import get_json

if TYPE_CHECKING:
    from magpie.typedefs import JSON, List, Str


class UserViews(BaseViews):
    def add_template_data(self, data=None):
        data = data or {}
        data["MAGPIE_SUB_TITLE"] = "User Management"
        return super(UserViews, self).add_template_data(data)

    @handle_errors
    def get_current_user_groups(self, user_group_status=UserGroupStatus.ACTIVE):
        # type: (UserGroupStatus) -> List[str]
        path = schemas.LoggedUserGroupsAPI.path + "?status={}".format(user_group_status.value)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        return get_json(resp)["group_names"]

    @handle_errors
    def get_current_user_info(self):
        # type: () -> JSON
        user_resp = request_api(self.request, schemas.LoggedUserAPI.path, "GET")
        check_response(user_resp)
        return get_json(user_resp)["user"]

    @handle_errors
    def get_discoverable_groups(self):
        # type: () -> List[str]
        resp = request_api(self.request, schemas.RegisterGroupsAPI.path, "GET")
        check_response(resp)
        return get_json(resp)["group_names"]

    @handle_errors
    def join_discoverable_group(self, group_name):
        """
        Registers the current user to the discoverable group.

        :raises HTTPBadRequest: if the operation is not valid.
        """
        path = schemas.RegisterGroupAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "POST", data={})
        check_response(resp)

    @handle_errors
    def leave_discoverable_group(self, group_name):
        # type: (Str) -> None
        """
        Unregisters the current user from the discoverable group.

        :raises HTTPBadRequest: if the operation is not valid.
        """
        path = schemas.RegisterGroupAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "DELETE")
        check_response(resp)

    @view_config(route_name="edit_current_user", renderer="templates/edit_current_user.mako", permission=Authenticated)
    def edit_current_user(self):
        """
        Edit the own fields of the current user profile (self-update information).

        .. seealso::
            - :meth:`magpie.ui.management.views.ManagementViews.edit_user` for corresponding operation by administrator
        """
        joined_groups = self.get_current_user_groups()
        pending_groups = self.get_current_user_groups(user_group_status=UserGroupStatus.PENDING)
        public_groups = self.get_discoverable_groups()
        user_info = self.get_current_user_info()
        user_info["edit_mode"] = "no_edit"
        user_info["joined_groups"] = joined_groups
        user_info["pending_groups"] = pending_groups
        user_info["groups"] = public_groups
        # FIXME: disable email edit when self-registration is enabled to avoid not having any confirmation of new email
        #   (see https://github.com/Ouranosinc/Magpie/issues/436)
        user_info["user_edit_email"] = not asbool(get_constant("MAGPIE_USER_REGISTRATION_ENABLED", self.request,
                                                               default_value=False, print_missing=True,
                                                               raise_missing=False, raise_not_set=False))
        user_info["user_with_error"] = schemas.UserStatuses.get(user_info["status"]) != schemas.UserStatuses.OK
        # reset error messages/flags
        user_info["error_message"] = ""
        for field in ["password", "user_email", "user_name"]:
            user_info["invalid_" + field] = ""
            user_info["reason_" + field] = ""

        if self.request.method == "POST":
            is_edit_group_membership = False
            is_save_user_info = False

            if "edit_group_membership" in self.request.POST:
                is_edit_group_membership = True
            elif "edit_password" in self.request.POST:
                user_info["edit_mode"] = "edit_password"
            elif "edit_email" in self.request.POST:
                user_info["edit_mode"] = "edit_email"
            elif "save_password" in self.request.POST:
                user_info["password"] = self.request.POST.get("new_user_password")
                is_save_user_info = True
            elif "save_email" in self.request.POST:
                user_info["email"] = self.request.POST.get("new_user_email")
                is_save_user_info = True
            elif "delete" in self.request.POST:
                delete_response = request_api(
                    self.request,
                    schemas.UserAPI.path.format(user_name=user_info["user_name"]),
                    "DELETE")
                check_response(delete_response)
                logout_response = request_api(
                    self.request,
                    schemas.SignoutAPI.path,
                    "GET")
                check_response(logout_response)
                return HTTPFound(location="/")

            if is_save_user_info:
                resp = request_api(self.request, schemas.LoggedUserAPI.path, "PATCH", data=user_info)
                if resp.status_code in (HTTPBadRequest.code, HTTPUnprocessableEntity.code):
                    # attempt to retrieve the API specific reason why the operation is invalid
                    body = get_json(resp)
                    param_name = body.get("param", {}).get("name")
                    reason = body.get("detail", "Invalid")
                    user_info.pop("password", None)  # always remove password from output
                    if param_name == "password":
                        user_info["invalid_password"] = True
                        user_info["reason_password"] = reason
                        return self.add_template_data(user_info)
                    if param_name == "user_email":
                        user_info["invalid_user_email"] = True
                        user_info["reason_user_email"] = reason
                        return self.add_template_data(user_info)
                # fail if unknown bad request reason or other error type
                check_response(resp)
                # need to commit updates since we are using the same session
                # otherwise, updated user doesn't exist yet in the db for next calls
                self.request.tm.commit()

            # edits to groups checkboxes
            if is_edit_group_membership:
                selected_groups = self.request.POST.getall("member")
                removed_groups = list(set(joined_groups) - set(selected_groups))
                new_groups = list(set(selected_groups) - set(joined_groups))
                for group in removed_groups:
                    self.leave_discoverable_group(group)
                for group in new_groups:
                    self.join_discoverable_group(group)
                user_info["joined_groups"] = self.get_current_user_groups()
                user_info["pending_groups"] = self.get_current_user_groups(
                    user_group_status=UserGroupStatus.PENDING)

        user_info.pop("password", None)  # always remove password from output
        return self.add_template_data(data=user_info)
