from pyramid.authentication import Authenticated
from pyramid.view import view_config

from magpie.api import schemas
from magpie.typedefs import TYPE_CHECKING
from magpie.ui.utils import BaseViews, check_response, error_badrequest, request_api
from magpie.utils import get_json

if TYPE_CHECKING:
    from magpie.typedefs import JSON, List, Str


class UserViews(BaseViews):
    def add_template_data(self, data=None):
        data = data or {}
        data["MAGPIE_SUB_TITLE"] = "User Management"
        return super(UserViews, self).add_template_data(data)

    @error_badrequest
    def get_current_user_groups(self):
        # type: () -> List[str]
        resp = request_api(self.request, schemas.LoggedUserGroupsAPI.path, "GET")
        check_response(resp)
        return get_json(resp)["group_names"]

    @error_badrequest
    def get_current_user_info(self):
        # type: () -> JSON
        user_resp = request_api(self.request, schemas.LoggedUserAPI.path, "GET")
        check_response(user_resp)
        return get_json(user_resp)["user"]

    @error_badrequest
    def get_discoverable_groups(self):
        # type: () -> List[str]
        resp = request_api(self.request, schemas.RegisterGroupsAPI.path, "GET")
        check_response(resp)
        return get_json(resp)["group_names"]

    @error_badrequest
    def join_discoverable_group(self, group_name):
        """Registers the current user to the discoverable group.

        :raises HTTPBadRequest: if the operation is not valid.
        """
        data = {"group_name": group_name}
        resp = request_api(self.request, schemas.RegisterGroupsAPI.path, "POST", data=data)
        check_response(resp)

    @error_badrequest
    def leave_discoverable_group(self, group_name):
        # type: (Str) -> None
        """Unregisters the current user from the discoverable group.

        :raises HTTPBadRequest: if the operation is not valid.
        """
        path = schemas.RegisterGroupAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "DELETE")
        check_response(resp)

    @view_config(route_name="edit_current_user", renderer="templates/edit_current_user.mako", permission=Authenticated)
    def edit_current_user(self):
        own_groups = self.get_current_user_groups()
        public_groups = self.get_discoverable_groups()
        user_info = self.get_current_user_info()
        user_info[u"edit_mode"] = u"no_edit"
        user_info[u"own_groups"] = own_groups
        user_info[u"groups"] = public_groups
        error_message = ""

        if self.request.method == "POST":
            is_edit_group_membership = False
            is_save_user_info = False

            # FIXME: user unregister itself?
            # if u"delete" in self.request.POST:
            #     resp = request_api(self.request, user_path, "DELETE")
            #    check_response(resp)
            #    return HTTPFound(self.request.route_url("view_users"))

            if u"edit_group_membership" in self.request.POST:
                is_edit_group_membership = True
            elif u"edit_password" in self.request.POST:
                user_info[u"edit_mode"] = u"edit_password"
            elif u"edit_email" in self.request.POST:
                user_info[u"edit_mode"] = u"edit_email"
            elif u"save_password" in self.request.POST:
                user_info[u"password"] = self.request.POST.get(u"new_user_password")
                is_save_user_info = True
            elif u"save_email" in self.request.POST:
                user_info[u"email"] = self.request.POST.get(u"new_user_email")
                is_save_user_info = True

            if is_save_user_info:
                resp = request_api(self.request, schemas.LoggedUserAPI, "PUT", data=user_info)
                check_response(resp)
                # need to commit updates since we are using the same session
                # otherwise, updated user doesn't exist yet in the db for next calls
                self.request.tm.commit()

            # edits to groups checkboxes
            if is_edit_group_membership:
                selected_groups = self.request.POST.getall("member")
                removed_groups = list(set(own_groups) - set(selected_groups))
                new_groups = list(set(selected_groups) - set(own_groups))
                for group in removed_groups:
                    self.leave_discoverable_group(group)
                for group in new_groups:
                    self.join_discoverable_group(group)
                user_info[u"joined_groups"] = self.get_current_user_groups()

        user_info.pop(u"password", None)  # always remove password from output
        user_info[u"error_message"] = error_message
        return self.add_template_data(data=user_info)
