from typing import TYPE_CHECKING

from pyramid.authentication import Authenticated
from pyramid.httpexceptions import (
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPOk
)
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.view import view_config

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.group import group_formats as gf
from magpie.api.management.register import register_utils as ru
from magpie.api.management.user import user_utils as uu

if TYPE_CHECKING:
    from pyramid.httpexceptions import HTTPException
    from pyramid.request import Request


# note: optional view config added in includeme according to setting
@s.RegisterUsersAPI.get(schema=s.RegisterUsers_GET_RequestSchema, tags=[s.UsersTag, s.RegisterTag],
                        response_schemas=s.RegisterUsers_GET_responses)
def get_pending_users_view(request):
    """
    List all user names pending registration.
    """
    user_name_list = ax.evaluate_call(lambda: [user.user_name for user in
                                               models.UserSearchService.by_status(models.UserStatuses.Pending,
                                                                                  db_session=request.db)],
                                      fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                      msg_on_fail=s.RegisterUsers_GET_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, content={"registrations": sorted(user_name_list)},
                         detail=s.RegisterUsers_GET_OkResponseSchema.description)


# note: optional view config added in includeme according to setting
@s.RegisterUsersAPI.post(schema=s.RegisterUsers_POST_RequestSchema, tags=[s.UsersTag, s.RegisterTag],
                         response_schemas=s.RegisterUsers_POST_responses)
def create_pending_user_view(request):
    """
    Create a new pending user registration.
    """
    user_name = ar.get_multiformat_body(request, "user_name")
    email = ar.get_multiformat_body(request, "email")
    password = ar.get_multiformat_body(request, "password")
    return ru.register_pending_user(user_name, email, password, request)


@s.RegisterUserAPI.delete(schema=s.RegisterUser_DELETE_RequestSchema, tags=[s.UsersTag, s.RegisterTag],
                          response_schemas=s.RegisterUser_DELETE_responses)
def delete_pending_user_view(request):
    """
    Remove a pending user registration (disapprove account creation).
    """
    user_name = ar.get_user_matchdict_checked()


@s.RegisterGroupsAPI.get(tags=[s.GroupsTag, s.LoggedUserTag, s.RegisterTag],
                         response_schemas=s.RegisterGroups_GET_responses)
@view_config(route_name=s.RegisterGroupsAPI.name, request_method="GET", permission=Authenticated)
def get_discoverable_groups_view(request):
    # type: (Request) -> HTTPException
    """
    List all discoverable groups (publicly available to join).
    """
    public_groups = ru.get_discoverable_groups(request.db)
    public_group_names = ax.evaluate_call(lambda: [grp.group_name for grp in public_groups],
                                          http_error=HTTPInternalServerError,
                                          msg_on_fail=s.InternalServerErrorResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, content={"group_names": public_group_names},
                         detail=s.RegisterGroups_GET_OkResponseSchema.description)


@s.RegisterGroupAPI.get(schema=s.RegisterGroup_GET_RequestSchema,
                        tags=[s.GroupsTag, s.LoggedUserTag, s.RegisterTag],
                        response_schemas=s.RegisterGroup_GET_responses)
@view_config(route_name=s.RegisterGroupAPI.name, request_method="GET", permission=Authenticated)
def get_discoverable_group_info_view(request):
    """
    Obtain the information of a discoverable group.
    """
    group = ar.get_group_matchdict_checked(request)
    public_group = ru.get_discoverable_group_by_name(group.group_name, db_session=request.db)
    group_fmt = gf.format_group(public_group, public_info=True)
    return ax.valid_http(http_success=HTTPOk, content={"group": group_fmt},
                         detail=s.RegisterGroup_GET_OkResponseSchema.description)


@s.RegisterGroupAPI.post(schema=s.RegisterGroup_POST_RequestSchema, tags=[s.GroupsTag, s.LoggedUserTag, s.RegisterTag],
                         response_schemas=s.RegisterGroup_POST_responses)
@view_config(route_name=s.RegisterGroupAPI.name, request_method="POST", permission=Authenticated)
def join_discoverable_group_view(request):
    """
    Assigns membership of the logged user to a publicly discoverable group.
    """
    group = ar.get_group_matchdict_checked(request)
    user = ar.get_logged_user(request)
    group = ru.get_discoverable_group_by_name(group.group_name, db_session=request.db)

    ax.verify_param(user.id, param_compare=[usr.id for usr in group.users], not_in=True, with_param=False,
                    http_error=HTTPConflict, content={"user_name": user.user_name, "group_name": group.group_name},
                    msg_on_fail=s.RegisterGroup_POST_ConflictResponseSchema.description)
    ax.evaluate_call(lambda: request.db.add(models.UserGroup(group_id=group.id, user_id=user.id)),  # noqa
                     fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                     msg_on_fail=s.RegisterGroup_POST_ForbiddenResponseSchema.description,
                     content={"user_name": user.user_name, "group_name": group.group_name})
    return ax.valid_http(http_success=HTTPCreated, detail=s.RegisterGroup_POST_CreatedResponseSchema.description,
                         content={"user_name": user.user_name, "group_name": group.group_name})


@s.RegisterGroupAPI.delete(schema=s.RegisterGroup_DELETE_RequestSchema,
                           tags=[s.GroupsTag, s.LoggedUserTag, s.RegisterTag],
                           response_schemas=s.RegisterGroup_DELETE_responses)
@view_config(route_name=s.RegisterGroupAPI.name, request_method="DELETE", permission=Authenticated)
def leave_discoverable_group_view(request):
    """
    Removes membership of the logged user from a previously joined discoverable group.
    """
    group = ar.get_group_matchdict_checked(request)
    user = ar.get_logged_user(request)
    group = ru.get_discoverable_group_by_name(group.group_name, db_session=request.db)
    uu.delete_user_group(user, group, request.db)
    return ax.valid_http(http_success=HTTPOk, detail=s.RegisterGroup_DELETE_OkResponseSchema.description)


@s.TemporaryUrlAPI.get(schema=s.TemporaryURL_GET_RequestSchema, tags=[s.RegisterTag],
                       response_schemas=s.TemporaryURL_GET_responses)  # note: endpoint public, sub-task can have auth
@view_config(route_name=s.TemporaryUrlAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def handle_temporary_url(request):
    """
    Handles the operation according to the provided temporary URL token.
    """
    str_token = ar.get_value_matchdict_checked(request, key="token", pattern=ax.UUID_REGEX)
    str_token = str_token.split(":")[-1]  # remove optional prefix if any (e.g.: 'urn:uuid:')
    tmp_token = models.TemporaryToken.by_token(str_token, db_session=request.db)
    ax.verify_param(tmp_token, not_none=True,
                    http_error=HTTPNotFound, content={"token": str(str_token)},
                    msg_on_fail=s.TemporaryURL_GET_NotFoundResponseSchema.description)
    ru.handle_temporary_token(tmp_token, request)
    return ax.valid_http(http_success=HTTPOk, detail=s.TemporaryURL_GET_OkResponseSchema.description)
