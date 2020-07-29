from pyramid.authentication import Authenticated
from pyramid.httpexceptions import (
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPOk,
)
from pyramid.view import view_config
from typing import TYPE_CHECKING

from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.group import group_formats as gf
from magpie.api.management.register import register_utils as ru
from magpie.api.management.user import user_utils as uu
from magpie import models

if TYPE_CHECKING:
    from pyramid.httpexceptions import HTTPException
    from pyramid.request import Request


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


@s.RegisterGroupAPI.get(tags=[s.GroupsTag, s.LoggedUserTag, s.RegisterTag],
                        response_schemas=s.RegisterGroup_GET_responses)
@view_config(route_name=s.RegisterGroupAPI.name, request_method="GET", permission=Authenticated)
def get_discoverable_group_info_view(request):
    """
    Obtain the information of a discoverable group.
    """
    group_name = ar.get_group_matchdict_checked(request)
    public_group = ru.get_discoverable_group_by_name(group_name, db_session=request.db)
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
    group_name = ar.get_group_matchdict_checked(request)
    user = ar.get_logged_user(request)
    group = ru.get_discoverable_group_by_name(group_name, db_session=request.db)

    ax.verify_param(user.id, param_compare=[usr.id for usr in group.users], not_in=True, http_error=HTTPConflict,
                    content={"user_name": user.user_name, "group_name": group.group_name},
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
    group_name = ar.get_group_matchdict_checked(request)
    user = ar.get_logged_user(request)
    group = ru.get_discoverable_group_by_name(group_name, db_session=request.db)
    uu.delete_user_group(user, group, request.db)
    return ax.valid_http(http_success=HTTPOk, detail=s.RegisterGroup_DELETE_OkResponseSchema.description)
