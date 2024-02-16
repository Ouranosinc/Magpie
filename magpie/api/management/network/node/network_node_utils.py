from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict

from magpie import models
from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.api.exception import URL_REGEX
from magpie.cli.register_defaults import register_user_with_group
from magpie.constants import get_constant

if TYPE_CHECKING:
    from pyramid.request import Request

    from magpie.typedefs import Optional, Session, Str

NAME_REGEX = r"^[\w-]+$"


def create_associated_user_groups(new_node, request):
    # type: (models.NetworkNode, Request) -> None
    """
    Creates an associated anonymous user and group for the newly created ``new_node``.

    This will also create the network group (named ``MAGPIE_NETWORK_GROUP_NAME``) if it does not yet exist.
    """
    name = new_node.anonymous_user_name()

    # create an anonymous user and group for this network node
    register_user_with_group(user_name=name,
                             group_name=name,
                             email=get_constant("MAGPIE_NETWORK_ANONYMOUS_EMAIL_FORMAT").format(new_node.name),
                             password=None,  # autogen, value doesn't matter as no login applicable, just make it valid
                             db_session=request.db)

    group = models.GroupService.by_group_name(name, db_session=request.db)
    group.description = "Group for users who have accounts on the networked Magpie instance named '{}'.".format(
        new_node.name)
    group.discoverable = False

    # add the anonymous user to a group for all users in the network (from nodes other than this one).
    register_user_with_group(user_name=name,
                             group_name=get_constant("MAGPIE_NETWORK_GROUP_NAME"),
                             email=get_constant("MAGPIE_NETWORK_ANONYMOUS_EMAIL_FORMAT").format(new_node.name),
                             password=None,
                             db_session=request.db)

    group = models.GroupService.by_group_name(get_constant("MAGPIE_NETWORK_GROUP_NAME"), db_session=request.db)
    group.description = "Group for users who have accounts on a different Magpie instance on this network."
    group.discoverable = False


def update_associated_user_groups(node, old_node_name, request):
    # type: (models.NetworkNode, Str, Request) -> None
    """
    If the ``NetworkNode`` name has changed, update the names of the associated anonymous user and group to match.
    """
    if node.name != old_node_name:
        old_anonymous_name = models.NetworkNode.anonymous_user_name_formatter(old_node_name)
        anonymous_user = request.db.query(models.User).filter(models.User.user_name == old_anonymous_name).one()
        anonymous_group = request.db.query(models.Group).filter(models.Group.group_name == old_anonymous_name).one()
        anonymous_user.user_name = node.anonymous_user_name()
        anonymous_group.group_name = node.anonymous_user_name()


def delete_network_node(request, node):
    # type: (Request, Str) -> None
    """
    Delete a NetworkNode and the associated anonymous user and group.
    """
    request.db.delete(node.anonymous_user(request.db))
    request.db.delete(node.anonymous_group(request.db))
    request.db.delete(node)


def check_network_node_info(db_session=None, name=None, jwks_url=None, token_url=None, authorization_url=None,
                            redirect_uris=None):
    # type: (Optional[Session], Optional[Str], Optional[Str], Optional[Str], Optional[Str], Optional[Str]) -> None
    """
    Check that the parameters used to create a new ``NetworkNode`` or update an existing one are well-formed.
    """
    if name is not None:
        ax.verify_param(name, matches=True, param_name="name", param_compare=NAME_REGEX,
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.NetworkNodes_CheckInfo_NameValue_BadRequestResponseSchema.description)
        ax.verify_param(name, not_in=True, param_name="name",
                        param_compare=[n.name for n in db_session.query(models.NetworkNode)],
                        http_error=HTTPConflict,
                        msg_on_fail=s.NetworkNodes_CheckInfo_NameValue_ConflictResponseSchema.description)
    if jwks_url is not None:
        ax.verify_param(jwks_url, matches=True, param_name="jwks_url", param_compare=URL_REGEX,
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.NetworkNodes_CheckInfo_JWKSURLValue_BadRequestResponseSchema.description)
    if token_url is not None:
        ax.verify_param(token_url, matches=True, param_name="token_url", param_compare=URL_REGEX,
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.NetworkNodes_CheckInfo_TokenURLValue_BadRequestResponseSchema.description)
    if authorization_url is not None:
        ax.verify_param(authorization_url, matches=True, param_name="authorization_url", param_compare=URL_REGEX,
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.NetworkNodes_CheckInfo_AuthorizationURLValue_BadRequestResponseSchema.description)
    if redirect_uris is not None:
        for uri in redirect_uris:
            ax.verify_param(uri, matches=True, param_name="redirect_uris", param_compare=URL_REGEX,
                            http_error=HTTPBadRequest,
                            msg_on_fail=s.NetworkNodes_CheckInfo_RedirectURIsValue_BadRequestResponseSchema.description)
