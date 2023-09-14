from typing import TYPE_CHECKING

from magpie import models
from magpie.cli.register_defaults import register_user_with_group
from magpie.constants import get_constant

if TYPE_CHECKING:
    from magpie.typedefs import Str
    from pyramid.request import Request


def create_network_node(request, name, url):
    # type: (Request, Str, Str) -> None
    """
    Create a NetworkNode with the given name and url.
    """
    network_node = models.NetworkNode(name=name, url=url)
    name = network_node.anonymous_user_name

    # create an anonymous user and group for this network node
    register_user_with_group(user_name=name,
                             group_name=name,
                             email=get_constant("MAGPIE_ANONYMOUS_EMAIL"),
                             password=None,  # autogen, value doesn't matter as no login applicable, just make it valid
                             db_session=request.db)

    group = models.GroupService.by_group_name(name, db_session=request.db)
    group.description = "Group for users who have accounts on the networked Magpie instance named '{}'.".format(name)
    group.discoverable = False

    # add the anonymous user to a group for all users in the network (from nodes other than this one).
    register_user_with_group(user_name=name,
                             group_name=get_constant("MAGPIE_NETWORK_GROUP_NAME"),
                             email=get_constant("MAGPIE_ANONYMOUS_EMAIL"),
                             password=None,
                             db_session=request.db)

    group = models.GroupService.by_group_name(get_constant("MAGPIE_NETWORK_GROUP_NAME"), db_session=request.db)
    group.description = "Group for users who have accounts on a different Magpie instance on this network.".format(name)
    group.discoverable = False

    request.tm.commit()


def delete_network_node(request, node):
    # type: (Request, Str) -> None
    """
    Delete a NetworkNode and the associated anonymous user.
    """
    anonymous_user = node.anonymous_user
    if anonymous_user:
        anonymous_user.delete()
    node.delete()
    request.tm.commit()
