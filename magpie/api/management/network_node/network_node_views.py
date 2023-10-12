from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPNotFound,
    HTTPOk,
    HTTPCreated,
    HTTPInternalServerError
)

from pyramid.view import view_config

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.network_node.network_node_utils import create_network_node, delete_network_node
from magpie.constants import get_constant


@s.NetworkNodesAPI.get(tags=[s.NetworkNodeTag], response_schemas=s.NetworkNodes_GET_responses)
@view_config(route_name=s.NetworkNodesAPI.name, request_method="GET")
def get_network_nodes_view(request):
    nodes = [{"name": n.name, "url": n.url} for n in request.db.query(models.NetworkNode).all()]
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNode_GET_OkResponseSchema.description,
                         content={"nodes": nodes})


@s.NetworkNodeAPI.get(tags=[s.NetworkNodeTag], response_schemas=s.NetworkNode_GET_responses)
@view_config(route_name=s.NetworkNodeAPI.name, request_method="GET")
def get_network_node_view(request):
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_GET_NotFoundResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNode_GET_OkResponseSchema.description,
                         content={"name": node.name, "url": node.url})


@s.NetworkNodesAPI.post(schema=s.NetworkNode_POST_RequestBodySchema, tags=[s.NetworkNodeTag],
                        response_schemas=s.NetworkNodes_POST_responses)
@view_config(route_name=s.NetworkNodesAPI.name, request_method="POST")
def create_network_node_view(request):
    node_name = request.POST.get("name")
    node_url = request.POST.get("url")
    ax.verify_param(node_url, matches=True, param_compare=r'[\w-]+', http_error=HTTPBadRequest, param_name="name")
    ax.verify_param(node_url, matches=True, param_compare=ax.URL_REGEX, http_error=HTTPBadRequest, param_name="url")
    ax.evaluate_call(lambda: create_network_node(request, node_name, node_url),
                     http_error=HTTPConflict,
                     msg_on_fail=s.NetworkNodes_POST_ConflictResponseSchema.description)
    return ax.valid_http(http_success=HTTPCreated, detail=s.NetworkNode_GET_OkResponseSchema.description)


@s.NetworkNodeAPI.put(schema=s.NetworkNode_PUT_RequestBodySchema,
                      tags=[s.NetworkNodeTag], response_schemas=s.NetworkNode_PUT_responses)
@view_config(route_name=s.NetworkNodeAPI.name, request_method="PUT")
def update_network_node_view(request):
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_GET_NotFoundResponseSchema.description)
    new_name = request.POST.get("name")
    new_url = request.POST.get("url")
    ax.verify_param(any([new_name, new_url]), is_true=True,
                    http_error=HTTPBadRequest, msg_on_fail=s.BadRequestResponseSchema.description)
    node.name = new_name or node.name
    node.url = new_url or node.url
    ax.evaluate_call(lambda: request.tm.commit(),
                     http_error=HTTPConflict,
                     fallback=lambda: request.db.rollback(),
                     msg_on_fail=s.NetworkNode_PUT_ConflictResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNode_GET_OkResponseSchema.description)


@s.NetworkNodeAPI.delete(tags=[s.NetworkNodeTag], response_schemas=s.NetworkNode_DELETE_responses)
@view_config(route_name=s.NetworkNodeAPI.name, request_method="DELETE")
def delete_network_node_view(request):
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_GET_NotFoundResponseSchema.description)
    ax.evaluate_call(lambda: delete_network_node(request, node),
                     http_error=HTTPInternalServerError,
                     fallback=lambda: request.db.rollback(),
                     msg_on_fail=s.InternalServerErrorResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNode_DELETE_OkResponseSchema.description)
