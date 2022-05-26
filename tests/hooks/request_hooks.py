#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
from typing import TYPE_CHECKING

from six.moves.urllib.parse import urljoin

if TYPE_CHECKING:
    from pyramid.request import Request
    from pyramid.response import Response

    from magpie.adapter import HookContext
    from magpie.typedefs import ServiceConfigItem, ServiceHookConfigItem


def add_x_wps_output_context(request, service):
    # type: (Request, ServiceConfigItem) -> Request
    if "application/json" in request.content_type:
        body = request.json  # JSON generated from body, cannot override directly
        # following for testing purposes only
        body["hooks"] = len(service["hooks"])
        body["hook"] = "add_x_wps_output_context"
        request.body = json.dumps(body).encode()
    if request.user is not None:
        request.headers["X-WPS-Output-Context"] = "user-" + str(request.user.id)
    return request


# WARNING:
#   Operation on 'body' or 'json' can only work on non-buffered responses.
#   Otherwise, the content is not *yet* available at this point.
#   If it gets accumulated, this could cause an out-of-memory error if it is too large.
def add_x_wps_output_link(response, hook):
    # type: (Response, ServiceHookConfigItem) -> Response
    if "application/json" not in response.content_type or response.status_code != 200:
        return response
    body = response.json
    if body.get("status") != "succeeded":
        return response
    # following for testing purposes only
    job_out_url = response.request.url + "/outputs"
    wps_out_url = urljoin(response.request.url, "/wps-outputs")
    wps_job_id = response.request.path.rsplit("/", 1)[-1]
    wps_out_ctx = None if not response.request.user else ("user-" + str(response.request.user.id))
    wps_out_link = wps_out_url + ("/" + wps_out_ctx if wps_out_ctx else "") + "/" + wps_job_id
    response.headers["X-WPS-Output-Location"] = wps_out_link
    response.headers["X-WPS-Output-Context"] = wps_out_ctx
    response.headers["X-WPS-Output-Link"] = job_out_url
    response.headers["X-Magpie-Hook-Name"] = "add_x_wps_output_link"
    response.headers["X-Magpie-Hook-Target"] = hook["target"]
    return response


# only to demonstrate that hook/service parameters can be combined however we want
# also, this hook is used in combination with above one in matching condition to test multi-hook chaining
def combined_arguments(response, service, hook, context):
    # type: (Response, ServiceConfigItem, ServiceHookConfigItem, HookContext) -> Response
    for i, svc_hook in enumerate(service["hooks"]):
        if svc_hook == hook:
            response.headers["X-Magpie-Hook-Index"] = str(i)  # string because header requires it
            break
    # below is to validate definitions during testing of hook feature
    assert context
    assert context.request is response.request
    assert context.response is response
    assert context.hook == hook
    assert context.service
    assert context.service.service_type == "api"
    assert context.resource
    assert context.resource.resource_name == "weaver"
    assert context.resource.resource_type == "service"
    return response
