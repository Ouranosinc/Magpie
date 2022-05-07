#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
from typing import TYPE_CHECKING

from six.moves.urllib.parse import urljoin

if TYPE_CHECKING:
    from pyramid.request import Request
    from pyramid.response import Response

    from magpie.typedefs import ServiceHookConfigItem


def add_x_wps_output_context(request):
    # type: (Request) -> Request
    if "application/json" in request.content_type:
        body = request.json  # JSON generated from body, cannot override directly
        body["test"] = "added by hook"
        request.body = json.dumps(body).encode()
    if request.user is not None:
        request.headers["X-WPS-Output-Context"] = "user-" + str(request.user.id)
    return request


def add_x_wps_output_link(response, hook):
    # type: (Response, ServiceHookConfigItem) -> Response
    if "application/json" not in response.content_type or response.status_code != 200:
        return response
    body = response.json
    if body.get("status") != "succeeded":
        return response
    job_out_url = response.request.url + "/outputs"
    wps_out_url = urljoin(response.request.url, "/wps-outputs")
    wps_job_id = hook["path"].rsplit(",", 1)[-1]
    x_wps_output_context = response.request.headers.get("X-WPS-Output-Context")
    if x_wps_output_context:
        wps_out_link = wps_out_url + "/" + x_wps_output_context + "/" + wps_job_id
    else:
        wps_out_link = wps_out_url + "/" + wps_job_id
    response.headers["X-WPS-Output-Link"] = wps_out_link
    return response
