#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyramid.request import Request


def add_x_wps_output_context(request):
    # type: (Request) -> Request
    if "application/json" in request.content_type:
        body = request.json
        body["test"] = "added by hook"
    if request.user is not None:
        request.headers["X-WPS-Output-Context"] = "user-" + str(request.user.id)
    return request
