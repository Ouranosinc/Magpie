from pyramid.httpexceptions import exception_response


def check_response(response):
    if response.status_code >= 400:
        raise exception_response(response.status_code, body=response.text)
    return response
