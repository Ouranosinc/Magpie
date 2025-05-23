import json
import platform
import re
from sys import exc_info
from typing import TYPE_CHECKING

import colander
import six
from dicttoxml import dicttoxml
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPError,
    HTTPException,
    HTTPInternalServerError,
    HTTPOk,
    HTTPRedirection,
    HTTPSuccessful
)

from magpie.utils import (
    CONTENT_TYPE_ANY,
    CONTENT_TYPE_APP_XML,
    CONTENT_TYPE_HTML,
    CONTENT_TYPE_JSON,
    CONTENT_TYPE_PLAIN,
    CONTENT_TYPE_TXT_XML,
    SUPPORTED_ACCEPT_TYPES,
    get_header,
    get_logger,
    isclass,
    islambda
)

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Callable, Iterable, List, NoReturn, Optional, Tuple, Type, Union

    from magpie.typedefs import JSON, ParamsType, Str

LOGGER = get_logger(__name__)

# control variables to avoid infinite recursion in case of
# major programming error to avoid application hanging
RAISE_RECURSIVE_SAFEGUARD_MAX = 5
RAISE_RECURSIVE_SAFEGUARD_COUNT = 0

# utility parameter validation regexes for 'matches' argument
PARAM_REGEX = re.compile(r"^[A-Za-z0-9]+(?:[\s_\-\.][A-Za-z0-9]+)*$")    # request parameters
SCOPE_REGEX = re.compile(r"^[A-Za-z0-9]+(?:[\:\s_\-\.][A-Za-z0-9]+)*$")  # allow scoped names (e.g.: 'namespace:value')
EMAIL_REGEX = re.compile(colander.EMAIL_RE)
UUID_REGEX = re.compile(colander.UUID_REGEX)
URL_REGEX = re.compile(colander.URL_REGEX, re.I | re.X)
INDEX_REGEX = re.compile(r"^[0-9]+$")

if platform.python_version() >= "3.7":
    Pattern = re.Pattern
else:
    Pattern = type(re.compile(""))


def verify_param(  # noqa: E126  # pylint: disable=R0913,too-many-arguments
                 # --- verification values ---      # noqa: E126
                 param,                             # type: Any
                 param_compare=None,                # type: Optional[Union[Any, List[Any]]]
                 # --- output options on failure ---
                 param_name=None,                   # type: Optional[Str]
                 param_content=None,                # type: Optional[JSON]
                 with_param=True,                   # type: bool
                 http_error=HTTPBadRequest,         # type: Type[HTTPError]
                 http_kwargs=None,                  # type: Optional[ParamsType]
                 msg_on_fail="",                    # type: Str
                 content=None,                      # type: Optional[JSON]
                 content_type=CONTENT_TYPE_JSON,    # type: Str
                 metadata=None,                     # type: Optional[JSON]
                 # --- verification flags (method) ---
                 not_none=False,                    # type: bool
                 not_empty=False,                   # type: bool
                 not_in=False,                      # type: bool
                 not_equal=False,                   # type: bool
                 is_true=False,                     # type: bool
                 is_false=False,                    # type: bool
                 is_none=False,                     # type: bool
                 is_empty=False,                    # type: bool
                 is_in=False,                       # type: bool
                 is_equal=False,                    # type: bool
                 is_type=False,                     # type: bool
                 matches=False,                     # type: bool
                 ):                                 # type: (...) -> None   # noqa: E123,E126
    # pylint: disable=R0912,R0914
    """
    Evaluate various parameter combinations given the requested verification flags. Given a failing verification,
    directly raises the specified :paramref:`http_error`. Invalid usage exceptions generated by this verification
    process are treated as :class:`HTTPInternalServerError`. Exceptions are generated using the standard output method.

    :param param: parameter value to evaluate
    :param param_compare:
        Other value(s) to test :paramref:`param` against.
        Can be an iterable (single value resolved as iterable unless ``None``).
        To test for ``None`` type, use :paramref:`is_none`/:paramref:`not_none` flags instead.
    :param param_name: name of the tested parameter returned in response if specified for debugging purposes
    :param param_content:
        Additional JSON content to apply to generated error content on raise when :paramref:`with_param` is ``True``.
        Must be JSON serializable. Provided content can override generated error parameter if matching fields.
    :param with_param:
        On raise, adds values of :paramref:`param`, :paramref:`param_name` and :paramref:`param_compare`, as well as
        additional failing conditions metadata to the JSON response body for each of the corresponding value.
    :param http_error: derived exception to raise on test failure (default: :class:`HTTPBadRequest`)
    :param http_kwargs: additional keyword arguments to pass to :paramref:`http_error` called in case of HTTP exception
    :param msg_on_fail: message details to return in HTTP exception if flag condition failed
    :param content: json formatted additional content to provide in case of exception
    :param content_type: format in which to return the exception
        (one of :py:data:`magpie.common.SUPPORTED_ACCEPT_TYPES`)
    :param metadata: request metadata to add to the response body. (see: :func:`magpie.api.requests.get_request_info`)
    :param not_none: test that :paramref:`param` is not ``None`` type
    :param not_empty: test that :paramref:`param` is not an empty iterable (string, list, set, etc.)
    :param not_in: test that :paramref:`param` does not exist in :paramref:`param_compare` values
    :param not_equal: test that :paramref:`param` is not equal to :paramref:`param_compare` value
    :param is_true: test that :paramref:`param` is ``True``
    :param is_false: test that :paramref:`param` is ``False``
    :param is_none: test that :paramref:`param` is ``None`` type
    :param is_empty: test `param` for an empty iterable (string, list, set, etc.)
    :param is_in: test that :paramref:`param` exists in :paramref:`param_compare` values
    :param is_equal: test that :paramref:`param` equals :paramref:`param_compare` value
    :param is_type: test that :paramref:`param` is of same type as specified by :paramref:`param_compare` type
    :param matches: test that :paramref:`param` matches the regex specified by :paramref:`param_compare` value
    :raises HTTPError: if tests fail, specified exception is raised (default: :class:`HTTPBadRequest`)
    :raises HTTPInternalServerError: for evaluation error
    :return: nothing if all tests passed
    """
    content = {} if content is None else content
    needs_compare = is_type or is_in or not_in or is_equal or not_equal or matches
    needs_iterable = is_in or not_in

    # precondition evaluation of input parameters
    try:
        # following TypeError/ValueError are used instead of HTTPError as they would be incorrect setup by the developer
        # after validation of their conditions, we do actual validation of the parameters according to conditions
        if not isinstance(not_none, bool):
            raise TypeError("'not_none' is not a 'bool'")
        if not isinstance(not_empty, bool):
            raise TypeError("'not_empty' is not a 'bool'")
        if not isinstance(not_in, bool):
            raise TypeError("'not_in' is not a 'bool'")
        if not isinstance(not_equal, bool):
            raise TypeError("'not_equal' is not a 'bool'")
        if not isinstance(is_true, bool):
            raise TypeError("'is_true' is not a 'bool'")
        if not isinstance(is_false, bool):
            raise TypeError("'is_false' is not a 'bool'")
        if not isinstance(is_none, bool):
            raise TypeError("'is_none' is not a 'bool'")
        if not isinstance(is_empty, bool):
            raise TypeError("'is_empty' is not a 'bool'")
        if not isinstance(is_in, bool):
            raise TypeError("'is_in' is not a 'bool'")
        if not isinstance(is_equal, bool):
            raise TypeError("'is_equal' is not a 'bool'")
        if not isinstance(is_type, bool):
            raise TypeError("'is_type' is not a 'bool'")
        if not isinstance(matches, bool):
            raise TypeError("'matches' is not a 'bool'")
        # error if none of the flags specified
        if not any([not_none, not_empty, not_in, not_equal,
                    is_none, is_empty, is_in, is_equal, is_true, is_false, is_type, matches]):
            raise ValueError("no comparison flag specified for verification")
        if param_compare is None and needs_compare:
            raise TypeError("'param_compare' cannot be 'None' with specified test flags")
        is_cmp_typ = isinstance(param_compare, type) or (
            isinstance(param_compare, tuple) and param_compare and all(isinstance(_cmp, type) for _cmp in param_compare)
        )
        if is_cmp_typ:  # avoid calling 'in' or '__eq__' implementation that could have trouble with 'other' as str type
            is_str_typ = param_compare in six.string_types or param_compare == six.string_types
        else:
            is_str_typ = False
        if needs_compare and not needs_iterable:
            # allow 'different' string literals for comparison, otherwise types between value/compare must match exactly
            # with 'is_type', comparison must be made directly with compare as type instead of with instance type
            is_str_cmp = isinstance(param, six.string_types)
            ok_str_cmp = isinstance(param_compare, six.string_types)
            eq_typ_cmp = type(param) is type(param_compare)
            is_pattern = matches and isinstance(param_compare, Pattern)
            if is_type and not (is_str_typ or is_cmp_typ):
                LOGGER.debug("[param: %s] invalid type compare with [param_compare: %s]", type(param), param_compare)
                raise TypeError("'param_compare' cannot be of non-type with specified verification flags")
            if matches and not isinstance(param_compare, (six.string_types, Pattern)):
                LOGGER.debug("[param_compare: %s] invalid type is not a regex string or pattern", type(param_compare))
                raise TypeError("'param_compare' for matching verification must be a string or compile regex pattern")
            if not is_type and not ((is_str_cmp and ok_str_cmp) or (not is_str_cmp and eq_typ_cmp) or is_pattern):
                # since 'param' depends on provided input by user, it should be a user-side invalid parameter
                # only exception is if 'param_compare' is not value-based, then developer combined wrong flags
                if is_str_typ or is_cmp_typ:
                    LOGGER.debug("[param: %s] invalid value compare with [param_compare: %s]", param, param_compare)
                    raise TypeError("'param_compare' must be value-based for specified verification flags")
                # when both 'param' and 'param_compare' are values, then the types must match
                # raise immediately since mismatching param types can make following checks fail uncontrollably
                LOGGER.debug("[param: %s] != [param_compare: %s]", type(param), type(param_compare))
                content = apply_param_content(content, param, param_compare, param_name, with_param, param_content,
                                              needs_compare, needs_iterable, is_type, {"is_type": False})
                raise_http(http_error, http_kwargs=http_kwargs, detail=msg_on_fail,
                           content=content, content_type=content_type, metadata=metadata)
        if needs_iterable and (not hasattr(param_compare, "__iter__") or is_str_typ or is_cmp_typ):
            LOGGER.debug("[param_compare: %s]", param_compare)
            raise TypeError("'param_compare' must be an iterable of values for specified verification flags")
    except HTTPException:
        raise
    except Exception as exc:
        content["traceback"] = repr(exc_info())
        content["exception"] = repr(exc)
        raise_http(http_error=HTTPInternalServerError, http_kwargs=http_kwargs,
                   content=content, content_type=content_type, metadata=metadata,
                   detail="Error occurred during parameter verification")

    # passed this point, input condition flags are valid, evaluate requested parameter combinations
    fail_conditions = {}
    fail_verify = False
    if not_none:
        fail_conditions.update({"not_none": param is not None})
        fail_verify = fail_verify or not fail_conditions["not_none"]
    if is_none:
        fail_conditions.update({"is_none": param is None})
        fail_verify = fail_verify or not fail_conditions["is_none"]
    if is_true:
        fail_conditions.update({"is_true": param is True})
        fail_verify = fail_verify or not fail_conditions["is_true"]
    if is_false:
        fail_conditions.update({"is_false": param is False})
        fail_verify = fail_verify or not fail_conditions["is_false"]
    if not_empty:
        fail_conditions.update({"not_empty": hasattr(param, "__len__") and len(param) > 0})
        fail_verify = fail_verify or not fail_conditions["not_empty"]
    if is_empty:
        fail_conditions.update({"is_empty": hasattr(param, "__len__") and len(param) == 0})
        fail_verify = fail_verify or not fail_conditions["is_empty"]
    if not_in:
        fail_conditions.update({"not_in": param not in param_compare})
        fail_verify = fail_verify or not fail_conditions["not_in"]
    if is_in:
        fail_conditions.update({"is_in": param in param_compare})
        fail_verify = fail_verify or not fail_conditions["is_in"]
    if not_equal:
        fail_conditions.update({"not_equal": param != param_compare})
        fail_verify = fail_verify or not fail_conditions["not_equal"]
    if is_equal:
        fail_conditions.update({"is_equal": param == param_compare})
        fail_verify = fail_verify or not fail_conditions["is_equal"]
    if is_type:
        fail_conditions.update({"is_type": isinstance(param, param_compare)})
        fail_verify = fail_verify or not fail_conditions["is_type"]
    if matches:
        param_compare_regex = param_compare
        if isinstance(param_compare, six.string_types):
            param_compare_regex = re.compile(param_compare, re.X)
        fail_conditions.update({"matches": bool(re.match(param_compare_regex, param))})
        fail_verify = fail_verify or not fail_conditions["matches"]
    if fail_verify:
        content = apply_param_content(content, param, param_compare, param_name, with_param, param_content,
                                      needs_compare, needs_iterable, is_type, fail_conditions)
        raise_http(http_error, http_kwargs=http_kwargs, detail=msg_on_fail,
                   content=content, content_type=content_type, metadata=metadata)


def apply_param_content(content,                # type: JSON
                        param,                  # type: Any
                        param_compare,          # type: Any
                        param_name,             # type: Str
                        with_param,             # type: bool
                        param_content,          # type: Optional[JSON]
                        needs_compare,          # type: bool
                        needs_iterable,         # type: bool
                        is_type,                # type: bool
                        fail_conditions,        # type: JSON
                        ):                      # type: (...) -> JSON
    """
    Formats and applies the failing parameter conditions and results to returned JSON content according to flags.

    .. seealso::
        :func:`verify_param`
    """
    if with_param:
        content["param"] = {}
        content["param"]["conditions"] = fail_conditions
        if isinstance(param, six.string_types + (int, float, bool, type(None))):  # type: ignore
            content["param"]["value"] = param
        else:
            content["param"]["value"] = str(param)
        if param_name is not None:
            content["param"]["name"] = str(param_name)
        if needs_compare and param_compare is not None:
            if needs_iterable or is_type:
                param_compare = str if param_compare == six.string_types else param_compare
                param_compare = getattr(param_compare, "__name__", str(param_compare))
                param_compare = "Type[{}]".format(param_compare) if is_type else param_compare
            if isinstance(param_compare, Pattern):
                param_compare = param_compare.pattern
            content["param"]["compare"] = str(param_compare)
        if isinstance(param_content, dict):
            content["param"].update(param_content)
    return content


def evaluate_call(call,                                 # type: Callable[[], Any]
                  fallback=None,                        # type: Optional[Callable[[], None]]
                  http_error=HTTPInternalServerError,   # type: Type[HTTPError]
                  http_kwargs=None,                     # type: Optional[ParamsType]
                  msg_on_fail="",                       # type: Str
                  content=None,                         # type: Optional[JSON]
                  content_type=CONTENT_TYPE_JSON,       # type: Str
                  metadata=None,                        # type: Optional[JSON]
                  ):                                    # type: (...) -> Any
    """
    Evaluates the specified :paramref:`call` with a wrapped HTTP exception handling. On failure, tries to call.

    :paramref:`fallback` if specified, and finally raises the specified :paramref:`http_error`.

    Any potential error generated by :paramref:`fallback` or :paramref:`http_error` themselves are treated as
    :class:`HTTPInternalServerError`.

    Exceptions are generated using the standard output method formatted based on specified :paramref:`content_type`.

    Example:
        normal call::

            try:
                res = func(args)
            except Exception as exc:
                fb_func()
                raise HTTPExcept(exc.message)

        wrapped call::

            res = evaluate_call(lambda: func(args), fallback=lambda: fb_func(), http_error=HTTPExcept, **kwargs)


    :param call: function to call, *MUST* be specified as `lambda: <function_call>`
    :param fallback: function to call (if any) when `call` failed, *MUST* be `lambda: <function_call>`
    :param http_error: alternative exception to raise on `call` failure
    :param http_kwargs: additional keyword arguments to pass to `http_error` if called in case of HTTP exception
    :param msg_on_fail: message details to return in HTTP exception if `call` failed
    :param content: json formatted additional content to provide in case of exception
    :param content_type: format in which to return the exception (one of `magpie.common.SUPPORTED_ACCEPT_TYPES`)
    :param metadata: request metadata to add to the response body. (see: :func:`magpie.api.requests.get_request_info`)
    :raises http_error: on `call` failure
    :raises `HTTPInternalServerError`: on `fallback` failure
    :return: whichever return value `call` might have if no exception occurred
    """
    msg_on_fail = str(msg_on_fail) if isinstance(msg_on_fail, six.string_types) else repr(msg_on_fail)
    content_repr = repr(content) if content is not None else content
    if not islambda(call):
        raise_http(http_error=HTTPInternalServerError, http_kwargs=http_kwargs, metadata=metadata,
                   detail="Input 'call' is not a lambda expression.",
                   content={"call": {"detail": msg_on_fail, "content": content_repr}}, content_type=content_type)

    # preemptively check fallback to avoid possible call exception without valid recovery
    if fallback is not None:
        if not islambda(fallback):
            raise_http(http_error=HTTPInternalServerError, http_kwargs=http_kwargs, metadata=metadata,
                       detail="Input 'fallback'  is not a lambda expression, not attempting 'call'.",
                       content={"call": {"detail": msg_on_fail, "content": content_repr}}, content_type=content_type)
    try:
        return call()
    except Exception as exc:
        exc_call = {"exception": type(exc).__name__, "error": str(exc),
                    "detail": msg_on_fail, "content": content_repr, "type": content_type}
        LOGGER.debug("Exception during call evaluation: %s", exc_call, exc_info=exc)
    try:
        if fallback is not None:
            fallback()
    except Exception as exc:
        exc_fallback = {"exception": type(exc).__name__, "error": str(exc)}
        raise_http(http_error=HTTPInternalServerError, http_kwargs=http_kwargs, metadata=metadata,
                   detail="Exception occurred during 'fallback' called after failing 'call' exception.",
                   content={"call": exc_call, "fallback": exc_fallback}, content_type=content_type)
    raise_http(http_error, detail=msg_on_fail, http_kwargs=http_kwargs, metadata=metadata,
               content={"call": exc_call}, content_type=content_type)


def valid_http(http_success=HTTPOk,             # type: Union[Type[HTTPSuccessful], Type[HTTPRedirection]]
               http_kwargs=None,                # type: Optional[ParamsType]
               detail="",                       # type: Optional[Str]
               content=None,                    # type: Optional[JSON]
               content_type=CONTENT_TYPE_JSON,  # type: Optional[Str]
               metadata=None,                   # type: Optional[JSON]
               ):                               # type: (...) -> Union[HTTPSuccessful, HTTPRedirection]
    """
    Returns successful HTTP with standardized information formatted with content type. (see :func:`raise_http` for HTTP
    error calls)

    :param http_success: any derived class from *valid* HTTP codes (<400) (default: `HTTPOk`)
    :param http_kwargs: additional keyword arguments to pass to `http_success` when called
    :param detail: additional message information (default: empty)
    :param content: json formatted content to include
    :param content_type: format in which to return the exception (one of `magpie.common.SUPPORTED_ACCEPT_TYPES`)
    :param metadata: request metadata to add to the response body. (see: :func:`magpie.api.requests.get_request_info`)
    :returns: formatted successful response with additional details and HTTP code
    """
    global RAISE_RECURSIVE_SAFEGUARD_COUNT  # pylint: disable=W0603

    content = {} if content is None else content
    detail = repr(detail) if not isinstance(detail, six.string_types) else detail
    content_type = CONTENT_TYPE_JSON if content_type == CONTENT_TYPE_ANY else content_type
    http_code, detail, content = validate_params(http_success, [HTTPSuccessful, HTTPRedirection],
                                                 detail, content, content_type)
    json_body = format_content_json_str(http_code, detail, content, content_type)
    resp = generate_response_http_format(http_success, http_kwargs, json_body,
                                         content_type=content_type, metadata=metadata)
    RAISE_RECURSIVE_SAFEGUARD_COUNT = 0  # reset counter for future calls (don't accumulate for different requests)
    return resp  # noqa


def raise_http(http_error=HTTPInternalServerError,  # type: Type[HTTPError]
               http_kwargs=None,                    # type: Optional[ParamsType]
               detail="",                           # type: Str
               content=None,                        # type: Optional[JSON]
               content_type=CONTENT_TYPE_JSON,      # type: Str
               metadata=None,                       # type: Optional[JSON]
               nothrow=False                        # type: bool
               ):                                   # type: (...) -> NoReturn
    """
    Raises error HTTP with standardized information formatted with content type.

    The content contains the corresponding http error code, the provided message as detail and
    optional specified additional json content (kwarg dict).

    .. seealso::
        :func:`valid_http` for HTTP successful calls

    :param http_error: any derived class from base `HTTPError` (default: `HTTPInternalServerError`)
    :param http_kwargs: additional keyword arguments to pass to `http_error` if called in case of HTTP exception
    :param detail: additional message information (default: empty)
    :param content: JSON formatted content to include
    :param content_type: format in which to return the exception (one of `magpie.common.SUPPORTED_ACCEPT_TYPES`)
    :param metadata: request metadata to add to the response body. (see: :func:`magpie.api.requests.get_request_info`)
    :param nothrow: returns the error response instead of raising it automatically, but still handles execution errors
    :raises HTTPError: formatted raised exception with additional details and HTTP code
    :returns: HTTPError formatted exception with additional details and HTTP code only if `nothrow` is `True`
    """

    # fail-fast if recursion generates too many calls
    # this would happen only if a major programming error occurred within this function
    # a global variable is used since raised conditions are not "directly" recursive (they can be included anywhere),
    # and therefore there is no obvious method to "pass down" the recursive count variable between those calls
    global RAISE_RECURSIVE_SAFEGUARD_COUNT  # pylint: disable=W0602,W0603
    RAISE_RECURSIVE_SAFEGUARD_COUNT = RAISE_RECURSIVE_SAFEGUARD_COUNT + 1
    if RAISE_RECURSIVE_SAFEGUARD_COUNT > RAISE_RECURSIVE_SAFEGUARD_MAX:
        raise HTTPInternalServerError(detail="Terminated. Too many recursions of `raise_http`")

    # try dumping content with json format, `HTTPInternalServerError` with caller info if fails.
    # content is added manually to avoid auto-format and suppression of fields by `HTTPException`
    content_type = CONTENT_TYPE_JSON if content_type == CONTENT_TYPE_ANY else content_type
    _, detail, content = validate_params(http_error, HTTPError, detail, content, content_type)
    json_body = format_content_json_str(http_error.code, detail, content, content_type)
    resp = generate_response_http_format(http_error, http_kwargs, json_body,
                                         content_type=content_type, metadata=metadata)

    # reset counter for future calls (don't accumulate for different requests)
    # following raise is the last in the chain since it wasn't triggered by other functions
    RAISE_RECURSIVE_SAFEGUARD_COUNT = 0
    if nothrow:
        return resp
    raise resp


def validate_params(http_class,     # type: Type[HTTPException]
                    http_base,      # type: Union[Type[HTTPException], Iterable[Type[HTTPException]]]
                    detail,         # type: Str
                    content,        # type: Optional[JSON]
                    content_type,   # type: Str
                    ):              # type: (...) -> Tuple[int, Str, JSON]
    """
    Validates parameter types and formats required by :func:`valid_http` and :func:`raise_http`.

    :param http_class: any derived class from base `HTTPException` to verify
    :param http_base: any derived sub-class(es) from base `HTTPException` as minimum requirement for `http_class`
        (ie: 2xx, 4xx, 5xx codes). Can be a single class of an iterable of possible requirements (any).
    :param detail: additional message information (default: empty)
    :param content: json formatted content to include
    :param content_type: format in which to return the exception (one of `magpie.common.SUPPORTED_ACCEPT_TYPES`)
    :raise `HTTPInternalServerError`: if any parameter is of invalid expected format
    :returns http_code, detail, content: parameters with corrected and validated format if applicable
    """
    # verify input arguments, raise `HTTPInternalServerError` with caller info if invalid
    # cannot be done within a try/except because it would always trigger with `raise_http`
    content = {} if content is None else content
    detail = repr(detail) if not isinstance(detail, six.string_types) else detail
    caller = {"content": content, "type": content_type, "detail": detail, "code": 520}  # "unknown" code error
    verify_param(isclass(http_class), param_name="http_class", is_true=True,
                 http_error=HTTPInternalServerError, content_type=CONTENT_TYPE_JSON, content={"caller": caller},
                 msg_on_fail="Object specified is not a class, class derived from `HTTPException` is expected.")
    # if `http_class` derives from `http_base` (ex: `HTTPSuccessful` or `HTTPError`) it is of proper requested type
    # if it derives from `HTTPException`, it *could* be different than base (ex: 2xx instead of 4xx codes)
    # return 'unknown error' (520) if not of lowest level base `HTTPException`, otherwise use the available code
    http_base = tuple(http_base if hasattr(http_base, "__iter__") else [http_base])
    if issubclass(http_class, http_base):
        http_code = http_class.code  # noqa
    elif issubclass(http_class, HTTPException):
        http_code = http_class.code
    else:
        http_code = 520
    caller["code"] = http_code
    verify_param(issubclass(http_class, http_base), param_name="http_base", is_true=True,
                 http_error=HTTPInternalServerError, content_type=CONTENT_TYPE_JSON, content={"caller": caller},
                 msg_on_fail="Invalid 'http_base' derived class specified.")
    verify_param(content_type, param_name="content_type", param_compare=SUPPORTED_ACCEPT_TYPES, is_in=True,
                 http_error=HTTPInternalServerError, content_type=CONTENT_TYPE_JSON, content={"caller": caller},
                 msg_on_fail="Invalid 'content_type' specified for exception output.")
    return http_code, detail, content


def format_content_json_str(http_code, detail, content, content_type):
    # type: (int, Str, JSON, Str) -> Str
    """
    Inserts the code, details, content and type within the body using json format. Includes also any other specified
    json formatted content in the body. Returns the whole json body as a single string for output.

    :raise `HTTPInternalServerError`: if parsing of the json content failed.
    :returns: formatted JSON content as string with added HTTP code and details.
    """
    json_body = ""
    try:
        content["code"] = http_code
        content["detail"] = detail
        content["type"] = content_type
        json_body = json.dumps(content)
    except Exception as exc:  # pylint: disable=W0703
        msg = "Dumping json content '{!s}' resulted in exception '{!r}'.".format(content, exc)
        raise_http(http_error=HTTPInternalServerError, detail=msg,
                   content_type=CONTENT_TYPE_JSON,
                   content={"traceback": repr(exc_info()),
                            "exception": repr(exc),
                            "caller": {"content": repr(content),  # raw string to avoid recursive json.dumps error
                                       "detail": detail,
                                       "code": http_code,
                                       "type": content_type}})
    return json_body


def rewrite_content_type(content, content_type):
    # type: (Union[Str, JSON], Str) -> Tuple[Str, Optional[JSON]]
    """
    Attempts to rewrite the ``type`` field inserted by various functions such as:

        - :func:`format_content_json_str`
        - :func:`raise_http`
        - :func:`valid_http`

    By applying the new value provided by :paramref:`content_type`.

    :returns:
        Content with rewritten "type" (if possible) and converted to string directly insertable to a response body.
        Also provides the converted JSON body if applicable (original content was literal JSON or JSON-like string).
    """
    json_content = None
    if isinstance(content, six.string_types):
        try:
            content = json.loads(content)
            json_content = content
        except (TypeError, json.decoder.JSONDecodeError):
            pass
    if isinstance(content, (list, dict)):
        if "type" in content:
            content["type"] = content_type
        json_content = content
        content = json.dumps(content)
    return content, json_content


def generate_response_http_format(http_class, http_kwargs, content, content_type=CONTENT_TYPE_PLAIN, metadata=None):
    # type: (Type[HTTPException], Optional[ParamsType], JSON, Optional[Str], Optional[JSON]) -> HTTPException
    """
    Formats the HTTP response content according to desired ``content_type`` using provided HTTP code and content.

    :param http_class: `HTTPException` derived class to use for output (code, generic title/explanation, etc.)
    :param http_kwargs: additional keyword arguments to pass to `http_class` when called
    :param content: formatted JSON content or literal string content providing additional details for the response
    :param content_type: one of `magpie.common.SUPPORTED_ACCEPT_TYPES` (default: `magpie.common.CONTENT_TYPE_PLAIN`)
    :param metadata: request metadata to add to the response body. (see: :func:`magpie.api.requests.get_request_info`)
    :return: `http_class` instance with requested information and content type if creation succeeds
    :raises: `HTTPInternalServerError` instance details about requested information and content type if creation fails
    """
    # content body is added manually to avoid auto-format and suppression of fields by `HTTPException`
    content, json_content = rewrite_content_type(content, content_type)
    if isinstance(json_content, dict) and isinstance(metadata, dict):
        # ensure that original JSON content has priority in fields definition over metadata
        # preserve original JSON field ordering, as best as possible
        json_content.update({k: v for k, v in metadata.items() if k not in json_content})
        content, json_content = rewrite_content_type(json_content, content_type)
    content = str(content) if not isinstance(content, six.string_types) else content

    # adjust additional keyword arguments and try building the http response class with them
    http_kwargs = {} if http_kwargs is None else http_kwargs
    http_headers = http_kwargs.get("headers", {})
    # omit content-type and related headers that we override
    for header in dict(http_headers):
        if header.lower().startswith("content-"):
            http_headers.pop(header, None)

    try:
        # Pass down Location if it is provided and should be given as input parameter for this HTTP class.
        # Omitting this step would inject a (possibly extra) empty Location that defaults to the current application.
        # When resolving HTTP redirects, injecting this extra Location when the requested one is not the current
        # application will lead to redirection failures because all locations are appended in the header as CSV list.
        if issubclass(http_class, HTTPRedirection):
            location = get_header("Location", http_headers, pop=True)
            if location and "location" not in http_kwargs:
                http_kwargs["location"] = location

        # directly output json
        if content_type == CONTENT_TYPE_JSON:
            content_type = "{}; charset=UTF-8".format(CONTENT_TYPE_JSON)
            http_response = http_class(body=content, content_type=content_type, **http_kwargs)

        # otherwise json is contained within the html <body> section
        elif content_type == CONTENT_TYPE_HTML:
            if http_class is HTTPOk:
                http_class.explanation = "Operation successful."
            if not http_class.explanation:
                http_class.explanation = http_class.title  # some don't have any defined
            # add preformat <pre> section to output as is within the <body> section
            html_status = "Exception" if http_class.code >= 400 else "Response"
            html_header = "{}<br><h2>{} Details</h2>".format(http_class.explanation, html_status)
            html_template = "<pre style='word-wrap: break-word; white-space: pre-wrap;'>{}</pre>"
            content_type = "{}; charset=UTF-8".format(CONTENT_TYPE_HTML)
            if json_content:
                html_body = html_template.format(json.dumps(json_content, indent=True, ensure_ascii=False))
            else:
                html_body = html_template.format(content)
            html_body = html_header + html_body
            http_response = http_class(body_template=html_body, content_type=content_type, **http_kwargs)

        elif content_type in [CONTENT_TYPE_APP_XML, CONTENT_TYPE_TXT_XML]:
            xml_body = dicttoxml(json_content, custom_root="response")
            http_response = http_class(body=xml_body, content_type=CONTENT_TYPE_TXT_XML, **http_kwargs)

        # default back to plain text
        else:
            http_response = http_class(body=content, content_type=CONTENT_TYPE_PLAIN, **http_kwargs)

        return http_response
    except Exception as exc:  # pylint: disable=W0703
        raise_http(http_error=HTTPInternalServerError, detail="Failed to build HTTP response",
                   content={"traceback": repr(exc_info()), "exception": repr(exc),
                            "caller": {"http_kwargs": repr(http_kwargs),
                                       "http_class": repr(http_class),
                                       "content_type": str(content_type)}})
