import json
import os
from datetime import datetime, timedelta
from itertools import zip_longest
from typing import TYPE_CHECKING

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk
from pyramid.httpexceptions import HTTPBadRequest, HTTPInternalServerError, HTTPNotFound

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.constants import get_constant
from magpie.utils import get_logger

if TYPE_CHECKING:
    from typing import Dict, List, Optional, Tuple

    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
    from pyramid.request import Request

    from magpie.typedefs import JSON, AnySettingsContainer, Str

LOGGER = get_logger(__name__)


def pem_files(settings_container=None):
    # type: (Optional[AnySettingsContainer]) -> List[Str]
    pem_files_ = get_constant("MAGPIE_NETWORK_PEM_FILES", settings_container=settings_container)
    try:
        return json.loads(pem_files_)
    except json.decoder.JSONDecodeError:
        return [pem_files_]


def _pem_file_content(primary=False, settings_container=None):
    # type: (bool, Optional[AnySettingsContainer]) -> List[bytes]
    """
    Return the content of all PEM files
    """

    content = []
    for pem_file in pem_files(settings_container=settings_container):
        with open(pem_file, "rb") as f:
            content.append(f.read())
        if primary:
            break
    return content


def _pem_file_passwords(primary=False, settings_container=None):
    # type: (bool, Optional[AnySettingsContainer]) -> List[Optional[bytes]]
    """
    Return the passwords used to encrypt the PEM files.
    The passwords will be returned in the same order as the file content from `_pem_file_content`.

    If a file is not encrypted with a password, a ``None`` value will be returned in place of the password.

    For example: if there are 4 PEM files and the second and fourth are not encrypted, this will return
    ``["password1", None, "password2"]``
    """
    pem_passwords = get_constant("MAGPIE_NETWORK_PEM_PASSWORDS", settings_container=settings_container,
                                 raise_missing=False, raise_not_set=False)
    try:
        passwords = json.loads(pem_passwords or "")
    except json.decoder.JSONDecodeError:
        passwords = [pem_passwords]
    passwords = [p.encode() if p else None for p in passwords]
    if primary:
        return passwords[:1]
    return passwords


def create_private_key(filename, password=None, settings_container=None):
    # type: (Str, Optional[bytes], Optional[AnySettingsContainer]) -> None
    """
    Create a private key file at the specified filename. Encrypt it using the password if specified.
    If password is None and the filename matches a file in MAGPIE_NETWORK_PEM_FILES, the associated
    password specified in MAGPIE_NETWORK_PEM_PASSWORDS will be used instead.

    .. warning::
        This function should only be used to create a file if MAGPIE_NETWORK_CREATE_MISSING_PEM_FILE is
        truthy. This is not enforced in this function.
    """
    if password is None:
        for pem_file, pem_password in zip_longest(pem_files(settings_container),
                                                  _pem_file_passwords(False, settings_container)):
            if os.path.realpath(pem_file) == os.path.realpath(filename):
                password = pem_password

    LOGGER.info("Creating a valid PEM file at '%s'.", filename)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        encryption_algorithm = serialization.NoEncryption()
    private_bytes = private_key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm)
    with open(filename, mode="wb") as f:
        f.write(private_bytes)


def jwks(primary=False, settings_container=None):
    # type: (bool, Optional[AnySettingsContainer]) -> jwk.JWKSet
    """
    Return a JSON Web Key Set containing all JSON Web Keys loaded from the PEM files listed
    in ``MAGPIE_NETWORK_PEM_FILES``.
    """
    jwks_ = jwk.JWKSet()
    for pem_content, pem_password in zip_longest(_pem_file_content(primary, settings_container),
                                                 _pem_file_passwords(primary, settings_container)):
        jwks_["keys"].add(jwk.JWK.from_pem(pem_content, password=pem_password))
    return jwks_


def _private_keys(primary=False):
    # type: (bool) -> Dict[Str, PrivateKeyTypes]
    """
    Return a dictionary containing key ids and private keys from the PEM files listed in ``MAGPIE_NETWORK_PEM_FILES``.

    If the ``primary`` argument is True, only the primary key will be included in the returned list.
    """
    keys = {}
    for pem_content, pem_password in zip_longest(_pem_file_content(primary), _pem_file_passwords(primary)):
        kid = jwk.JWK.from_pem(pem_content, password=pem_password).export(as_dict=True)["kid"]
        keys[kid] = serialization.load_pem_private_key(pem_content, password=pem_password)
    return keys


def encode_jwt(claims, audience_name, settings_container=None):
    # type: (JSON, Str, Optional[AnySettingsContainer]) -> Str
    """
    Encode claims as a JSON web token.

    Unless overridden by a field in the ``claims`` argument, the ``"iss"`` claim will default to
    `MAGPIE_NETWORK_INSTANCE_NAME`, the ``"exp"`` claim will default to `MAGPIE_NETWORK_INTERNAL_TOKEN_EXPIRY`,
    and the ``"aud"`` claim will default to ``audience_name``. The JWT will be signed with `Magpie`'s primary private
    key (see the `_private_keys` function for details) using the asymmetric RS256 algorithm.
    """
    claims_override = {}
    kid, secret = ax.evaluate_call(lambda: next(iter(_private_keys().items())),
                                   http_error=HTTPInternalServerError,
                                   msg_on_fail="No private key found. Cannot sign JWT.")
    headers = {"kid": kid}
    algorithm = "RS256"
    if "exp" not in claims:
        expiry = int(get_constant("MAGPIE_NETWORK_INTERNAL_TOKEN_EXPIRY", settings_container))
        expiry_time = datetime.utcnow() + timedelta(seconds=expiry)
        claims_override["exp"] = expiry_time
    if "iss" not in claims:
        claims_override["iss"] = get_constant("MAGPIE_NETWORK_INSTANCE_NAME", settings_container)
    if "aud" not in claims:
        claims_override["aud"] = audience_name
    return jwt.encode({**claims, **claims_override}, secret, algorithm=algorithm, headers=headers)


def decode_jwt(token, node, settings_container=None):
    # type: (Str, models.NetworkNode, Optional[AnySettingsContainer]) -> JSON
    """
    Decode a JSON Web Token issued by a node in the network.

    The token must include the ``"exp"``, ``"aud"``,  and ``"iss"`` claims.
    If the issuer is not the same as ``node.name``, or the audience is not this instance (i.e. the same as
    ``MAGPIE_NETWORK_INSTANCE_NAME``), or the token is expired, an error will be raised.
    An error will also be raised if the token cannot be verified with the issuer node's public key.
    """
    jwks_client = jwt.PyJWKClient(node.jwks_url)
    instance_name = get_constant("MAGPIE_NETWORK_INSTANCE_NAME", settings_container)
    key = ax.evaluate_call(lambda: jwks_client.get_signing_key_from_jwt(token),
                           http_error=HTTPInternalServerError,
                           msg_on_fail="No valid public key found. Cannot decode JWT.")
    return ax.evaluate_call(lambda: jwt.decode(token, key.key,
                                               algorithms=["RS256"],
                                               issuer=node.name,
                                               audience=instance_name),
                            http_error=HTTPBadRequest,
                            msg_on_fail="Cannot verify JWT")


def get_network_models_from_request_token(request, create_network_remote_user=False):
    # type: (Request, bool) -> Tuple[models.NetworkNode, Optional[models.NetworkRemoteUser]]
    """
    Return a ``NetworkNode`` and associated ``NetworkRemoteUser`` determined by parsing the claims in the JWT included
    in the ``request`` argument.

    If the ``NetworkRemoteUser`` does not exist and ``create_network_remote_user`` is ``True``, this creates a new
    ``NetworkRemoteUser`` associated with the anonymous user for the given ``NetworkNode`` and adds it to the current
    database transaction.
    """
    token = ar.get_multiformat_body(request, "token", default=None)
    if token is None:
        ax.raise_http(http_error=HTTPBadRequest, detail=s.BadRequestResponseSchema.description)
    node_name = jwt.decode(token, options={"verify_signature": False}).get("iss")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_NotFoundResponseSchema.description)
    decoded_token = decode_jwt(token, node, request)
    user_name = decoded_token.get("user_name")
    network_remote_user = (request.db.query(models.NetworkRemoteUser)
                           .filter(models.NetworkRemoteUser.name == user_name)
                           .filter(models.NetworkRemoteUser.network_node_id == node.id)
                           .first())
    if network_remote_user is None and create_network_remote_user:
        network_remote_user = models.NetworkRemoteUser(network_node=node, name=user_name)
        request.db.add(network_remote_user)
    return node, network_remote_user
