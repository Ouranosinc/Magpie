import logging
from typing import TYPE_CHECKING

from jsonschema import validators

from magpie.utils import get_logger, print_log
from magpie.services import SERVICE_TYPE_DICT
from magpie.cli.sync_services import SYNC_SERVICES_TYPES

if TYPE_CHECKING:
    from magpie.typedefs import JSON, ServicesConfig

LOGGER = get_logger(__name__)


SERVICE_HOOK_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": ["request", "response"]},
        "path": {"type": "string"},
        "query": {"type": "string", "default": r".*"},
        "method": {"type": "string", "default": "*", "enum": [
            "HEAD", "GET", "POST", "PUT", "PATCH", "DELETE",
            "head", "get", "post", "put", "patch", "delete",
            "*"
        ]},
        "target": {"type": "string", "pattern": r"^\.{0,2}\/?([\w-]+\/)*[A-Za-z_]\w+\.py:[A-Za-z]\w+$"}
    },
    "required": [
        "type",
        "path",
        "target",
    ],
    "additionalProperties": False
}
SERVICE_CONFIG_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "pattern": r"^https?:\/\/.*$"},
        "title": {"type": "string"},
        "type": {"type": "string", "enum": list(SERVICE_TYPE_DICT)},
        "sync_type": {"type": "string", "enum": list(set(SYNC_SERVICES_TYPES) | set(SERVICE_TYPE_DICT))},
        "public": {"type": "boolean", "default": True},
        "c4i": {"type": "boolean", "default": False},
        "configuration": {"type": "object", "additionalProperties": True},
        "hooks": {"type": "array", "items": SERVICE_HOOK_ITEM_SCHEMA}
    },
    "required": [
        "url",
        "type"
    ],
    "additionalProperties": False
}
SERVICES_CONFIGURATION_SCHEMA = {
    "type": "object",
    "additionalProperties": SERVICE_CONFIG_ITEM_SCHEMA
}


def extend_with_default(validator_class):
    """
    Validator that applies inplace defaults in the instance when provided by the schema.
    """
    validate_properties = validator_class.VALIDATORS["properties"]

    def set_defaults(validator, properties, instance, schema):
        for prop, child_schema in properties.items():
            if "default" in child_schema:
                instance.setdefault(prop, child_schema["default"])
        for error in validate_properties(validator, properties, instance, schema):
            yield error

    return validators.extend(validator_class, {"properties": set_defaults})


JsonSchemaDefaultValidator = extend_with_default(validators.Draft7Validator)  # noqa


def validate_services_config(services_configuration):
    # type: (JSON) -> ServicesConfig
    """
    Validate configuration within the ``providers`` section.

    .. seealso::
        :ref:`config_providers` and :ref:`config_file`.

    :param services_configuration: Service definitions loaded from one or more combined configuration files.
    :return: Services configuration with validated schema and applied defaults.
    """
    try:
        JsonSchemaDefaultValidator(SERVICES_CONFIGURATION_SCHEMA).validate(services_configuration)
        return services_configuration
    except Exception as exc:
        print_log("Failed schema validation of services/providers configuration.",
                  level=logging.ERROR, logger=LOGGER, exc_info=exc)
        raise
