import multiprocessing
from collections import defaultdict
from typing import TYPE_CHECKING

import requests
import transaction
from six.moves.urllib.parse import urlparse

from magpie import models
from magpie.api.schemas import UserStatuses
from magpie.constants import get_constant
from magpie.db import get_db_session_from_config_ini
from magpie.register import get_all_configs
from magpie.utils import CONTENT_TYPE_JSON, FORMAT_TYPE_MAPPING, ExtendedEnum, get_logger, get_settings, raise_log

if TYPE_CHECKING:
    from typing import List, Optional

    from magpie.typedefs import (
        AnySettingsContainer,
        SettingsType,
        Str,
        WebhookConfig,
        WebhookConfigSettings,
        WebhookPayload,
        WebhookTemplateParameters
    )

# List of keys that should be found for a single webhook item in the config
WEBHOOK_KEYS_REQUIRED = {
    "name",
    "action",
    "method",
    "url",
    "payload"
}
WEBHOOK_KEYS_OPTIONAL = {
    "format"
}
WEBHOOK_KEYS = WEBHOOK_KEYS_REQUIRED | WEBHOOK_KEYS_OPTIONAL

# These are *potential* parameters permitted to use the template form in the webhook payload.
# Each parameter transferred to any given webhook are provided distinctively for each case.
WEBHOOK_TEMPLATE_PARAMS = ["user_name", "user_id", "user_email", "user_status", "callback_url"]

WEBHOOK_HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

LOGGER = get_logger(__name__)


class WebhookAction(ExtendedEnum):
    """
    Supported :term:`Webhook` actions.
    """

    CREATE_USER = "create_user"
    """
    Triggered when a new user gets successfully created.
    
    .. seealso:: 
        :ref:`webhook_user_create`
    """

    DELETE_USER = "delete_user"
    """Triggered when an existing user gets successfully deleted.
    
    .. seealso:: 
        :ref:`webhook_user_delete`
    """

    UPDATE_USER_STATUS = "update_user_status"
    """
    Triggered when an existing user status gets successfully updated.
    
    .. seealso:: 
        :ref:`webhook_user_update_status`
    """


def process_webhook_requests(action, params, update_user_status_on_error=False, settings=None):
    # type: (WebhookAction, WebhookTemplateParameters, bool, Optional[AnySettingsContainer]) -> None
    """
    Checks the config for any webhooks that correspond to the input action, and prepares corresponding requests.

    :param action: tag identifying which webhooks to use in the config
    :param params:
        Dictionary containing the required parameters and associated values for the request following the event action.
        Parameters will replace *templates* found in the ``payload`` definition of the webhook.
    :param update_user_status_on_error: update the user status or not in case of a webhook error.
    :param settings: application settings where webhooks configuration can be retrieved.
    """
    # Check for webhook requests
    settings = get_settings(settings, app=True)
    webhooks = settings.get("webhooks", {})  # type: WebhookConfig
    if not webhooks:
        return
    action_webhooks = webhooks[action]
    if len(action_webhooks) > 0:
        # Execute all webhook requests
        pool = multiprocessing.Pool(processes=len(action_webhooks))
        args = [(webhook, params, update_user_status_on_error) for webhook in action_webhooks]
        pool.starmap_async(send_webhook_request, args)


def replace_template(params, payload, force_str=False):
    # type: (WebhookTemplateParameters, WebhookPayload, bool) -> WebhookPayload
    """
    Replace each template parameter from the payload by its corresponding value.

    :param params: the values of the template parameters
    :param payload: structure containing the data to be processed by the template replacement
    :param force_str: enforce string conversion of applicable fields where non-string values are detected.
    :return: structure containing the data with the replaced template parameters
    """
    if isinstance(payload, dict):
        return {replace_template(params, key, force_str=True): replace_template(params, value)
                for key, value in payload.items()}
    if isinstance(payload, list):
        return [replace_template(params, value) for value in payload]
    if isinstance(payload, str):  # template fields are always string since '{<param>}' must be provided
        for template_param in params:
            template_replace = "{{" + template_param + "}}"
            if template_param in WEBHOOK_TEMPLATE_PARAMS and template_replace in payload:
                template_value = params[template_param]
                # if result field is not a string and template is defined as is, allow value type replacement
                if not force_str and not isinstance(template_value, str) and payload == template_replace:
                    payload = template_value
                # otherwise, enforce convert to string to avoid failing string replacement,
                # but remove any additional quotes that might be defined to enforce non-string to string conversion
                else:
                    template_single_string = "'" + template_replace + "'"
                    template_double_string = "\"" + template_replace + "\""
                    for template_str in [template_single_string, template_double_string]:
                        if payload == template_str and not isinstance(template_value, str):
                            template_replace = template_str
                    payload = payload.replace(template_replace, str(template_value))
        return payload
    # For any other type, no replacing to do
    return payload


def send_webhook_request(webhook_config, params, update_user_status_on_error=False):
    # type: (WebhookConfigSettings, WebhookTemplateParameters, bool) -> None
    """
    Sends a single webhook request using the input config.

    :param webhook_config: dictionary containing the config data of a single webhook
    :param params: dictionary containing the required parameters for the request, they will replace templates
                    found in the payload
    :param update_user_status_on_error: update the user status or not in case of a webhook error
    """
    try:
        # Replace template parameters if a corresponding value was defined in input and send the webhook request
        ctype = FORMAT_TYPE_MAPPING.get(webhook_config.get("format", "json"), CONTENT_TYPE_JSON)
        headers = {"Content-Type": ctype}
        data = replace_template(params, webhook_config["payload"])
        data_kw = {"json": data} if ctype == CONTENT_TYPE_JSON else {"data": data}  # json parsing error using 'data'
        resp = requests.request(webhook_config["method"], webhook_config["url"], headers=headers, **data_kw)
        resp.raise_for_status()
    except Exception as exception:
        LOGGER.error("An exception has occurred with the webhook request : %s", webhook_config["name"])
        LOGGER.error(str(exception))
        if "user_name" in params and update_user_status_on_error:
            webhook_update_error_status(params["user_name"])


def webhook_update_error_status(user_name):
    """
    Updates the user's status to indicate an error occurred with the webhook requests.
    """
    # find user and change its status to indicate a webhook error happened
    # NOTE:
    #   It is very important to use database connection and not request here, otherwise we could trigger more webhooks.
    #   This could be problematic as it could potentially create a loop of user create/update/delete back-and-forth
    #   requests between Magpie and the middleware URL subscribed in webhooks.
    db_session = get_db_session_from_config_ini(get_constant("MAGPIE_INI_FILE_PATH"))
    user = db_session.query(models.User).filter(models.User.user_name == user_name)  # pylint: disable=E1101,no-member
    user.update({"status": UserStatuses.WebhookErrorStatus.value})
    transaction.commit()


def setup_webhooks(config_path, settings):
    # type: (Optional[Str], SettingsType) -> None
    """
    Prepares the webhook settings for the application based on definitions retrieved from the configuration file.
    """

    settings["webhooks"] = defaultdict(lambda: [])
    webhooks_conf = settings["webhooks"]  # type: WebhookConfig
    if not config_path:
        LOGGER.info("No configuration file provided to load webhook definitions.")
    else:
        LOGGER.info("Loading provided configuration file to setup webhook definitions.")
        webhook_configs = get_all_configs(config_path, "webhooks", allow_missing=True)

        for cfg in webhook_configs:  # type: List[WebhookConfigSettings]
            for webhook in cfg:
                # Validate the webhook config
                if not isinstance(webhook, dict):
                    raise_log(
                        "Invalid format for webhook definition. Dictionary expected.",
                        exception=ValueError, logger=LOGGER
                    )
                LOGGER.debug("Validating webhook: %s", webhook.get("name", "<undefined-name>"))
                if set(webhook) != WEBHOOK_KEYS_REQUIRED or not all(value for value in webhook.values()):
                    raise_log(
                        "Missing or invalid key/value in webhook config from the config file {}".format(config_path),
                        exception=ValueError, logger=LOGGER
                    )
                if webhook["action"] not in WebhookAction.values():
                    raise_log(
                        "Invalid action {} found in webhook from config file {}".format(webhook["action"], config_path),
                        exception=ValueError, logger=LOGGER
                    )
                if webhook["method"] not in WEBHOOK_HTTP_METHODS:
                    raise_log(
                        "Invalid method {} found in webhook from config file {}".format(webhook["method"], config_path),
                        exception=ValueError, logger=LOGGER
                    )
                url_parsed = urlparse(webhook["url"])
                if not all([url_parsed.scheme, url_parsed.netloc, url_parsed.path]):
                    raise_log(
                        "Invalid URL {} found in webhook from config file {}".format(webhook["url"], config_path),
                        exception=ValueError, logger=LOGGER
                    )

                # Regroup webhooks by action key
                webhook_cfg = {k: webhook[k] for k in WEBHOOK_KEYS if k in webhook}  # noqa # ignore optional fields
                webhook_action = WebhookAction.get(webhook["action"])
                webhooks_conf[webhook_action].append(webhook_cfg)
