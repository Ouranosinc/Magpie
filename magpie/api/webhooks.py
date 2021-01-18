import multiprocessing

from pyramid.threadlocal import get_current_registry
import requests
import transaction

from magpie.api.schemas import UserWebhookErrorStatus
from magpie.constants import MAGPIE_INI_FILE_PATH
from magpie.db import get_db_session_from_config_ini
from magpie import models
from magpie.utils import get_logger, get_settings

# List of keys that should be found for a single webhook item in the config
WEBHOOK_KEYS = {
    "name",
    "action",
    "method",
    "url",
    "payload"
}

# List of possible actions associated with a webhook
WEBHOOK_CREATE_USER_ACTION = "create_user"
WEBHOOK_DELETE_USER_ACTION = "delete_user"
WEBHOOK_ACTIONS = [
    WEBHOOK_CREATE_USER_ACTION,
    WEBHOOK_DELETE_USER_ACTION
]

# These are the parameters permitted to use the template form in the webhook payload.
WEBHOOK_TEMPLATE_PARAMS = ["user_name", "tmp_url"]

HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

LOGGER = get_logger(__name__)


def process_webhook_requests(action, params, update_user_status_on_error=False):
    """
    Checks the config for any webhooks that correspond to the input action, and prepares corresponding requests.

    :param action: tag identifying which webhooks to use in the config
    :param params: dictionary containing the required parameters for the request, they will replace templates
                    found in the payload
    :param update_user_status_on_error: update the user status or not in case of a webhook error
    """
    # Check for webhook requests
    webhooks = get_settings(get_current_registry())["webhooks"][action]
    if len(webhooks) > 0:
        # Execute all webhook requests
        pool = multiprocessing.Pool(processes=len(webhooks))
        args = [(webhook, params, update_user_status_on_error) for webhook in webhooks]
        pool.starmap_async(send_webhook_request, args)


def replace_template(param_name, param_value, payload):
    """
    Replace each instances of a template parameter by its corresponding value.

    :param param_name: name of a template parameter
    :param param_value: value of a template parameter
    :param payload: structure containing the data to be processed by the template replacement
    :return: structure containing the data with the replaced template parameters
    """
    if isinstance(payload, dict):
        replace_dict = payload.copy()
        for key, value in payload.items():
            # replace templates in the dictionary value
            replace_dict[key] = replace_template(param_name, param_value, value)

            # replace templates in the dictionary key
            new_key = replace_template(param_name, param_value, key)
            if new_key != key:
                replace_dict[new_key] = replace_dict[key]
                del replace_dict[key]
        return replace_dict
    if isinstance(payload, list):
        return [replace_template(param_name, param_value, value) for value in payload]
    if isinstance(payload, str):
        return payload.replace("{" + param_name + "}", param_value)
    # For any other type, no replacing to do
    return payload


def send_webhook_request(webhook_config, params, update_user_status_on_error=False):
    """
    Sends a single webhook request using the input config.

    :param webhook_config: dictionary containing the config data of a single webhook
    :param params: dictionary containing the required parameters for the request, they will replace templates
                    found in the payload
    :param update_user_status_on_error: update the user status or not in case of a webhook error
    """
    # Replace each instance of template parameters if a corresponding value was defined in input
    try:
        for template_param in WEBHOOK_TEMPLATE_PARAMS:
            if template_param in params:
                webhook_config["payload"] = replace_template(template_param,
                                                             params[template_param],
                                                             webhook_config["payload"])
    except Exception as exception:
        LOGGER.error("An exception has occured while processing the template parameters in a webhook payload : %s",
                     str(exception))
    try:
        resp = requests.request(webhook_config["method"], webhook_config["url"], json=webhook_config["payload"])
        resp.raise_for_status()
    except Exception as exception:
        LOGGER.error("An exception has occured with the webhook request : %s", webhook_config["name"])
        LOGGER.error(str(exception))
        if "user_name" in params.keys() and update_user_status_on_error:
            webhook_update_error_status(params["user_name"])


def webhook_update_error_status(user_name):
    """
    Updates the user's status to indicate an error occured with the webhook requests.
    """
    # find user and change its status to 0 to indicate a webhook error happened
    db_session = get_db_session_from_config_ini(MAGPIE_INI_FILE_PATH)
    user = db_session.query(models.User).filter(models.User.user_name == user_name)  # pylint: disable=E1101,no-member
    user.update({"status": UserWebhookErrorStatus})
    transaction.commit()
