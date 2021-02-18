import multiprocessing

from pyramid.threadlocal import get_current_registry
import requests
import transaction

from magpie.api.schemas import UserWebhookErrorStatus
from magpie.constants import MAGPIE_INI_FILE_PATH
from magpie.db import get_db_session_from_config_ini
from magpie import models
from magpie.utils import get_logger, get_settings, ExtendedEnum

# List of keys that should be found for a single webhook item in the config
WEBHOOK_KEYS = {
    "name",
    "action",
    "method",
    "url",
    "payload"
}

# These are the parameters permitted to use the template form in the webhook payload.
WEBHOOK_TEMPLATE_PARAMS = ["user_name", "tmp_url"]

HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

LOGGER = get_logger(__name__)


class WebhookAction(ExtendedEnum):
    """
    Actions supported by webhooks.
    """
    CREATE_USER = "create_user"
    DELETE_USER = "delete_user"


def process_webhook_requests(action, params, update_user_status_on_error=False):
    """
    Checks the config for any webhooks that correspond to the input action, and prepares corresponding requests.

    :param action: tag identifying which webhooks to use in the config
    :param params: dictionary containing the required parameters for the request, they will replace templates
                    found in the payload
    :param update_user_status_on_error: update the user status or not in case of a webhook error
    """
    # Check for webhook requests
    webhooks = get_settings(get_current_registry())["webhooks"][action.value]
    if len(webhooks) > 0:
        # Execute all webhook requests
        pool = multiprocessing.Pool(processes=len(webhooks))
        args = [(webhook, params, update_user_status_on_error) for webhook in webhooks]
        pool.starmap_async(send_webhook_request, args)


def replace_template(params, payload):
    """
    Replace each template parameter from the payload by its corresponding value.

    :param params: the values of the template parameters
    :param payload: structure containing the data to be processed by the template replacement
    :return: structure containing the data with the replaced template parameters
    """
    if isinstance(payload, dict):
        return {replace_template(params, key): replace_template(params, value)
                for key, value in payload.items()}
    if isinstance(payload, list):
        return [replace_template(params, value) for value in payload]
    if isinstance(payload, str):
        for template_param in WEBHOOK_TEMPLATE_PARAMS:
            if template_param in params:
                payload = payload.replace("{" + template_param + "}", params[template_param])
        return payload
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
    try:
        # Replace template parameters if a corresponding value was defined in input and send the webhook request
        resp = requests.request(webhook_config["method"],
                                replace_template(params, webhook_config["url"]),
                                json=replace_template(params, webhook_config["payload"]))
        resp.raise_for_status()
    except Exception as exception:
        LOGGER.error("An exception has occurred with the webhook request : %s", webhook_config["name"])
        LOGGER.error(str(exception))
        if "user_name" in params.keys() and update_user_status_on_error:
            webhook_update_error_status(params["user_name"])


def webhook_update_error_status(user_name):
    """
    Updates the user's status to indicate an error occurred with the webhook requests.
    """
    # find user and change its status to 0 to indicate a webhook error happened
    db_session = get_db_session_from_config_ini(MAGPIE_INI_FILE_PATH)
    user = db_session.query(models.User).filter(models.User.user_name == user_name)  # pylint: disable=E1101,no-member
    user.update({"status": UserWebhookErrorStatus})
    transaction.commit()
