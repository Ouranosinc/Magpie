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

HTTP_METHODS = ["GET", "OPTIONS", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

LOGGER = get_logger(__name__)


def process_webhook_requests(action, payload, update_user_status_on_error=False):
    """
    Checks the config for any webhooks that correspond to the input action, and prepares corresponding requests
    :param action: tag identifying which webhooks to use in the config
    :param payload: dictionary containing the parameters used for the request
    :param update_user_status_on_error: update the user status or not in case of a webhook error
    """
    # Check for webhook requests
    webhooks = get_settings(get_current_registry())["webhooks"][action]
    if len(webhooks) > 0:
        # Execute all webhook requests
        pool = multiprocessing.Pool(processes=len(webhooks))
        args = [(webhook, payload, update_user_status_on_error) for webhook in webhooks]
        pool.starmap_async(send_webhook_request, args)


def send_webhook_request(webhook_config, params, update_user_status_on_error=False):
    # type: (Dict, Dict, bool) -> None
    """
    Sends a single webhook request using the input config.
    """
    # Replace each instance of template parameters if a corresponding value was defined in input
    for template_param in WEBHOOK_TEMPLATE_PARAMS:
        if template_param in params:
            for k,v in webhook_config["payload"].items():
                webhook_config["payload"][k] = v.replace("{" + template_param + "}", params[template_param])

    try:
        resp = requests.request(webhook_config["method"], webhook_config["url"], data=webhook_config["payload"])
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        LOGGER.error(str(e))
        if "user_name" in params.keys() and update_user_status_on_error:
            webhook_update_error_status(params["user_name"])


def webhook_update_error_status(user_name):
    """
    Updates the user's status to indicate an error occured with the webhook requests
    """
    # find user and change its status to 0 to indicate a webhook error happened
    db_session = get_db_session_from_config_ini(MAGPIE_INI_FILE_PATH)
    db_session.query(models.User).filter(models.User.user_name == user_name).update({"status": UserWebhookErrorStatus})
    transaction.commit()
