import requests
import transaction

from magpie.constants import MAGPIE_INI_FILE_PATH
from magpie.db import get_db_session_from_config_ini
from magpie import models
from magpie.utils import get_logger

WEBHOOK_KEYS = {
    "name",
    "action",
    "method",
    "url",
    "payload"
}
WEBHOOK_ACTIONS = [
    "create_user",
    "delete_user"
]
HTTP_METHODS = ["GET", "OPTIONS", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

LOGGER = get_logger(__name__)


def webhook_request(webhook_config, params, update_user_status_on_error=False):
    # type: (Dict, Dict, bool) -> None
    """
    Sends a webhook request using the input url.
    """
    # These are the parameters permitted to use the template form in the webhook payload.
    webhook_template_params = ["user_name", "tmp_url"]

    # Replace each instance of template parameters if a corresponding value was defined in input
    for template_param in webhook_template_params:
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
    db_session.query(models.User).filter(models.User.user_name == user_name).update({"status": 0})
    transaction.commit()
