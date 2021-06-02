import os
import smtplib
from datetime import datetime
from typing import TYPE_CHECKING

from mako.template import Template
from pyramid.settings import asbool

from magpie.constants import get_constant
from magpie.utils import get_logger, get_magpie_url, get_settings, raise_log

if TYPE_CHECKING:
    from typing import Any, Dict, Optional, Union

    from magpie.typedefs import AnySettingsContainer, SettingsType, Str, TypedDict

    SMTPServerConfiguration = TypedDict("SMTPServerConfiguration", {
        "from": Str, "host": Str, "port": Str, "user": Str, "password": Optional[Str], "sender": Str, "ssl": bool,
    })
    TemplateParameters = Dict[Str, Any]

LOGGER = get_logger(__name__)

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
DEFAULT_TEMPLATE_MAPPING = {
    "MAGPIE_USER_REGISTRATION_SUBMISSION_EMAIL_TEMPLATE":
        os.path.join(TEMPLATE_DIR, "email_user_registration_submission.mako"),
    "MAGPIE_USER_REGISTRATION_APPROVAL_EMAIL_TEMPLATE":
        os.path.join(TEMPLATE_DIR, "email_user_registration_approval.mako"),
    "MAGPIE_USER_REGISTRATION_COMPLETED_EMAIL_TEMPLATE":
        os.path.join(TEMPLATE_DIR, "email_user_registration_completed.mako"),
    "MAGPIE_USER_REGISTRATION_NOTIFY_EMAIL_TEMPLATE":
        os.path.join(TEMPLATE_DIR, "email_user_registration_notify.mako"),
}


def get_email_template(template_constant, container=None):
    # type: (Str, Optional[AnySettingsContainer]) -> Template
    """
    Retrieves the template file with email content matching the custom application setting or the corresponding default.

    Allowed values of :paramref:`template_constant` are:

        - :envvar:`MAGPIE_USER_REGISTRATION_SUBMISSION_EMAIL_TEMPLATE`
        - :envvar:`MAGPIE_USER_REGISTRATION_APPROVAL_EMAIL_TEMPLATE`
        - :envvar:`MAGPIE_USER_REGISTRATION_COMPLETED_EMAIL_TEMPLATE`
        - :envvar:`MAGPIE_USER_REGISTRATION_NOTIFY_EMAIL_TEMPLATE`

    :raises IOError: if an explicit override value of the requested template cannot be located.
    :returns: template formatter from the requested template file.
    """
    if template_constant not in DEFAULT_TEMPLATE_MAPPING:
        raise_log("Specified template is not one of {}".format(list(DEFAULT_TEMPLATE_MAPPING)), ValueError, LOGGER)
    template_file = get_constant(template_constant, container,
                                 default_value=DEFAULT_TEMPLATE_MAPPING[template_constant],
                                 print_missing=False, empty_missing=True, raise_missing=False, raise_not_set=False)
    if not isinstance(template_file, str) or not os.path.isfile(template_file) or not template_file.endswith(".mako"):
        raise_log("Email template [{}] missing or invalid from [{!s}]".format(template_constant, template_file),
                  IOError, logger=LOGGER)
    template = Template(filename=template_file, strict_undefined=True)  # report name of any missing variable reference
    return template


def get_smtp_server_configuration(settings):
    # type: (SettingsType) -> SMTPServerConfiguration
    """
    Obtains and validates all required configuration parameters for SMTP server in order to send an email.
    """
    from_user = get_constant("MAGPIE_SMTP_USER", settings, default_value="Magpie",
                             print_missing=False, raise_missing=False, raise_not_set=False)
    from_addr = get_constant("MAGPIE_SMTP_FROM", settings,
                             print_missing=True, raise_missing=False, raise_not_set=False)
    password = get_constant("MAGPIE_SMTP_PASSWORD", settings,
                            print_missing=True, raise_missing=False, raise_not_set=False)
    smtp_host = get_constant("MAGPIE_SMTP_HOST", settings, empty_missing=True, print_missing=True)
    smtp_port = get_constant("MAGPIE_SMTP_PORT", settings,
                             raise_not_set=False, raise_missing=False, default_value=465)
    smtp_ssl = get_constant("MAGPIE_SMTP_SSL", settings, default_value=True,
                            print_missing=True, raise_missing=False, raise_not_set=False)
    # one of [from-user/from-addr] must be provided to define the 'sender' (FROM email field)
    # - addr has priority over user as it is unique compared to display name, but both are acceptable
    # - user takes value of addr to display that instead of blank user name explicitly overridden as empty string
    # - addr can then take the value of user name if addr was omitted
    #   (valid only when no auth with password required, or "user" was defined as email directly instead of "from")
    sender = from_addr or from_user
    from_user = from_user or from_addr
    from_addr = from_addr or from_user
    config = {
        "from": from_addr,
        "host": smtp_host,
        "port": smtp_port,
        "user": from_user,
        "password": password,
        "sender": sender,
        "ssl": asbool(smtp_ssl),
    }
    # host, port and resolved sender must always be defined regardless of direct, resolved or default values
    if not smtp_host or not str.isnumeric(str(smtp_port)) or not sender:
        LOGGER.debug("SMTP invalid config: %s", config)
        raise ValueError("SMTP email server configuration is missing required parameters.")
    config["port"] = int(config["port"])  # update only after validated
    return config


def get_smtp_server_connection(config):
    # type: (SMTPServerConfiguration) -> Union[smtplib.SMTP, smtplib.SMTP_SSL]
    """
    Obtains an opened connection to a SMTP server from application settings.

    If the connection is correctly instantiated, the returned SMTP server will be ready for sending emails.
    """
    if config["ssl"]:
        server = smtplib.SMTP_SSL(config["host"], config["port"])
    else:
        server = smtplib.SMTP(config["host"], config["port"])
        server.ehlo()
        try:
            server.starttls()
            server.ehlo()
        except smtplib.SMTPException:
            LOGGER.warning("[Security Risk] "
                           "Failed to establish a TLS connection to SMTP server when SSL was explicitly disabled. "
                           "Emails will not be encrypted.")
    if config["password"]:
        server.login(config["from"], config["password"])
    return server


def make_email_contents(config, settings, template, parameters=None):
    # type: (SMTPServerConfiguration, SettingsType, Template, Optional[TemplateParameters]) -> Str
    """
    Generates the email contents using the template, substitution parameters, and the target email server configuration.
    """
    # add defaults parameters always offered to all templates
    magpie_url = get_magpie_url(settings)
    params = {
        "magpie_url": magpie_url,
        "login_url": "{}/ui/login".format(magpie_url),
        "email_sender": config["sender"],
        "email_user": config["user"],
        "email_from": config["from"],
        "email_datetime": datetime.utcnow().isoformat(" ", "seconds") + " UTC"  # "YYYY-MM-DD HH:mm:ss UTC"
    }
    params.update(parameters or {})
    contents = template.render(**params)
    message = u"{}".format(contents).strip(u"\n")
    return message.encode("utf8")


def send_email(recipient, container, template, parameters=None):
    # type: (Str, AnySettingsContainer, Template, Optional[TemplateParameters]) -> bool
    """
    Send email notification using provided template and parameters.

    The preparation steps of the email (retrieve SMTP configuration, setup the SMTP connection, define email content
    parameters and attempt template generation) will directly raise if invalid as they correspond to incorrect
    application code or configuration settings.

    Following step to send the email with the established SMTP connection is caught and logged if raising an exception.
    This is to allow the calling operation to ignore failing email notification and act accordingly using the resulting
    email status.

    :param recipient: Email address of the intended recipient to which the email must be sent.
    :param template: Mako template used for the email contents.
    :param container: Any container to retrieve application settings.
    :param parameters:
        Parameters to provide for templating email contents.
        They are applied on top of various defaults values provided to all emails.
    :raises: any SMTP server configuration, template generator or parameter parsing error for email setup.
    :returns: success status of the notification email (sent without error, no guarantee of reception).
    """
    LOGGER.debug("Preparing email to: [%s] using template [%s]", recipient, template.filename)
    if not recipient:
        LOGGER.warning("Skipping send email request without a valid recipient: [%s]", template.filename)
        return False

    settings = get_settings(container)
    config = get_smtp_server_configuration(settings)

    params = parameters or {}
    params["email_recipient"] = recipient
    message = make_email_contents(config, settings, template, params)

    LOGGER.debug("Creating SMTP connection to send email using config: %s.", config)
    server = get_smtp_server_connection(config)

    result = None
    try:
        LOGGER.debug("Sending email to: [%s] using template [%s]", recipient, template.filename)
        # result of sendmail is returned only if at least one of many recipients succeeds,
        # but here we use just one, so it should either succeed completely or raise
        result = server.sendmail(config["sender"], [recipient], message)
    except Exception as exc:
        LOGGER.error("Failure during notification email to: [%s] using template [%s]. "
                     "Error: %r", recipient, template.filename, exc)
        LOGGER.debug("Email contents:\n\n%s\n", message, exc_info=exc)
        # don't re-raise here (see docstring)
    finally:
        server.quit()
    if result:
        LOGGER.debug("Unexpected error result from SMTP server during email notification:\n%s", result)
        return False
    LOGGER.debug("Successfully sent email to: [%s] using template [%s]", recipient, template.filename)
    return True
