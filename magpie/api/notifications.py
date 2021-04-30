import os
import smtplib
from typing import TYPE_CHECKING

from mako.template import Template
from pyramid.settings import asbool

from magpie.constants import get_constant
from magpie.utils import get_logger, get_magpie_url, get_settings, raise_log

if TYPE_CHECKING:
    from typing import Any, Dict, Optional, Union

    from magpie.typedefs import AnySettingsContainer, SettingsType, Str, TypedDict

    SMTPServerConfiguration = TypedDict("SMTPServerConfiguration", {
        "addr": Str, "host": Str, "port": Str, "user": Str, "password": Optional[Str], "sender": Str, "ssl": bool,
    })
    TemplateParameters = Dict[Str, Any]

LOGGER = get_logger(__name__)

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
DEFAULT_TEMPLATE_MAPPING = {
    "MAGPIE_USER_REGISTRATION_EMAIL_TEMPLATE": os.path.join(TEMPLATE_DIR, "email_user_registration.mako"),
    "MAGPIE_USER_REGISTERED_EMAIL_TEMPLATE": os.path.join(TEMPLATE_DIR, "email_user_registered.mako"),
    "MAGPIE_ADMIN_APPROVAL_EMAIL_TEMPLATE": os.path.join(TEMPLATE_DIR, "email_admin_approval.mako"),
    "MAGPIE_ADMIN_APPROVED_EMAIL_TEMPLATE": os.path.join(TEMPLATE_DIR, "email_admin_approved.mako"),
}


def get_email_template(template_constant, settings=None):
    # type: (Str, Optional[AnySettingsContainer]) -> Template
    """
    Retrieves the template file with email content matching the custom application setting or the corresponding default.

    Allowed values of :paramref:`template_constant` are:

        - :envvar:`MAGPIE_USER_REGISTRATION_EMAIL_TEMPLATE`
        - :envvar:`MAGPIE_USER_REGISTERED_EMAIL_TEMPLATE`
        - :envvar:`MAGPIE_ADMIN_APPROVAL_EMAIL_TEMPLATE`
        - :envvar:`MAGPIE_ADMIN_APPROVED_EMAIL_TEMPLATE`
    """
    if template_constant not in DEFAULT_TEMPLATE_MAPPING:
        raise_log("Specified template is not one of {}".format(list(DEFAULT_TEMPLATE_MAPPING)), ValueError, LOGGER)
    template_file = get_constant(template_constant, settings, default_value=DEFAULT_TEMPLATE_MAPPING[template_constant],
                                 print_missing=False, raise_missing=False, raise_not_set=False)
    if not isinstance(template_file, str) or not os.path.isfile(template_file) or not template_file.endswith(".mako"):
        raise_log("Email template [{}] missing or invalid from [{!s}]".format(template_constant, template_file),
                  IOError, logger=LOGGER)
    template = Template(filename=template_file)
    return template


def get_smtp_server_configuration(settings):
    # type: (SettingsType) -> SMTPServerConfiguration
    """
    Obtains and validates all required configuration parameters for SMTP server in order to send an email.
    """
    # from/password can be empty for no-auth SMTP server
    from_user = get_constant("MAGPIE_SMTP_USER", settings, default_value="Magpie",
                             print_missing=False, raise_missing=False, raise_not_set=False)
    from_addr = get_constant("MAGPIE_SMTP_FROM", settings,
                             print_missing=True, raise_missing=False, raise_not_set=False)
    password = get_constant("MAGPIE_SMTP_PASSWORD", settings,
                            print_missing=True, raise_missing=False, raise_not_set=False)
    smtp_host = get_constant("MAGPIE_SMTP_HOST", settings)
    smtp_port = int(get_constant("MAGPIE_SMTP_PORT", settings))
    smtp_ssl = asbool(get_constant("MAGPIE_SMTP_SSL", settings, default_value=True,
                                   print_missing=True, raise_missing=False, raise_not_set=False))
    sender = from_addr or from_user
    if not smtp_host or not smtp_port:
        raise ValueError("SMTP email server configuration is missing.")
    config = {
        "addr": from_addr,
        "host": smtp_host,
        "port": smtp_port,
        "user": from_user,
        "password": password,
        "sender": sender,
        "ssl": smtp_ssl,
    }
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
            pass
    if config["password"]:
        server.login(config["from"], config["password"])
    return server


def make_email_contents(config, template, parameters, settings):
    # type: (SMTPServerConfiguration, Template, TemplateParameters, SettingsType) -> Str
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
        "email_from": config["addr"],
    }
    params.update(parameters or {})
    contents = template.render(**params)
    message = u"{}".format(contents).strip(u"\n")
    return message.encode("utf8")


def send_email(recipient, template, container, parameters=None):
    # type: (Str, Template, AnySettingsContainer, Optional[TemplateParameters]) -> None
    """
    Send email notification using provided template and parameters.

    :param recipient: email of the intended recipient of the email.
    :param template: Mako template used for the email contents.
    :param container: Any container to retrieve application settings.
    :param parameters:
        Parameters to provide for templating email contents.
        They are applied on top of various defaults values provided to all emails.
    """
    LOGGER.debug("Preparing email to: [%s] using template [%s]", recipient, template.filename)
    settings = get_settings(container)
    params = parameters or {}
    params["email_recipient"] = recipient
    config = get_smtp_server_configuration(settings)
    message = make_email_contents(config, template, params, settings)

    server = None
    try:
        LOGGER.debug("Sending email to: [%s] using template [%s]", recipient, template.filename)
        server = get_smtp_server_connection(config)
        result = server.sendmail(config["sender"], recipient, message)
    except Exception as exc:
        LOGGER.error("Failure during notification email.", exc_info=exc)
        LOGGER.debug("Email contents:\n\n%s\n", message)
        raise
    finally:
        if server:
            server.quit()

    if result:
        code, error_message = result[recipient]
        raise IOError("Code: {}, Message: {}".format(code, error_message))
