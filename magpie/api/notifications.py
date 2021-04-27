import os
import smtplib
from typing import TYPE_CHECKING

from mako.template import Template
from pyramid.settings import asbool

from magpie.constants import get_constant
from magpie.utils import get_logger, get_magpie_url, get_settings

if TYPE_CHECKING:
    from typing import Any, Dict, Optional, Tuple, Union

    from magpie.typedefs import AnySettingsContainer, SettingsType, Str

LOGGER = get_logger(__name__)


def get_smtp_server_connection(settings):
    # type: (SettingsType) -> Tuple[Union[smtplib.SMTP, smtplib.SMTP_SSL], Str, Str, Optional[Str]]
    """
    Obtains an opened connection to a SMTP server from application settings.

    If the connection is correctly instantiated, the returned SMTP server will be ready for sending emails.
    """
    # from/password can be empty for no-auth SMTP server
    from_user = get_constant("MAGPIE_SMTP_USER", settings, default_value="Magpie",
                             print_missing=False, raise_missing=False, raise_not_set=False),
    from_addr = get_constant("MAGPIE_SMTP_FROM", settings,
                             print_missing=True, raise_missing=False, raise_not_set=False)
    password = get_constant("MAGPIE_SMTP_PASSWORD", settings,
                            print_missing=True, raise_missing=False, raise_not_set=False)
    smtp_host = get_constant("MAGPIE_SMTP_HOST", settings)
    smtp_port = int(get_constant("MAGPIE_SMTP_PORT", settings))
    ssl = asbool(get_constant("MAGPIE_SMTP_SSL", settings, default_value=True,
                              print_missing=True, raise_missing=False, raise_not_set=False))
    if not smtp_host or not smtp_port:
        raise ValueError("SMTP email server configuration is missing.")
    if ssl:
        server = smtplib.SMTP_SSL(smtp_host, smtp_port)
    else:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.ehlo()
        try:
            server.starttls()
            server.ehlo()
        except smtplib.SMTPException:
            pass
    if password:
        server.login(from_addr, password)
    sender = from_addr or from_user
    return server, sender, from_user, from_addr


def notify_email(recipient, template_file, container, parameters=None):
    # type: (Str, Str, AnySettingsContainer, Optional[Dict[Str, Any]]) -> None
    """
    Send email notification using provided template and parameters.

    :param recipient: email of the intended recipient of the email.
    :param template_file: Mako template file used for the email body.
    :param container: Any container to retrieve application settings.
    :param parameters:
        Parameters to provide for templating email contents.
        They are applied on top of various defaults values provided to all emails.
    """
    settings = get_settings(container)

    if not isinstance(template_file, str) or not os.path.isfile(template_file) or not template_file.endswith(".mako"):
        raise IOError("Email template file doesn't exist or is invalid [{!s}]".format(template_file))

    # add defaults parameters always offered to all templates
    magpie_url = get_magpie_url(settings)
    params = {
        "email_recipient": recipient,
        "magpie_url": magpie_url,
        "login_url": "{}/ui/login".format(magpie_url),
    }
    params.update(parameters or {})
    template = Template(filename=template_file)
    contents = template.render(**params)
    message = u"{}".format(contents).strip(u"\n")

    server = None
    try:
        server, sender, from_user, from_addr = get_smtp_server_connection(settings)
        params.update({
            "email_sender": sender,
            "email_user": from_user,
            "email_from": from_addr,
        })
        result = server.sendmail(sender, recipient, message.encode("utf8"))
    except Exception as exc:
        LOGGER.error("Failure during notification email", exc_info=exc)
        raise
    finally:
        if server:
            server.quit()

    if result:
        code, error_message = result[recipient]
        raise IOError("Code: {}, Message: {}".format(code, error_message))
