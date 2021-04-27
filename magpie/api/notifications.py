import binascii
import hashlib
import os
import smtplib
from typing import TYPE_CHECKING

from mako.template import Template
from pyramid.settings import asbool

from magpie.utils import get_logger, get_settings

if TYPE_CHECKING:
    from typing import Union

    from magpie.typedefs import AnySettingsContainer, SettingsType

LOGGER = get_logger(__name__)


def get_smtp_server_connection(settings):
    # type: (SettingsType) -> Union[smtplib.SMTP, smtplib.SMTP_SSL]
    """
    Obtains an opened connection to a SMTP server from application settings.

    If the connection is correctly instantiated, the returned SMTP server will be ready for sending emails.
    """
    smtp_host = settings.get("magpie.wps_email_notify_smtp_host")
    from_addr = settings.get("magpie.wps_email_notify_from_addr")
    password = settings.get("magpie.wps_email_notify_password")
    port = settings.get("magpie.wps_email_notify_port")
    ssl = asbool(settings.get("magpie.wps_email_notify_ssl", True))
    if not smtp_host or not port:
        raise ValueError("SMTP email server configuration is missing.")
    if ssl:
        server = smtplib.SMTP_SSL(smtp_host, port)
    else:
        server = smtplib.SMTP(smtp_host, port)
        server.ehlo()
        try:
            server.starttls()
            server.ehlo()
        except smtplib.SMTPException:
            pass
    if password:
        server.login(from_addr, password)
    return server


def notify_email(recipient, template_file, container):
    # type: (str, str, AnySettingsContainer) -> None
    """
    Send email notification using provided template and parameters.

    :param recipient: email of the intended recipient of the email.
    :param template_file: Mako template file used for the email body.
    :param container: any container to retrieve application settings.
    """
    settings = get_settings(container)

    if not isinstance(template_file, str) or not os.path.isfile(template_file) or not template_file.endswith(".mako"):
        raise IOError("Email template file doesn't exist or is invalid [{!s}]".format(template_file))

    params = {}
    template = Template(filename=template_file)
    contents = template.render(to=recipient, settings=settings, **params)
    message = u"{}".format(contents).strip(u"\n")

    server = get_smtp_server_connection(settings)

    try:
        result = server.sendmail(from_addr, recipient, message.encode("utf8"))
    finally:
        server.close()

    if result:
        code, error_message = result[recipient]
        raise IOError("Code: {}, Message: {}".format(code, error_message))
