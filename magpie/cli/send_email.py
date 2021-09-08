#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Sends email notification using SMTP connection defined from configuration.

Useful for validation of SMTP settings retrieved from an INI file or debugging the rendered email contents.
"""
import argparse
import inspect
from typing import TYPE_CHECKING

from mako.template import Template

from magpie.api.notifications import DEFAULT_TEMPLATE_MAPPING, get_email_template, send_email
from magpie.cli.utils import make_logging_options, setup_logger_from_options
from magpie.utils import get_logger, get_settings_from_config_ini

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional, Sequence

    from magpie.typedefs import Str
    UserConfig = List[Dict[Str, Str]]

LOGGER = get_logger(__name__,
                    message_format="%(asctime)s - %(levelname)s - %(message)s",
                    datetime_format="%d-%b-%y %H:%M:%S", force_stdout=False)


class EmailTemplateChoiceFormatter(argparse.HelpFormatter):
    def _format_action(self, action):
        """
        Override the returned help message with available options and shortcuts for email template selection.
        """
        text = super(EmailTemplateChoiceFormatter, self)._format_action(action)  # noqa: W0212
        if action.dest != "template":
            return text
        self._indent()
        indent = " " * self._current_indent
        choices = action.choices.items()  # noqa
        choices_str = ["{}{}) {}".format(indent, i, tmpl) for i, tmpl in choices if isinstance(i, int)]
        text += "\n{}Choices are:\n{}".format(indent, "\n".join(choices_str))
        self._dedent()
        return text


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=EmailTemplateChoiceFormatter)
    email_opts = parser.add_argument_group(title="Email Arguments",
                                           description="Operation arguments to define email to be sent.")
    email_opts.add_argument("-e", "--email", required=True, help="Address where to sent the test email.")
    # Because email template names are long and inconvenient to type, provide a "index" map for quick selection
    #   Example: "test", "0" (str) and 0 (int) will all map to the same template, and so on for all available templates.
    # str(index) mapping is needed for parsing since int indices become str when parsed from command line inputs
    # int(index) are useful to avoid duplicates items when generating the option list in EmailTemplateChoiceFormatter
    email_choices = ["test"] + list(DEFAULT_TEMPLATE_MAPPING)
    email_choices_map = {i: tmpl for i, tmpl in enumerate(email_choices)}
    email_choices_map.update({str(i): tmpl for i, tmpl in list(email_choices_map.items())})
    email_choices_map.update({tmpl: tmpl for tmpl in email_choices})
    email_opts.add_argument("-t", "--template", default="test", choices=email_choices_map,
                            type=lambda value: email_choices_map.get(value),  # auto-map index shortcut to name
                            metavar="TEMPLATE_CHOICE",  # choices meta-var to replace list, otherwise its very ugly
                            help="Email template of email contents to send. Must be one of the allowed templates. "
                                 "Minimal example content by default using [%(default)s]. ")
    conf_opts = parser.add_argument_group(title="Configuration Arguments",
                                          description="Configuration parameters to define email and SMTP settings.")
    conf_opts.add_argument("-c", "--config", "--ini", required=True, metavar="CONFIG", dest="config",
                           help="Configuration INI file to retrieve application settings.")
    make_logging_options(parser)
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    setup_logger_from_options(LOGGER, args)

    settings = get_settings_from_config_ini(args.config)

    parameters = {}
    if args.template == "test":
        tmpl_str = inspect.cleandoc("""
        From: Magpie
        To: ${email_recipient}
        Subject: Magpie CLI Test Email
        Content-Type: text/plain; charset=UTF-8

        This is a minimal test email sent from Magpie CLI at ${email_datetime}.
        """)
        template = Template(text=tmpl_str,  # nosec: B702  # mako escapes against XSS attacks
                            default_filters=["decode.utf8", "trim"],  # Content-Type charset=UTF-8
                            strict_undefined=True)  # report name of any missing variable reference
    else:
        template = get_email_template(args.template)

        # setup a fake user to generate template contents
        class FakeTestUser(object):
            user_name = "fake-test-user"
            email = "fake-test-user@email.com"
            id = 1234

        parameters = {"user": FakeTestUser()}
        param_urls = ["confirm_url", "approve_url", "decline_url"]
        parameters.update({key: "http://fake-url/{}".format(key) for key in param_urls})

    if send_email(args.email, settings, template, parameters):
        LOGGER.info("Email expedition returned successfully. Please validate email inbox of sent recipient.")
    else:
        LOGGER.warning("Email expedition indicated an error during operation. Email probably failed to be sent.")
    return 0


if __name__ == "__main__":
    main()
