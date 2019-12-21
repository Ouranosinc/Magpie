#!/usr/bin/env python

"""
Send contents to server.
"""

import argparse
from shlex import split
from subprocess import check_call

from six.moves.urllib.parse import urljoin

from .conf import __meta__

DOC_DESTINATION = None  # TODO: Edit this


def norm_perms():
    """
    Normalize permissions in the build directory.
    """
    cmd = split("find _build/html/ -type d -exec chmod o+x '{}' ';'")
    check_call(cmd)
    cmd = split("chmod -R o+r _build/html/")
    check_call(cmd)


def send_static(destination=DOC_DESTINATION):
    """
    Send static site on server.
    """
    cmd = split("rsync -av _build/html/")
    cmd += [urljoin(destination, __meta__.__version__)]
    check_call(cmd)


def main():
    """
    Command line entry point.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination',
                        action='store',
                        default=DOC_DESTINATION,
                        help="Where the static version of the documentation "
                             "will be sent, "
                             "default={}".format(DOC_DESTINATION))
    args = parser.parse_args()
    norm_perms()
    send_static(destination=args.destination)


if __name__ == '__main__':
    main()
