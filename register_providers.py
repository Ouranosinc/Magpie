from magpie.register import *
from os import path as p
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Register service providers into Magpie and Phoenix")
    parser.add_argument('-c', '--config-file', metavar='config_file', dest='config_file',
                        type=str, default=p.join(p.dirname(p.abspath(__file__)), "providers.cfg"),
                        help="configuration file to employ for services registration (default: %(default)s)")
    parser.add_argument('-f', '--force-update', default=False, action='store_true', dest='force_update',
                        help="enforce update of services URL if conflicting services are found (default: %(default)s)")
    parser.add_argument('-g', '--no-getcapabilities-overwrite', default=False, action='store_true',
                        dest='no_getcapabilities',
                        help="disable overwriting 'GetCapabilities' permissions to applicable services when they "
                             "already exist, ie: when conflicts occur during service creation (default: %(default)s)")
    parser.add_argument('-p', '--phoenix-push', default=False, action='store_true', dest='phoenix_push',
                        help="push registered Magpie services to sync in Phoenix (default: %(default)s)")
    args = parser.parse_args()
    magpie_register_services_from_config(args.config_file, args.phoenix_push,
                                         args.force_update, args.no_getcapabilities)
