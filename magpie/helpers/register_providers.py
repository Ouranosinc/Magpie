from magpie import MAGPIE_PROVIDERS_CONFIG_PATH, MAGPIE_INI_FILE_PATH
from register import magpie_register_services_from_config
from db import get_db_session_from_config_ini
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Register service providers into Magpie and Phoenix")
    parser.add_argument('-c', '--config-file', metavar='config_file', dest='config_file',
                        type=str, default=MAGPIE_PROVIDERS_CONFIG_PATH,
                        help="configuration file to employ for services registration (default: %(default)s)")
    parser.add_argument('-f', '--force-update', default=False, action='store_true', dest='force_update',
                        help="enforce update of services URL if conflicting services are found (default: %(default)s)")
    parser.add_argument('-g', '--no-getcapabilities-overwrite', default=False, action='store_true',
                        dest='no_getcapabilities',
                        help="disable overwriting 'GetCapabilities' permissions to applicable services when they "
                             "already exist, ie: when conflicts occur during service creation (default: %(default)s)")
    parser.add_argument('-p', '--phoenix-push', default=False, action='store_true', dest='phoenix_push',
                        help="push registered Magpie services to sync in Phoenix (default: %(default)s)")
    parser.add_argument('-d', '--use-db-session', default=False, action='store_true', dest='use_db_session',
                        help="update registered services using db session config instead of API (default: %(default)s)")
    args = parser.parse_args()

    db_session = None
    if args.use_db_session:
        db_session = get_db_session_from_config_ini(MAGPIE_INI_FILE_PATH)
    magpie_register_services_from_config(args.config_file,
                                         push_to_phoenix=args.phoenix_push, force_update=args.force_update,
                                         disable_getcapabilities=args.no_getcapabilities, db_session=db_session)
