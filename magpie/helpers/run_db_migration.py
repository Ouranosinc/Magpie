import argparse

from magpie.constants import MAGPIE_INI_FILE_PATH
from magpie.db import run_database_migration

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Magpie database migration")
    parser.add_argument("-c", "--config-file", metavar="config_file", dest="config_file", type=str,
                        default=MAGPIE_INI_FILE_PATH,
                        help="configuration file to employ for database connection settings "
                             "(default: MAGPIE_INI_FILE_PATH='%(default)s)'")
    args = parser.parse_args()
    run_database_migration(settings={"magpie.ini_file_path": args.config_file})
