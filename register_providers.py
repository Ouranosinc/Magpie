from magpie.register import magpie_register_services
import sys
from os import path as p


if __name__ == "__main__":
    """
    >> python register_providers [<path_to_config_file> [<push_to_phoenix>(0|1)]]
    """
    if len(sys.argv) < 2:
        config_file_path = p.join(p.dirname(p.abspath(__file__)), "providers.cfg")
        print("Using default file [" + config_file_path + "] since not provided as input")
    else:
        config_file_path = sys.argv[1]

    push_to_phoenix = bool(sys.argv[2]) if len(sys.argv) > 2 else False

    magpie_register_services(config_file_path)
