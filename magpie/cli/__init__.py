import argparse
import importlib
import os
import sys
from typing import TYPE_CHECKING

from magpie.__meta__ import __version__

if TYPE_CHECKING:
    from typing import Callable


class SubArgumentParserFixedMutexGroups(argparse.ArgumentParser):
    """
    Patch incorrectly handled mutually exclusive groups sections in subparsers.

    .. seealso::
        - https://bugs.python.org/issue43259
        - https://bugs.python.org/issue16807
    """
    def _add_container_actions(self, container):
        # pylint: disable=W0212
        groups = container._mutually_exclusive_groups
        container._mutually_exclusive_groups = []
        super(SubArgumentParserFixedMutexGroups, self)._add_container_actions(container)
        for group in groups:
            mutex_group = self.add_mutually_exclusive_group(required=group.required)
            for action in group._group_actions:
                mutex_group._group_actions.append(action)


def magpie_helper_cli(args=None):
    """
    Groups all sub-helper CLI listed in :py:mod:`magpie.cli` as a common ``magpie_helper``.

    Dispatches the provided arguments to the appropriate sub-helper CLI as requested. Each sub-helper CLI must implement
    functions ``make_parser`` and ``main`` to generate the arguments and dispatch them to the corresponding caller.
    """
    parser = SubArgumentParserFixedMutexGroups(description="Execute Magpie helper operations.")
    parser.add_argument("--version", "-V", action="version", version="%(prog)s {}".format(__version__),
                        help="prints the version of the library and exits")
    subparsers = parser.add_subparsers(title="Helper", dest="helper", description="Name of the helper to execute.")
    helpers_dir = os.path.dirname(__file__)
    helper_mods = os.listdir(helpers_dir)
    helpers = {}
    for module_item in sorted(helper_mods):
        helper_path = os.path.join(helpers_dir, module_item)
        if os.path.isfile(helper_path) and "__init__" not in module_item and module_item.endswith(".py"):
            helper_name = module_item.replace(".py", "")
            helper_root = "magpie.cli"
            helper_module = importlib.import_module("{}.{}".format(helper_root, helper_name), helper_root)
            parser_maker = getattr(helper_module, "make_parser", None)  # type: Callable[[], argparse.ArgumentParser]
            helper_caller = getattr(helper_module, "main", None)
            if parser_maker and helper_caller:
                # add help disabled otherwise conflicts with this main helper's help
                helper_parser = parser_maker()
                subparsers.add_parser(helper_name, parents=[helper_parser],
                                      add_help=False, help=helper_parser.description,
                                      formatter_class=helper_parser.formatter_class,
                                      description=helper_parser.description, usage=helper_parser.usage)
                helpers[helper_name] = {"caller": helper_caller, "parser": helper_parser}
    args = args or sys.argv[1:]         # same as was parse args does, but we must provide them to subparser
    ns = parser.parse_args(args=args)   # if 'helper' is unknown, auto prints the help message with exit(2)
    helper_name = vars(ns).pop("helper")
    if not helper_name:
        parser.print_help()
        return 0
    helper_args = args[1:]
    helper_caller = helpers[helper_name]["caller"]
    helper_parser = helpers[helper_name]["parser"]
    result = helper_caller(args=helper_args, parser=helper_parser, namespace=ns)
    return 0 if result is None else result


if __name__ == "__main__":
    magpie_helper_cli()
