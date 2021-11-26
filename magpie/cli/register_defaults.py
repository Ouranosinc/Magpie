#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Magpie helpers for user and group registration.
"""
import argparse
import logging
import time
from typing import TYPE_CHECKING

import transaction
from sqlalchemy.orm.session import Session
from ziggurat_foundations.models.services import BaseService
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.user import UserService

from magpie import db, models
from magpie.api.management.user import user_utils as uu
from magpie.cli.utils import make_logging_options, setup_logger_from_options
from magpie.constants import get_constant
from magpie.register import pseudo_random_string
from magpie.utils import get_json, get_logger, print_log, raise_log

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Optional, Sequence

    from magpie.typedefs import AnySettingsContainer, Str

LOGGER = get_logger(__name__)


def register_user_with_group(user_name, group_name, email, password, db_session):
    # type: (Str, Str, Str, Optional[Str], Session) -> None
    """
    Registers the user if missing and associate him to a group specified by name, also created if missing.

    :param user_name: name of the user to create (if missing) and to make part of the group (if specified)
    :param group_name: name of the group to create (if missing and specified) and to make the user join (if not already)
    :param email: email of the user to be created (if missing)
    :param password: password of the user to be created (if missing), auto-generate if not provided (None).
    :param db_session: database connexion to apply changes

    .. warning::
        Should be employed only for **special** users/groups in this module as other expected API behaviour
        and operations will not be applied (ex: create additional permissions or user-group references).
    """

    if not GroupService.by_group_name(group_name, db_session=db_session):
        new_group = models.Group(group_name=group_name)  # noqa
        db_session.add(new_group)
    registered_group = GroupService.by_group_name(group_name=group_name, db_session=db_session)

    registered_user = UserService.by_user_name(user_name, db_session=db_session)
    if not registered_user:
        if password is None:
            LOGGER.debug("No password provided for user [%s], auto-generating one.", user_name)
            password = pseudo_random_string(length=get_constant("MAGPIE_PASSWORD_MIN_LENGTH"))
        uu.check_user_info(user_name=user_name, password=password, group_name=group_name, check_email=False)
        new_user = models.User(user_name=user_name, email=email)  # noqa
        UserService.set_password(new_user, password)
        db_session.add(new_user)
        if group_name is not None:
            registered_user = UserService.by_user_name(user_name, db_session=db_session)
    else:
        print_log("User '{}' already exist".format(user_name), level=logging.DEBUG, logger=LOGGER)

    try:
        # ensure the reference between user/group exists (user joined the group)
        user_group_refs = BaseService.all(models.UserGroup, db_session=db_session)
        user_group_refs_tup = [(ref.group_id, ref.user_id) for ref in user_group_refs]
        if (registered_group.id, registered_user.id) not in user_group_refs_tup:
            group_entry = models.UserGroup(group_id=registered_group.id, user_id=registered_user.id)  # noqa
            db_session.add(group_entry)
    except Exception:  # noqa: W0703 # nosec: B110 # pragma: no cover
        # in case reference already exists, avoid duplicate error
        db_session.rollback()


def init_anonymous(db_session, settings=None):
    # type: (Session, Optional[AnySettingsContainer]) -> None
    """
    Registers into the database the user and group matching configuration values of.

    :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` and :py:data:`magpie.constants.MAGPIE_ANONYMOUS_GROUP`
    respectively if not defined.

    Afterwards, updates the group's parameters to ensure integrity with `Magpie` settings.
    """
    anonymous_group = get_constant("MAGPIE_ANONYMOUS_GROUP", settings_container=settings)
    register_user_with_group(user_name=get_constant("MAGPIE_ANONYMOUS_USER", settings_container=settings),
                             group_name=anonymous_group,
                             email=get_constant("MAGPIE_ANONYMOUS_EMAIL", settings_container=settings),
                             password=None,  # autogen, value doesn't matter as no login applicable, just make it valid
                             db_session=db_session)

    # enforce some admin group fields
    group = GroupService.by_group_name(anonymous_group, db_session=db_session)
    group.description = "Group that grants public access to its members for applicable resources."
    group.discoverable = False


def init_admin(db_session, settings=None):
    # type: (Session, Optional[AnySettingsContainer]) -> None
    """
    Registers into the database the user and group matching configuration values of.

    :py:data:`magpie.constants.MAGPIE_ADMIN_USER` and :py:data:`magpie.constants.MAGPIE_ADMIN_GROUP` respectively if
    not defined.

    Also associates the created admin user with the admin group and give it admin permissions.
    Finally, updates the group's parameters to ensure integrity with `Magpie` settings.
    """
    admin_usr_name = get_constant("MAGPIE_ADMIN_USER", settings_container=settings)
    admin_grp_name = get_constant("MAGPIE_ADMIN_GROUP", settings_container=settings)
    admin_password = get_constant("MAGPIE_ADMIN_PASSWORD", settings_container=settings)
    admin_usr = UserService.by_user_name(admin_usr_name, db_session=db_session)
    if not (admin_usr and GroupService.by_group_name(admin_grp_name, db_session=db_session)):
        register_user_with_group(user_name=admin_usr_name,
                                 group_name=admin_grp_name,
                                 email=get_constant("MAGPIE_ADMIN_EMAIL", settings_container=settings),
                                 password=admin_password,
                                 db_session=db_session)
    # allow old 'invalid' password to ease backward support of existing servers
    elif admin_usr and not UserService.check_password(admin_usr, admin_password):
        # admin user already exist, update modified password
        LOGGER.warning("Detected password change for 'MAGPIE_ADMIN_USER'. Attempting to update...")
        try:
            uu.check_user_info(password=admin_password, check_name=False, check_email=False, check_group=False)
            UserService.set_password(admin_usr, admin_password)
            UserService.regenerate_security_code(admin_usr)
        except Exception as http_exc:  # noqa  # re-raised as value error  # pragma: no cover
            db_session.rollback()
            try:
                msg = "[{}]".format(get_json(http_exc)["detail"])
            except Exception:  # noqa
                msg = "(allowed characters, min-length, etc.)"  # give generic detail as explicit could not be found
            raise_log("Failed to update 'MAGPIE_ADMIN_PASSWORD'. Provided configuration value does not conform to "
                      "password format requirements {}.".format(msg), exception=ValueError, logger=LOGGER)
    elif len(admin_password) < get_constant("MAGPIE_PASSWORD_MIN_LENGTH", settings_container=settings):
        print_log("Weak password detected for 'MAGPIE_ADMIN_USER', consider changing it.",
                  logger=LOGGER, level=logging.WARN)

    # Check if MAGPIE_ADMIN_GROUP has permission MAGPIE_ADMIN_PERMISSION
    magpie_admin_group = GroupService.by_group_name(admin_grp_name, db_session=db_session)  # type: models.Group
    permission_names = [permission.perm_name for permission in magpie_admin_group.permissions]
    admin_perm = get_constant("MAGPIE_ADMIN_PERMISSION", settings_container=settings)
    if admin_perm not in permission_names:
        new_group_permission = models.GroupPermission(perm_name=admin_perm, group_id=magpie_admin_group.id)  # noqa
        try:
            db_session.add(new_group_permission)
        except Exception as exc:  # noqa: W0703 # nosec: B110 # pragma: no cover
            db_session.rollback()
            raise_log("Failed to create admin user-group permission", exception=type(exc), logger=LOGGER)

    # enforce some admin group fields
    magpie_admin_group.description = "Administrative group that grants full access management control to its members."
    magpie_admin_group.discoverable = False


def init_users_group(db_session, settings=None):
    # type: (Session, Optional[AnySettingsContainer]) -> None
    """
    Registers into database the group matching :py:data:`magpie.constants.MAGPIE_USERS_GROUP` if not defined.
    """
    usr_grp_name = get_constant("MAGPIE_USERS_GROUP", settings_container=settings)
    if not GroupService.by_group_name(usr_grp_name, db_session=db_session):
        user_group = models.Group(group_name=usr_grp_name)  # noqa
        db_session.add(user_group)
    else:
        print_log("MAGPIE_USERS_GROUP already initialized", level=logging.DEBUG, logger=LOGGER)


def register_defaults(db_session=None, settings=None, ini_file_path=None):
    # type: (Optional[Session], Optional[AnySettingsContainer], Optional[Str]) -> None
    """
    Registers into database every undefined default users and groups matching following variables:

    - :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`
    - :py:data:`magpie.constants.MAGPIE_USERS_GROUP`
    - :py:data:`magpie.constants.MAGPIE_ADMIN_GROUP`
    - :py:data:`magpie.constants.MAGPIE_ADMIN_USER`
    """
    if not isinstance(db_session, Session):
        if not ini_file_path:
            ini_file_path = get_constant("MAGPIE_INI_FILE_PATH", settings_container=settings)
        db_session = db.get_db_session_from_config_ini(ini_file_path)
    if not db.is_database_ready(db_session):
        time.sleep(2)
        raise_log("Database not ready", logger=LOGGER)

    init_admin(db_session, settings)
    init_anonymous(db_session, settings)
    init_users_group(db_session, settings)
    transaction.commit()
    db_session.close()


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Registers default users and groups in Magpie.")
    parser.add_argument("ini_file_path", help="Path of the configuration INI file to use to retrieve required settings")
    make_logging_options(parser)
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    setup_logger_from_options(LOGGER, args)
    return register_defaults(ini_file_path=args.ini_file_path)


if __name__ == "__main__":
    main()
