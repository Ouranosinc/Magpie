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
from magpie.constants import get_constant
from magpie.utils import get_logger, print_log, raise_log

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from magpie.typedefs import AnySettingsContainer, Str, Optional  # noqa: F401
    from typing import Any, AnyStr, Optional, Sequence  # noqa: F401

LOGGER = get_logger(__name__)


def register_user_with_group(user_name, group_name, email, password, db_session):
    # type: (Str, Str, Str, Str, Session) -> None
    """
    Registers the user if missing and associate him to a group specified by name, also created if missing.

    :param user_name: name of the user to create (if missing) and to make part of the group (if specified)
    :param group_name: name of the group to create (if missing and specified) and to make the user join (if not already)
    :param email: email of the user to be created (if missing)
    :param password: password of the user to be created (if missing)
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
        new_user = models.User(user_name=user_name, email=email)  # noqa
        UserService.set_password(new_user, password)
        UserService.regenerate_security_code(new_user)
        db_session.add(new_user)
        if group_name is not None:
            registered_user = UserService.by_user_name(user_name, db_session=db_session)
    else:
        print_log("User '{}' already exist".format(user_name), level=logging.DEBUG)

    try:
        # ensure the reference between user/group exists (user joined the group)
        user_group_refs = BaseService.all(models.UserGroup, db_session=db_session)
        user_group_refs_tup = [(ref.group_id, ref.user_id) for ref in user_group_refs]
        if (registered_group.id, registered_user.id) not in user_group_refs_tup:
            group_entry = models.UserGroup(group_id=registered_group.id, user_id=registered_user.id)  # noqa
            db_session.add(group_entry)
    except Exception:  # noqa: W0703 # nosec: B110
        # in case reference already exists, avoid duplicate error
        db_session.rollback()


def init_anonymous(db_session, settings=None):
    # type: (Session, Optional[AnySettingsContainer]) -> None
    """
    Registers in db the user and group matching ``MAGPIE_ANONYMOUS_USER`` and ``MAGPIE_ANONYMOUS_GROUP`` respectively if
    not defined.
    """
    register_user_with_group(user_name=get_constant("MAGPIE_ANONYMOUS_USER", settings_container=settings),
                             group_name=get_constant("MAGPIE_ANONYMOUS_GROUP", settings_container=settings),
                             email=get_constant("MAGPIE_ANONYMOUS_EMAIL", settings_container=settings),
                             password=get_constant("MAGPIE_ANONYMOUS_PASSWORD", settings_container=settings),
                             db_session=db_session)


def init_admin(db_session, settings=None):
    # type: (Session, Optional[AnySettingsContainer]) -> None
    """
    Registers in db the user and group matching ``MAGPIE_ADMIN_USER`` and ``MAGPIE_ADMIN_GROUP`` respectively if not
    defined.

    Also associates the created admin user with the admin group and give it admin permissions.
    """
    admin_usr_name = get_constant("MAGPIE_ADMIN_USER", settings_container=settings)
    admin_grp_name = get_constant("MAGPIE_ADMIN_GROUP", settings_container=settings)
    if not (UserService.by_user_name(admin_usr_name, db_session=db_session) and
            GroupService.by_group_name(admin_grp_name, db_session=db_session)):
        register_user_with_group(user_name=admin_usr_name,
                                 group_name=admin_grp_name,
                                 email=get_constant("MAGPIE_ADMIN_EMAIL", settings_container=settings),
                                 password=get_constant("MAGPIE_ADMIN_PASSWORD", settings_container=settings),
                                 db_session=db_session)

    # Check if MAGPIE_ADMIN_GROUP has permission MAGPIE_ADMIN_PERMISSION
    magpie_admin_group = GroupService.by_group_name(admin_grp_name, db_session=db_session)
    permission_names = [permission.perm_name for permission in magpie_admin_group.permissions]
    admin_perm = get_constant("MAGPIE_ADMIN_PERMISSION", settings_container=settings)
    if admin_perm not in permission_names:
        new_group_permission = models.GroupPermission(perm_name=admin_perm, group_id=magpie_admin_group.id)  # noqa
        try:
            db_session.add(new_group_permission)
        except Exception as exc:
            db_session.rollback()
            raise_log("Failed to create admin user-group permission", exception=type(exc))


def init_users_group(db_session, settings=None):
    # type: (Session, Optional[AnySettingsContainer]) -> None
    """
    Registers in db the group matching ``MAGPIE_USERS_GROUP`` if not defined.
    """
    usr_grp_name = get_constant("MAGPIE_USERS_GROUP", settings_container=settings)
    if not GroupService.by_group_name(usr_grp_name, db_session=db_session):
        user_group = models.Group(group_name=usr_grp_name)  # noqa
        db_session.add(user_group)
    else:
        print_log("MAGPIE_USERS_GROUP already initialized", level=logging.DEBUG)


def register_default_users(db_session=None, settings=None, ini_file_path=None):
    # type: (Optional[Session], Optional[AnySettingsContainer], Optional[AnyStr]) -> None
    """
    Registers in db every undefined default users and groups matching following variables :

    - ``MAGPIE_ANONYMOUS_USER``
    - ``MAGPIE_USERS_GROUP``
    - ``MAGPIE_ADMIN_GROUP``
    - ``MAGPIE_ADMIN_USER``
    """
    if not isinstance(db_session, Session):
        if not ini_file_path:
            ini_file_path = get_constant("MAGPIE_INI_FILE_PATH", settings_container=settings)
        db_session = db.get_db_session_from_config_ini(ini_file_path)
    if not db.is_database_ready(db_session):
        time.sleep(2)
        raise_log("Database not ready")

    init_admin(db_session, settings)
    init_anonymous(db_session, settings)
    init_users_group(db_session, settings)
    transaction.commit()
    db_session.close()


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Registers default users in Magpie")
    parser.add_argument("ini_file_path", help="Path of the configuration INI file to use to retrieve required settings")
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[AnyStr]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    return register_default_users(ini_file_path=args.ini_file_path)


if __name__ == "__main__":
    register_default_users()
