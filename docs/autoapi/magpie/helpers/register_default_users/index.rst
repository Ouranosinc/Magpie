:mod:`magpie.helpers.register_default_users`
============================================

.. py:module:: magpie.helpers.register_default_users


Module Contents
---------------

.. data:: LOGGER
   

   

.. function:: register_user_with_group(user_name, group_name, email, password, db_session) -> None
   Registers the user if missing and associate him to a group specified by name, also created if missing.

   :param user_name: name of the user to create (if missing) and to make part of the group (if specified)
   :param group_name: name of the group to create (if missing and specified) and to make the user join (if not already)
   :param email: email of the user to be created (if missing)
   :param password: password of the user to be created (if missing)
   :param db_session: database connexion to apply changes

   .. warning::
       Should be employed only for **special** users/groups in this module as other expected API behaviour
       and operations will not be applied (ex: create additional permissions or user-group references).


.. function:: init_anonymous(db_session, settings=None) -> None
   Registers in db the user and group matching ``MAGPIE_ANONYMOUS_USER`` and ``MAGPIE_ANONYMOUS_GROUP`` respectively if
   not defined.


.. function:: init_admin(db_session, settings=None) -> None
   Registers in db the user and group matching ``MAGPIE_ADMIN_USER`` and ``MAGPIE_ADMIN_GROUP`` respectively if not
   defined.

   Also associates the created admin user with the admin group and give it admin permissions.


.. function:: init_users_group(db_session, settings=None) -> None
   Registers in db the group matching ``MAGPIE_USERS_GROUP`` if not defined.


.. function:: register_default_users(db_session=None, settings=None) -> None
   Registers in db every undefined default users and groups matching following variables :

   - ``MAGPIE_ANONYMOUS_USER``
   - ``MAGPIE_USERS_GROUP``
   - ``MAGPIE_ADMIN_GROUP``
   - ``MAGPIE_ADMIN_USER``


