:mod:`magpie.register`
======================

.. py:module:: magpie.register


Module Contents
---------------

.. data:: LOGGER
   

   

.. data:: LOGIN_ATTEMPT
   :annotation: = 10

   

.. data:: LOGIN_TIMEOUT
   :annotation: = 10

   

.. data:: LOGIN_TMP_DIR
   :annotation: = /tmp

   

.. data:: CREATE_SERVICE_INTERVAL
   :annotation: = 2

   

.. data:: GETCAPABILITIES_INTERVAL
   :annotation: = 10

   

.. data:: GETCAPABILITIES_ATTEMPTS
   :annotation: = 12

   

.. data:: SERVICES_MAGPIE
   :annotation: = MAGPIE

   

.. data:: SERVICES_PHOENIX
   :annotation: = PHOENIX

   

.. data:: SERVICES_PHOENIX_ALLOWED
   

   

.. data:: ConfigItem
   

   

.. py:exception:: RegistrationError

   Bases: :class:`RuntimeError`

   Generic error during registration operation.


.. py:exception:: RegistrationValueError

   Bases: :class:`magpie.register.RegistrationError`, :class:`ValueError`

   Registration error caused by an invalid value precondition.


.. py:exception:: RegistrationLoginError

   Bases: :class:`magpie.register.RegistrationError`

   Registration error caused by a failure to complete required login operation.


.. py:exception:: RegistrationConfigurationError

   Bases: :class:`magpie.register.RegistrationValueError`

   Registration error caused by an invalid configuration entry or definition.


.. function:: _login_loop(login_url, cookies_file, data=None, message='Login response')

.. function:: _request_curl(url, cookie_jar=None, cookies=None, form_params=None, msg='Response') -> Tuple[int, int]
   Executes a request using cURL.

   :returns: tuple of the returned system command code and the response http code


.. function:: phoenix_update_services(services_dict)

.. function:: phoenix_login(cookies)

.. function:: phoenix_login_check(cookies)
   Since Phoenix always return 200, even on invalid login, 'hack' check unauthorized access.

   :param cookies: temporary cookies file storage used for login with `phoenix_login`.
   :return: status indicating if login access was granted with defined credentials.


.. function:: phoenix_remove_services() -> bool
   Removes the Phoenix services using temporary cookies retrieved from login with defined `PHOENIX` constants.

   :returns: success status of the procedure.


.. function:: phoenix_register_services(services_dict, allowed_service_types=None)

.. function:: _register_services(where, services_dict, cookies, message='Register response') -> Tuple[bool, Dict[Str, int]]
   Registers services on desired location using provided configurations and access cookies.

   :returns: tuple of overall success and individual http response of each service registration.


.. function:: sync_services_phoenix(services_object_dict, services_as_dicts=False)
   Syncs Magpie services by pushing updates to Phoenix. Services must be one of types specified in
   SERVICES_PHOENIX_ALLOWED.

   :param services_object_dict: dictionary of {svc-name: models.Service} objects containing each service's information
   :param services_as_dicts: alternatively specify `services_object_dict` as dict of {svc-name: {service-info}}
   where {service-info} = {'public_url': <url>, 'service_name': <name>, 'service_type': <type>}


.. function:: magpie_add_register_services_perms(services, statuses, curl_cookies, request_cookies, disable_getcapabilities)

.. function:: magpie_update_services_conflict(conflict_services, services_dict, request_cookies) -> Dict[Str, int]
   Resolve conflicting services by name during registration by updating them only if pointing to different URL.


.. function:: magpie_register_services_with_requests(services_dict, push_to_phoenix, username, password, provider, force_update=False, disable_getcapabilities=False) -> bool
   Registers magpie services using the provided services configuration.

   :param services_dict: services configuration definition.
   :param push_to_phoenix: push registered Magpie services to Phoenix for synced configurations.
   :param username: login username to use to obtain permissions for services registration.
   :param password: login password to use to obtain permissions for services registration.
   :param provider: login provider to use to obtain permissions for services registration.
   :param force_update: override existing services matched by name
   :param disable_getcapabilities: do not execute 'GetCapabilities' validation for applicable services.
   :return: successful operation status


.. function:: magpie_register_services_with_db_session(services_dict, db_session, push_to_phoenix=False, force_update=False, update_getcapabilities_permissions=False)

.. function:: _load_config(path_or_dict, section) -> ConfigDict
   Loads a file path or dictionary as YAML/JSON configuration.


.. function:: _get_all_configs(path_or_dict, section) -> List[ConfigDict]
   Loads all configuration files specified by the path (if a directory), a single configuration (if a file) or
   directly returns the specified dictionary section (if a configuration dictionary).

   :returns:
       list of configurations loaded if input was a directory path
       list of single configuration if input was a file path
       list of single configuration if input was a JSON dict
       empty list if none of the other cases where matched

   .. note::
       Order of file loading will be resolved by alphabetically sorted filename if specifying a directory path.


.. function:: _expand_all(config) -> ConfigDict
   Applies environment variable expansion recursively to all applicable fields of a configuration definition.


.. function:: magpie_register_services_from_config(service_config_path, push_to_phoenix=False, force_update=False, disable_getcapabilities=False, db_session=None) -> None
   Registers Magpie services from one or many `providers.cfg` file.

   Uses the provided DB session to directly update service definitions, or uses API request routes as admin. Optionally
   pushes updates to Phoenix.


.. function:: _log_permission(message, permission_index, trail=', skipping...', detail=None, permission=None, level=logging.WARN) -> None
   Logs a message related to a 'permission' entry.

   Log message format is as follows::

       {message} [permission: #{permission_index}] [{permission}]{trail}
       Detail: [{detail}]

   Such that the following logging entry is generated (omitting any additional logging formatters)::

       >> log_permission("test", 1, " skip test...", "just a test", "fake")
       test [permission: #1] [fake] skip test...
       Detail: [just a test]

   :param message: base message to log
   :param permission_index: index of the permission in the configuration list for traceability
   :param trail: trailing message appended after the base message
   :param detail: additional details appended after the trailing message after moving to another line.
   :param permission: permission name to log just before the trailing message.
   :param level: logging level (default: ``logging.WARN``)

   .. seealso::
       `magpie/config/permissions.cfg`


.. function:: _use_request(cookies_or_session)

.. function:: _parse_resource_path(permission_config_entry, entry_index, service_info, cookies_or_session=None, magpie_url=None) -> Tuple[Optional[int], bool]
   Parses the `resource` field of a permission config entry and retrieves the final resource id. Creates missing
   resources as necessary if they can be automatically resolved.

   If `cookies` are provided, uses requests to a running `Magpie` instance (with ``magpie_url``) to apply permission.
   If `session` to db is provided, uses direct db connection instead to apply permission.

   :returns: tuple of found id (if any, ``None`` otherwise), and success status of the parsing operation (error)


.. function:: _apply_permission_entry(permission_config_entry, entry_index, resource_id, cookies_or_session, magpie_url) -> None
   Applies the single permission entry retrieved from the permission configuration.

   Assumes that permissions fields where pre-validated. Permission is applied for the user/group/resource using request
   or db session accordingly to arguments.


.. function:: magpie_register_permissions_from_config(permissions_config, magpie_url=None, db_session=None) -> None
   Applies `permissions` specified in configuration(s) defined as file, directory with files or literal configuration.

   :param permissions_config: file/dir path to `permissions` config or JSON/YAML equivalent pre-loaded.
   :param magpie_url: URL to magpie instance (when using requests; default: `magpie.url` from this app's config).
   :param db_session: db session to use instead of requests to directly create/remove permissions with config.

   .. seealso::
       `magpie/config/permissions.cfg` for specific parameters and operational details.


.. function:: _process_permissions(permissions, magpie_url, cookies_or_session) -> None
   Processes a single `permissions` configuration.


