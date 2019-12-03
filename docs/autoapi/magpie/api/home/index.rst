:mod:`magpie.api.home`
======================

.. py:module:: magpie.api.home


Submodules
----------
.. toctree::
   :titlesonly:
   :maxdepth: 1

   home/index.rst


Package Contents
----------------

.. function:: get_homepage(request)
   Magpie API homepage (only if Magpie UI is not enabled).


.. function:: get_constant(constant_name, settings_container=None, settings_name=None, default_value=None, raise_missing=True, print_missing=False, raise_not_set=True) -> SettingValue
   Search in order for matched value of ``constant_name``:
     1. search in settings if specified
     2. search alternative setting names
     3. search in ``magpie.constants`` definitions
     4. search in environment variables

   Parameter ``constant_name`` is expected to have the format ``MAGPIE_[VARIABLE_NAME]`` although any value can
   be passed to retrieve generic settings from all above mentioned search locations.

   If ``settings_name`` is provided as alternative name, it is used as is to search for results if ``constant_name``
   was not found. Otherwise, ``magpie.[variable_name]`` is used for additional search when the format
   ``MAGPIE_[VARIABLE_NAME]`` was used for ``constant_name``
   (ie: ``MAGPIE_ADMIN_USER`` will also search for ``magpie.admin_user`` and so on for corresponding constants).

   :param constant_name: key to search for a value
   :param settings_container: wsgi app settings container
   :param settings_name: alternative name for `settings` if specified
   :param default_value: default value to be returned if not found anywhere, and exception raises are disabled.
   :param raise_missing: raise exception if key is not found anywhere
   :param print_missing: print message if key is not found anywhere, return `None`
   :param raise_not_set: raise an exception if the found key is None, search until last case if previous are `None`
   :returns: found value or `default_value`
   :raises: according message based on options (by default raise missing/`None` value)


.. function:: get_logger(name, level=None)
   Immediately sets the logger level to avoid duplicate log outputs from the `root logger` and `this logger` when
   `level` is `NOTSET`.


.. data:: LOGGER
   

   

.. function:: includeme(config)

