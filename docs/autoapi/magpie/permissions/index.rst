:mod:`magpie.permissions`
=========================

.. py:module:: magpie.permissions


Module Contents
---------------

.. py:class:: Permission

   Bases: :class:`six.with_metaclass()`

   .. attribute:: READ
      :annotation: = read

      

   .. attribute:: READ_MATCH
      :annotation: = read-match

      

   .. attribute:: WRITE
      :annotation: = write

      

   .. attribute:: WRITE_MATCH
      :annotation: = write-match

      

   .. attribute:: ACCESS
      :annotation: = access

      

   .. attribute:: GET_CAPABILITIES
      :annotation: = getcapabilities

      

   .. attribute:: GET_MAP
      :annotation: = getmap

      

   .. attribute:: GET_FEATURE_INFO
      :annotation: = getfeatureinfo

      

   .. attribute:: GET_LEGEND_GRAPHIC
      :annotation: = getlegendgraphic

      

   .. attribute:: GET_METADATA
      :annotation: = getmetadata

      

   .. attribute:: GET_FEATURE
      :annotation: = getfeature

      

   .. attribute:: DESCRIBE_FEATURE_TYPE
      :annotation: = describefeaturetype

      

   .. attribute:: DESCRIBE_PROCESS
      :annotation: = describeprocess

      

   .. attribute:: EXECUTE
      :annotation: = execute

      

   .. attribute:: LOCK_FEATURE
      :annotation: = lockfeature

      

   .. attribute:: TRANSACTION
      :annotation: = transaction

      


.. function:: convert_permission(permission) -> Optional[Permission]
   Converts any permission representation to the ``Permission`` enum.

   If the permission cannot be matched to one of the enum's value, ``None`` is returned instead.


.. function:: format_permissions(permissions) -> List[Str]
   Obtains the formatted permission representation after validation that it is a member of ``Permission`` enum.

   The returned list is sorted alphabetically and cleaned of any duplicate entries.


