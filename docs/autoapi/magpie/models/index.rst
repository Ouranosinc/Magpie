:mod:`magpie.models`
====================

.. py:module:: magpie.models


Module Contents
---------------

.. data:: Base
   

   

.. function:: get_session_callable(request)

.. py:class:: Group

   Bases: :class:`magpie.definitions.ziggurat_definitions.GroupMixin`, :class:`Base`

   
   .. method:: get_member_count(self, db_session=None)




.. py:class:: GroupPermission

   Bases: :class:`magpie.definitions.ziggurat_definitions.GroupPermissionMixin`, :class:`Base`


.. py:class:: UserGroup

   Bases: :class:`magpie.definitions.ziggurat_definitions.UserGroupMixin`, :class:`Base`


.. py:class:: GroupResourcePermission

   Bases: :class:`magpie.definitions.ziggurat_definitions.GroupResourcePermissionMixin`, :class:`Base`


.. py:class:: Resource

   Bases: :class:`magpie.definitions.ziggurat_definitions.ResourceMixin`, :class:`Base`

   .. attribute:: resource_type_name
      :annotation: :Str

      

   .. attribute:: child_resource_allowed
      :annotation: = True

      

   .. attribute:: resource_display_name
      

      

   .. attribute:: root_service_id
      

      

   .. attribute:: __acl__
      

      


.. py:class:: UserPermission

   Bases: :class:`magpie.definitions.ziggurat_definitions.UserPermissionMixin`, :class:`Base`


.. py:class:: UserResourcePermission

   Bases: :class:`magpie.definitions.ziggurat_definitions.UserResourcePermissionMixin`, :class:`Base`


.. py:class:: User

   Bases: :class:`magpie.definitions.ziggurat_definitions.UserMixin`, :class:`Base`

   
   .. method:: __str__(self)




.. py:class:: ExternalIdentity

   Bases: :class:`magpie.definitions.ziggurat_definitions.ExternalIdentityMixin`, :class:`Base`


.. py:class:: RootFactory(request)

   Bases: :class:`object`


.. py:class:: Service

   Bases: :class:`magpie.models.Resource`

   Resource of `service` type.

   .. attribute:: __tablename__
      :annotation: = services

      

   .. attribute:: resource_id
      

      

   .. attribute:: resource_type_name
      :annotation: = service

      

   .. attribute:: __mapper_args__
      

      

   .. attribute:: permissions
      

      

   .. attribute:: url
      

      

   .. attribute:: type
      

      Identifier matching ``magpie.services.ServiceInterface.service_type``.


   .. attribute:: sync_type
      

      Identifier matching ``magpie.helpers.SyncServiceInterface.sync_type``.


   
   .. staticmethod:: by_service_name(service_name, db_session)




.. py:class:: PathBase

   Bases: :class:`object`

   .. attribute:: permissions
      

      


.. py:class:: File

   Bases: :class:`magpie.models.Resource`, :class:`magpie.models.PathBase`

   .. attribute:: child_resource_allowed
      :annotation: = False

      

   .. attribute:: resource_type_name
      :annotation: = file

      

   .. attribute:: __mapper_args__
      

      


.. py:class:: Directory

   Bases: :class:`magpie.models.Resource`, :class:`magpie.models.PathBase`

   .. attribute:: resource_type_name
      :annotation: = directory

      

   .. attribute:: __mapper_args__
      

      


.. py:class:: Workspace

   Bases: :class:`magpie.models.Resource`

   .. attribute:: resource_type_name
      :annotation: = workspace

      

   .. attribute:: __mapper_args__
      

      

   .. attribute:: permissions
      

      


.. py:class:: Route

   Bases: :class:`magpie.models.Resource`

   .. attribute:: resource_type_name
      :annotation: = route

      

   .. attribute:: __mapper_args__
      

      

   .. attribute:: permissions
      

      


.. py:class:: RemoteResource

   Bases: :class:`magpie.definitions.ziggurat_definitions.BaseModel`, :class:`Base`

   .. attribute:: __tablename__
      :annotation: = remote_resources

      

   .. attribute:: __possible_permissions__
      :annotation: = []

      

   .. attribute:: _ziggurat_services
      

      

   .. attribute:: resource_id
      

      

   .. attribute:: service_id
      

      

   .. attribute:: parent_id
      

      

   .. attribute:: ordering
      

      

   .. attribute:: resource_name
      

      

   .. attribute:: resource_display_name
      

      

   .. attribute:: resource_type
      

      

   
   .. method:: __repr__(self)




.. py:class:: RemoteResourcesSyncInfo

   Bases: :class:`magpie.definitions.ziggurat_definitions.BaseModel`, :class:`Base`

   .. attribute:: __tablename__
      :annotation: = remote_resources_sync_info

      

   .. attribute:: id
      

      

   .. attribute:: service_id
      

      

   .. attribute:: service
      

      

   .. attribute:: remote_resource_id
      

      

   .. attribute:: last_sync
      

      

   
   .. staticmethod:: by_service_id(service_id, session)



   
   .. method:: __repr__(self)




.. py:class:: RemoteResourceTreeService(service_cls)

   Bases: :class:`magpie.definitions.ziggurat_definitions.ResourceTreeService`


.. py:class:: RemoteResourceTreeServicePostgresSQL

   Bases: :class:`magpie.definitions.ziggurat_definitions.ResourceTreeServicePostgreSQL`

   This is necessary, because ResourceTreeServicePostgresSQL.model is the Resource class. If we want to change it for a
   RemoteResource, we need this class.

   The ResourceTreeService.__init__ call sets the model.


.. data:: resource_tree_service
   

   

.. data:: remote_resource_tree_service
   

   

.. data:: RESOURCE_TYPE_DICT
   

   

.. function:: resource_factory(**kwargs)

.. function:: find_children_by_name(child_name, parent_id, db_session)

