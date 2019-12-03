:mod:`magpie.services`
======================

.. py:module:: magpie.services


Module Contents
---------------

.. py:class:: ServiceMeta

   Bases: :class:`type`

   .. attribute:: resource_types
      

      Allowed resources type classes under the service.


   .. attribute:: resource_type_names
      

      Allowed resources type names under the service.


   .. attribute:: child_resource_allowed
      

      

   
   .. method:: get_resource_permissions(cls, resource_type_name)

      Obtains the allowed permissions of the service's child resource fetched by resource type name.




.. py:class:: ServiceInterface(service, request)

   Bases: :class:`six.with_metaclass()`

   .. attribute:: service_type
      :annotation: :Str

      

   .. attribute:: params_expected
      :annotation: :List[Str] = []

      

   .. attribute:: permissions
      :annotation: :List[Permission] = []

      

   .. attribute:: resource_types_permissions
      :annotation: :Dict[models.Resource, List[Permission]]

      

   .. attribute:: __acl__
      

      List of access control rules defining (outcome, user/group, permission) combinations.


   
   .. method:: _get_acl_cached(self, service_id, user)

      Beaker will cache this method based on the service id and the user.

      If the cache is not hit, call the self.get_acl() method



   
   .. method:: get_acl(self)



   
   .. method:: expand_acl(self, resource, user)



   
   .. method:: permission_requested(self)



   
   .. method:: effective_permissions(self, resource, user)

      Recursively rewind the resource tree from the specified resource up to the topmost parent service resource and
      retrieve permissions along the way that should be applied to children when using resource inheritance.




.. py:class:: ServiceWPS(service, request)

   Bases: :class:`magpie.services.ServiceInterface`

   .. attribute:: service_type
      :annotation: = wps

      

   .. attribute:: permissions
      

      

   .. attribute:: params_expected
      :annotation: = ['service', 'request', 'version']

      

   .. attribute:: resource_types_permissions
      

      

   
   .. method:: get_acl(self)




.. py:class:: ServiceBaseWMS(service, request)

   Bases: :class:`magpie.services.ServiceInterface`

   .. attribute:: permissions
      

      

   .. attribute:: params_expected
      :annotation: = ['service', 'request', 'version', 'layers', 'layername', 'dataset']

      

   .. attribute:: resource_types_permissions
      

      

   
   .. method:: get_acl(self)




.. py:class:: ServiceNCWMS2(service, request)

   Bases: :class:`magpie.services.ServiceBaseWMS`

   .. attribute:: service_type
      :annotation: = ncwms

      

   .. attribute:: resource_types_permissions
      

      

   
   .. method:: get_acl(self)




.. py:class:: ServiceGeoserverWMS(service, request)

   Bases: :class:`magpie.services.ServiceBaseWMS`

   .. attribute:: service_type
      :annotation: = geoserverwms

      

   
   .. method:: get_acl(self)




.. py:class:: ServiceAccess(service, request)

   Bases: :class:`magpie.services.ServiceInterface`

   .. attribute:: service_type
      :annotation: = access

      

   .. attribute:: permissions
      

      

   .. attribute:: params_expected
      :annotation: = []

      

   .. attribute:: resource_types_permissions
      

      

   
   .. method:: get_acl(self)



   
   .. method:: permission_requested(self)




.. py:class:: ServiceAPI(service, request)

   Bases: :class:`magpie.services.ServiceInterface`

   .. attribute:: service_type
      :annotation: = api

      

   .. attribute:: permissions
      

      

   .. attribute:: params_expected
      :annotation: = []

      

   .. attribute:: resource_types_permissions
      

      

   
   .. method:: get_acl(self, sub_api_route=None)



   
   .. method:: permission_requested(self)



   
   .. method:: effective_permissions(self, resource, user)




.. py:class:: ServiceWFS(service, request)

   Bases: :class:`magpie.services.ServiceInterface`

   .. attribute:: service_type
      :annotation: = wfs

      

   .. attribute:: permissions
      

      

   .. attribute:: params_expected
      :annotation: = ['service', 'request', 'version', 'typenames']

      

   .. attribute:: resource_types_permissions
      

      

   
   .. method:: get_acl(self)




.. py:class:: ServiceTHREDDS(service, request)

   Bases: :class:`magpie.services.ServiceInterface`

   .. attribute:: service_type
      :annotation: = thredds

      

   .. attribute:: permissions
      

      

   .. attribute:: params_expected
      :annotation: = ['request']

      

   .. attribute:: resource_types_permissions
      

      

   
   .. method:: get_acl(self)



   
   .. method:: permission_requested(self)




.. data:: SERVICE_TYPE_DICT
   

   

.. function:: service_factory(service, request) -> ServiceInterface
   Retrieve the specific service class from the provided database service entry.


