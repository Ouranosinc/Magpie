# -*- coding: utf-8 -*-

__author__ = 'Francois-Xavier'
__email__ = 'francois-xavier.derue@crim.ca'
__version__ = '0.2.0'


import json
import os
from api_except import *
from api_except import *
from models import *
from pyramid.httpexceptions import (
    HTTPFound,
    HTTPOk,
    HTTPTemporaryRedirect,
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPNotFound,
    HTTPUnauthorized,
    HTTPAccepted,
    HTTPNoContent,
)
from pyramid.security import ALL_PERMISSIONS
from pyramid.view import view_config
from ziggurat_foundations.ext.pyramid.sign_in import ZigguratSignInBadAuth
from ziggurat_foundations.ext.pyramid.sign_in import ZigguratSignInSuccess
from ziggurat_foundations.ext.pyramid.sign_in import ZigguratSignOut
from ziggurat_foundations.models.services.external_identity import ExternalIdentityService
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.user import UserService
from ziggurat_foundations.permissions import permission_to_pyramid_acls
from ziggurat_foundations.models.services.group_resource_permission import GroupResourcePermissionService
from ziggurat_foundations.models.services.resource import ResourceService
from ziggurat_foundations.models.services.user_resource_permission import UserResourcePermissionService
from ziggurat_foundations.permissions import ANY_PERMISSION
from ziggurat_foundations.models.services.resource_tree import ResourceTreeService
from ziggurat_foundations.models.services.resource_tree_postgres import ResourceTreeServicePostgreSQL
from pyramid.security import NO_PERMISSION_REQUIRED
ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_GROUP = os.getenv('ADMIN_GROUP', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')

USER_GROUP = os.getenv('USER_GROUP', 'user')

ANONYMOUS_USER = os.getenv('ANONYMOUS_USER', 'anonymous')

#ADMIN_PERM = 'edit'
ADMIN_PERM = NO_PERMISSION_REQUIRED

LOGGED_USER = 'current'
