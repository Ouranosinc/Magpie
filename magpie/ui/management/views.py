import datetime
from collections import OrderedDict

import humanize

from magpie.definitions.pyramid_definitions import *
from magpie.constants import get_constant
from magpie.common import str2bool
from magpie.helpers.sync_resources import OUT_OF_SYNC
from magpie.services import service_type_dict
from magpie.models import resource_type_dict, remote_resource_tree_service
from magpie.ui.management import check_response
from magpie.helpers import sync_resources
from magpie.ui.home import add_template_data
from magpie import register, __meta__
from distutils.version import LooseVersion
import requests
import json


class ManagementViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = get_constant('magpie.url', settings=self.request.registry.settings,
                                       raise_missing=True, raise_not_set=True)

    def get_all_groups(self, first_default_group=None):
        try:
            resp_groups = requests.get('{url}/groups'.format(url=self.magpie_url), cookies=self.request.cookies)
        except Exception:
            raise HTTPBadRequest(detail='Bad Json response')
        check_response(resp_groups)
        try:
            groups = list(resp_groups.json()['group_names'])
            if type(first_default_group) is str and first_default_group in groups:
                groups.remove(first_default_group)
                groups.insert(0, first_default_group)
            return groups
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def get_group_users(self, group_name):
        try:
            resp_group_users = requests.get('{url}/groups/{grp}/users'.format(url=self.magpie_url, grp=group_name),
                                            cookies=self.request.cookies)
            check_response(resp_group_users)
            return resp_group_users.json()['user_names']
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def get_user_groups(self, user_name):
        try:
            resp_user_groups = requests.get('{url}/users/{usr}/groups'.format(url=self.magpie_url, usr=user_name),
                                            cookies=self.request.cookies)
            check_response(resp_user_groups)
            return resp_user_groups.json()['group_names']
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def get_user_names(self):
        resp_users = requests.get('{url}/users'.format(url=self.magpie_url), cookies=self.request.cookies)
        try:
            return resp_users.json()['user_names']
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def get_user_emails(self):
        user_names = self.get_user_names()
        try:
            emails = list()
            for user in user_names:
                resp_user = requests.get('{url}/users/{usr}'.format(url=self.magpie_url, usr=user),
                                         cookies=self.request.cookies)
                check_response(resp_user)
                if LooseVersion(__meta__.__version__) >= LooseVersion('0.6.3'):
                    user_email = resp_user.json()['user']['email']
                else:
                    user_email = resp_user.json()['email']
                emails.append(user_email)
            return emails
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def get_resource_types(self):
        """
        :return: dictionary of all resources as {id: 'resource_type'}
        :rtype: dict
        """
        resp_resources = requests.get('{url}/resources'.format(url=self.magpie_url), cookies=self.request.cookies)
        check_response(resp_resources)
        res_dic = self.default_get(resp_resources.json(), 'resources', dict())
        res_ids = dict()
        self.flatten_tree_resource(res_dic, res_ids)
        return res_ids

    def get_services(self, cur_svc_type):
        try:
            resp_services = requests.get('{url}/services'.format(url=self.magpie_url), cookies=self.request.cookies)
            check_response(resp_services)
            all_services = resp_services.json()['services']
            svc_types = sorted(all_services.keys())
            if cur_svc_type not in svc_types:
                cur_svc_type = svc_types[0]
            services = all_services[cur_svc_type]
            return svc_types, cur_svc_type, services
        except Exception:
            raise HTTPBadRequest(detail='Bad Json response')

    def get_service_data(self, service_name):
        try:
            svc_res = requests.get('{url}/services/{svc}'.format(url=self.magpie_url, svc=service_name),
                                   cookies=self.request.cookies)
            check_response(svc_res)
            return svc_res.json()[service_name]
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def update_service_name(self, old_service_name, new_service_name, service_push):
        try:
            svc_data = self.get_service_data(old_service_name)
            svc_data['service_name'] = new_service_name
            svc_data['resource_name'] = new_service_name
            svc_data['service_push'] = service_push
            svc_id = str(svc_data['resource_id'])
            resp_put = requests.put('{url}/resources/{svc_id}'.format(url=self.magpie_url, svc_id=svc_id),
                                    data=svc_data, cookies=self.request.cookies)
            check_response(resp_put)
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def update_service_url(self, service_name, new_service_url, service_push):
        try:
            svc_data = self.get_service_data(service_name)
            svc_data['service_url'] = new_service_url
            svc_data['service_push'] = service_push
            resp_put = requests.put('{url}/services/{svc}'.format(url=self.magpie_url, svc=service_name),
                                    data=svc_data, cookies=self.request.cookies)
            check_response(resp_put)
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def goto_service(self, resource_id):
        try:
            res_json = requests.get('{url}/resources/{id}'.format(url=self.magpie_url, id=resource_id),
                                    cookies=self.request.cookies).json()
            svc_name = res_json[resource_id]['resource_name']
            # get service type instead of 'cur_svc_type' in case of 'default' ('cur_svc_type' not set yet)
            res_json = requests.get('{url}/services/{svc}'.format(url=self.magpie_url, svc=svc_name),
                                    cookies=self.request.cookies).json()
            svc_type = res_json[svc_name]['service_type']
            return HTTPFound(self.request.route_url('edit_service', service_name=svc_name, cur_svc_type=svc_type))
        except Exception as e:
            raise HTTPBadRequest(detail=repr(e))

    @staticmethod
    def flatten_tree_resource(resource_node, resource_dict):
        """
        :param resource_node: any-level dictionary composing the resources tree
        :param resource_dict: reference of flattened dictionary across levels
        :return: flattened dictionary `resource_dict` of all {id: 'resource_type'}
        :rtype: dict
        """
        if type(resource_node) is not dict:
            return
        if not len(resource_node) > 0:
            return
        [ManagementViews.flatten_tree_resource(r, resource_dict) for r in resource_node.values()]
        if 'resource_id' in resource_node.keys() and 'resource_type' in resource_node.keys():
            resource_dict[resource_node['resource_id']] = resource_node['resource_type']

    @view_config(route_name='view_users', renderer='templates/view_users.mako')
    def view_users(self):
        if 'delete' in self.request.POST:
            user_name = self.request.POST.get('user_name')
            check_response(requests.delete(self.magpie_url + '/users/' + user_name, cookies=self.request.cookies))

        if 'edit' in self.request.POST:
            user_name = self.request.POST.get('user_name')
            return HTTPFound(self.request.route_url('edit_user', user_name=user_name, cur_svc_type='default'))

        return add_template_data(self.request, {'users': self.get_user_names()})

    @view_config(route_name='add_user', renderer='templates/add_user.mako')
    def add_user(self):
        users_group = get_constant('MAGPIE_USERS_GROUP')
        return_data = {u'conflict_group_name': False, u'conflict_user_name': False, u'conflict_user_email': False,
                       u'invalid_user_name': False, u'invalid_user_email': False, u'invalid_password': False,
                       u'too_long_user_name': False, u'form_user_name': u'', u'form_user_email': u'',
                       u'user_groups': self.get_all_groups(first_default_group=users_group)}
        check_data = [u'conflict_group_name', u'conflict_user_name', u'conflict_email',
                      u'invalid_user_name', u'invalid_email', u'invalid_password']

        if 'create' in self.request.POST:
            groups = self.get_all_groups()
            user_name = self.request.POST.get('user_name')
            group_name = self.request.POST.get('group_name')
            user_email = self.request.POST.get('email')
            password = self.request.POST.get('password')
            return_data[u'form_user_name'] = user_name
            return_data[u'form_user_email'] = user_email

            if group_name not in groups:
                data = {u'group_name': group_name}
                resp = requests.post('{url}/groups'.format(url=self.magpie_url), data, cookies=self.request.cookies)
                if resp.status_code == HTTPConflict.code:
                    return_data[u'conflict_group_name'] = True
            if user_email in self.get_user_emails():
                return_data[u'conflict_user_email'] = True
            if user_email == '':
                return_data[u'invalid_user_email'] = True
            if len(user_name) > get_constant('MAGPIE_USER_NAME_MAX_LENGTH'):
                return_data[u'too_long_user_name'] = True
            if user_name in self.get_user_names():
                return_data[u'conflict_user_name'] = True
            if user_name == '':
                return_data[u'invalid_user_name'] = True
            if password == '':
                return_data[u'invalid_password'] = True

            for check_fail in check_data:
                if return_data.get(check_fail, False):
                    return add_template_data(self.request, return_data)

            data = {u'user_name': user_name,
                    u'email': user_email,
                    u'password': password,
                    u'group_name': group_name}
            check_response(requests.post(self.magpie_url + '/users', data, cookies=self.request.cookies))
            return HTTPFound(self.request.route_url('view_users'))

        return add_template_data(self.request, return_data)

    @view_config(route_name='edit_user', renderer='templates/edit_user.mako')
    def edit_user(self):
        user_name = self.request.matchdict['user_name']
        cur_svc_type = self.request.matchdict['cur_svc_type']
        inherited_permissions = self.request.matchdict.get('inherited_permissions', False)

        user_url = '{url}/users/{usr}'.format(url=self.magpie_url, usr=user_name)
        own_groups = self.get_user_groups(user_name)
        all_groups = self.get_all_groups(first_default_group=get_constant('MAGPIE_USERS_GROUP'))

        error_message = None

        # Todo:
        # Until the api is modified to make it possible to request from the RemoteResource table,
        # we have to access the database directly here
        session = self.request.db

        try:
            # The service type is 'default'. This function replaces cur_svc_type with the first service type.
            svc_types, cur_svc_type, services = self.get_services(cur_svc_type)
        except Exception as e:
            raise HTTPBadRequest(detail=repr(e))

        user_resp = requests.get(user_url, cookies=self.request.cookies)
        check_response(user_resp)
        user_info = user_resp.json()['user']
        user_info[u'edit_mode'] = u'no_edit'
        user_info[u'own_groups'] = own_groups
        user_info[u'groups'] = all_groups
        user_info[u'inherited_permissions'] = inherited_permissions

        if self.request.method == 'POST':
            res_id = self.request.POST.get(u'resource_id')
            is_edit_group_membership = False
            is_save_user_info = False
            requires_update_name = False

            if u'inherited_permissions' in self.request.POST:
                inherited_permissions = str2bool(self.request.POST[u'inherited_permissions'])
                user_info[u'inherited_permissions'] = inherited_permissions

            if u'delete' in self.request.POST:
                check_response(requests.delete(user_url, cookies=self.request.cookies))
                return HTTPFound(self.request.route_url('view_users'))
            elif u'goto_service' in self.request.POST:
                return self.goto_service(res_id)
            elif u'clean_resource' in self.request.POST:
                # 'clean_resource' must be above 'edit_permissions' because they're in the same form.
                self.delete_resource(res_id)
            elif u'edit_permissions' in self.request.POST:
                if not res_id or res_id == 'None':
                    remote_id = int(self.request.POST.get('remote_id'))
                    services_names = [s['service_name'] for s in services.values()]
                    res_id = self.add_remote_resource(cur_svc_type, services_names, user_name, remote_id, is_user=True)
                self.edit_user_or_group_resource_permissions(user_name, res_id, is_user=True)
            elif u'edit_group_membership' in self.request.POST:
                is_edit_group_membership = True
            elif u'edit_username' in self.request.POST:
                user_info[u'edit_mode'] = u'edit_username'
            elif u'edit_password' in self.request.POST:
                user_info[u'edit_mode'] = u'edit_password'
            elif u'edit_email' in self.request.POST:
                user_info[u'edit_mode'] = u'edit_email'
            elif u'save_username' in self.request.POST:
                user_info[u'user_name'] = self.request.POST.get(u'new_user_name')
                is_save_user_info = True
                requires_update_name = True
            elif u'save_password' in self.request.POST:
                user_info[u'password'] = self.request.POST.get(u'new_user_password')
                is_save_user_info = True
            elif u'save_email' in self.request.POST:
                user_info[u'email'] = self.request.POST.get(u'new_user_email')
                is_save_user_info = True
            elif u'force_sync' in self.request.POST:
                errors = []
                for service_info in services.values():
                    try:
                        sync_resources.fetch_single_service(service_info['resource_id'], session)
                    except Exception:
                        errors.append(service_info['service_name'])
                if errors:
                    error_message += self.make_sync_error_message(errors)
            elif u'clean_all' in self.request.POST:
                ids_to_clean = self.request.POST.get('ids_to_clean').split(";")
                for id_ in ids_to_clean:
                    self.delete_resource(id_)

            if is_save_user_info:
                check_response(requests.put(user_url, data=user_info, cookies=self.request.cookies))

            # always remove password from output
            user_info.pop(u'password', None)

            if requires_update_name:
                # re-fetch user groups as current user-group will have changed on new user_name
                user_info[u'own_groups'] = self.get_user_groups(user_info[u'user_name'])
                # return immediately with updated URL to user with new name
                return HTTPFound(self.request.route_url('edit_user', **user_info))

            # edits to groups checkboxes
            if is_edit_group_membership:
                selected_groups = self.request.POST.getall('member')
                removed_groups = list(set(own_groups) - set(selected_groups))
                new_groups = list(set(selected_groups) - set(own_groups))
                for group in removed_groups:
                    url_group = '{url}/users/{usr}/groups/{grp}'.format(url=self.magpie_url, usr=user_name, grp=group)
                    check_response(requests.delete(url_group, cookies=self.request.cookies))
                for group in new_groups:
                    url_group = '{url}/users/{usr}/groups'.format(url=self.magpie_url, usr=user_name)
                    data = {'group_name': group}
                    check_response(requests.post(url_group, data=data, cookies=self.request.cookies))
                user_info[u'own_groups'] = self.get_user_groups(user_name)

        # display resources permissions per service type tab
        try:
            res_perm_names, res_perms = self.get_user_or_group_resources_permissions_dict(
                user_name, services, cur_svc_type, is_user=True, is_inherited_permissions=inherited_permissions)
        except Exception as e:
            raise HTTPBadRequest(detail=repr(e))

        sync_types = [s["service_sync_type"] for s in services.values()]
        sync_implemented = any(s in sync_resources.SYNC_SERVICES_TYPES for s in sync_types)

        info = self.get_remote_resources_info(res_perms, services, session)
        res_perms, ids_to_clean, last_sync_humanized, out_of_sync = info

        if out_of_sync:
            error_message = self.make_sync_error_message(out_of_sync)

        user_info[u'error_message'] = error_message
        user_info[u'ids_to_clean'] = ";".join(ids_to_clean)
        user_info[u'last_sync'] = last_sync_humanized
        user_info[u'sync_implemented'] = sync_implemented
        user_info[u'out_of_sync'] = out_of_sync
        user_info[u'cur_svc_type'] = cur_svc_type
        user_info[u'svc_types'] = svc_types
        user_info[u'resources'] = res_perms
        user_info[u'permissions'] = res_perm_names

        return add_template_data(self.request, data=user_info)

    @view_config(route_name='view_groups', renderer='templates/view_groups.mako')
    def view_groups(self):
        if 'delete' in self.request.POST:
            group_name = self.request.POST.get('group_name')
            check_response(requests.delete('{url}/groups/{grp}'.format(url=self.magpie_url, grp=group_name),
                                           cookies=self.request.cookies))

        if 'edit' in self.request.POST:
            group_name = self.request.POST.get('group_name')
            return HTTPFound(self.request.route_url('edit_group', group_name=group_name, cur_svc_type='default'))

        groups_info = {}
        groups = sorted(self.get_all_groups())
        [groups_info.setdefault(grp, {u'members': len(self.get_group_users(grp))}) for grp in groups if grp != u'']

        return add_template_data(self.request, {u'group_names': groups_info})

    @view_config(route_name='add_group', renderer='templates/add_group.mako')
    def add_group(self):
        return_data = {u'conflict_group_name': False, u'invalid_group_name': False, u'form_group_name': u''}

        if 'create' in self.request.POST:
            group_name = self.request.POST.get('group_name')
            return_data[u'form_group_name'] = group_name
            if group_name == '':
                return_data[u'invalid_group_name'] = True
                return add_template_data(self.request, return_data)

            data = {u'group_name': group_name}
            resp = requests.post(self.magpie_url + '/groups', data, cookies=self.request.cookies)
            if resp.status_code == HTTPConflict.code:
                return_data[u'conflict_group_name'] = True
                return add_template_data(self.request, return_data)

            check_response(resp)  # check for any other exception than conflict
            return HTTPFound(self.request.route_url('view_groups'))

        return add_template_data(self.request, return_data)

    def resource_tree_parser(self, raw_resources_tree, permission):
        resources_tree = {}
        for r_id, resource in raw_resources_tree.items():
            perm_names = self.default_get(permission, r_id, [])
            children = self.resource_tree_parser(resource['children'], permission)
            children = OrderedDict(sorted(children.items()))
            resources_tree[resource['resource_name']] = dict(id=r_id, permission_names=perm_names, children=children)
        return resources_tree

    def perm_tree_parser(self, raw_perm_tree):
        permission = {}
        for r_id, resource in raw_perm_tree.items():
            permission[r_id] = resource['permission_names']
            permission.update(self.perm_tree_parser(resource['children']))
        return permission

    @staticmethod
    def default_get(dictionary, key, default):
        try:
            return dictionary[key]
        except KeyError:
            return default

    def edit_group_users(self, group_name):
        current_members = self.get_group_users(group_name)
        selected_members = self.request.POST.getall('member')
        removed_members = list(set(current_members) - set(selected_members))
        new_members = list(set(selected_members) - set(current_members))

        for user_name in removed_members:
            url_group = '{url}/users/{usr}/groups/{grp}'.format(url=self.magpie_url, usr=user_name, grp=group_name)
            check_response(requests.delete(url_group, cookies=self.request.cookies))
        for user_name in new_members:
            url_group = '{url}/users/{usr}/groups'.format(url=self.magpie_url, usr=user_name)
            data = {'group_name': group_name}
            check_response(requests.post(url_group, data=data, cookies=self.request.cookies))

    def edit_user_or_group_resource_permissions(self, user_or_group_name, resource_id, is_user=False):
        usr_grp_type = 'users' if is_user else 'groups'
        res_perms_url = '{url}/{grp_type}/{grp}/resources/{res_id}/permissions' \
            .format(url=self.magpie_url, grp_type=usr_grp_type, grp=user_or_group_name, res_id=resource_id)
        try:
            res_perms_resp = requests.get(res_perms_url, cookies=self.request.cookies)
            res_perms = res_perms_resp.json()['permission_names']
        except Exception as e:
            raise HTTPBadRequest(detail=repr(e))

        selected_perms = self.request.POST.getall('permission')

        removed_perms = list(set(res_perms) - set(selected_perms))
        new_perms = list(set(selected_perms) - set(res_perms))

        for perm in removed_perms:
            del_perm_url = '{url}/{perm}'.format(url=res_perms_url, perm=perm)
            check_response(requests.delete(del_perm_url, cookies=self.request.cookies))
        for perm in new_perms:
            data = {u'permission_name': perm}
            check_response(requests.post(res_perms_url, data=data, cookies=self.request.cookies))

    def get_user_or_group_resources_permissions_dict(self, user_or_group_name, services, service_type,
                                                     is_user=False, is_inherited_permissions=False):
        user_or_group_type = 'users' if is_user else 'groups'
        inherit_type = 'inherited_' if is_inherited_permissions and is_user else ''

        group_perms_url = '{url}/{usr_grp_type}/{usr_grp}/{inherit}resources' \
            .format(url=self.magpie_url, usr_grp_type=user_or_group_type,
                    usr_grp=user_or_group_name, inherit=inherit_type)
        resp_group_perms = check_response(requests.get(group_perms_url, cookies=self.request.cookies))
        resp_group_perms_json = resp_group_perms.json()

        svc_perm_url = '{url}/services/types/{svc_type}'.format(url=self.magpie_url, svc_type=service_type)
        resp_svc_type = check_response(requests.get(svc_perm_url, cookies=self.request.cookies))
        resp_available_svc_types = resp_svc_type.json()['services'][service_type]

        # remove possible duplicate permissions from different services
        resources_permission_names = set()
        for svc in resp_available_svc_types:
            resources_permission_names.update(set(resp_available_svc_types[svc]['permission_names']))
        # inverse sort so that displayed permissions are sorted, since added from right to left in tree view
        resources_permission_names = sorted(resources_permission_names, reverse=True)

        resources = OrderedDict()
        for service in sorted(services):
            if not service:
                continue

            permission = OrderedDict()
            try:
                raw_perms = resp_group_perms_json['resources'][service_type][service]
                permission[raw_perms['resource_id']] = raw_perms['permission_names']
                permission.update(self.perm_tree_parser(raw_perms['resources']))
            except KeyError:
                pass

            resp_resources = check_response(requests.get('{url}/services/{svc}/resources'
                                                         .format(url=self.magpie_url, svc=service),
                                                         cookies=self.request.cookies))
            raw_resources = resp_resources.json()[service]
            resources[service] = OrderedDict(
                id=raw_resources['resource_id'],
                permission_names=self.default_get(permission, raw_resources['resource_id'], []),
                children=self.resource_tree_parser(raw_resources['resources'], permission))
        return resources_permission_names, resources

    @view_config(route_name='edit_group', renderer='templates/edit_group.mako')
    def edit_group(self):
        group_name = self.request.matchdict['group_name']
        cur_svc_type = self.request.matchdict['cur_svc_type']
        group_info = {u'edit_mode': u'no_edit', u'group_name': group_name, u'cur_svc_type': cur_svc_type}

        error_message = ""

        # Todo:
        # Until the api is modified to make it possible to request from the RemoteResource table,
        # we have to access the database directly here
        session = self.request.db

        try:
            # The service type is 'default'. This function replaces cur_svc_type with the first service type.
            svc_types, cur_svc_type, services = self.get_services(cur_svc_type)
        except Exception as e:
            raise HTTPBadRequest(detail=repr(e))

        # move to service or edit requested group/permission changes
        if self.request.method == 'POST':
            res_id = self.request.POST.get('resource_id')
            group_url = '{url}/groups/{grp}'.format(url=self.magpie_url, grp=group_name)

            if u'delete' in self.request.POST:
                check_response(requests.delete(group_url, cookies=self.request.cookies))
                return HTTPFound(self.request.route_url('view_groups'))
            elif u'edit_group_name' in self.request.POST:
                group_info[u'edit_mode'] = u'edit_group_name'
            elif u'save_group_name' in self.request.POST:
                group_info[u'group_name'] = self.request.POST.get(u'new_group_name')
                check_response(requests.put(group_url, data=group_info, cookies=self.request.cookies))
                # return immediately with updated URL to group with new name
                return HTTPFound(self.request.route_url('edit_group', **group_info))
            elif u'goto_service' in self.request.POST:
                return self.goto_service(res_id)
            elif u'clean_resource' in self.request.POST:
                # 'clean_resource' must be above 'edit_permissions' because they're in the same form.
                self.delete_resource(res_id)
            elif u'edit_permissions' in self.request.POST:
                if not res_id or res_id == 'None':
                    remote_id = int(self.request.POST.get('remote_id'))
                    services_names = [s['service_name'] for s in services.values()]
                    res_id = self.add_remote_resource(cur_svc_type, services_names, group_name, remote_id, is_user=False)
                self.edit_user_or_group_resource_permissions(group_name, res_id, is_user=False)
            elif u'member' in self.request.POST:
                self.edit_group_users(group_name)
            elif u'force_sync' in self.request.POST:
                errors = []
                for service_info in services.values():
                    try:
                        sync_resources.fetch_single_service(service_info['resource_id'], session)
                    except Exception:
                        errors.append(service_info['service_name'])
                if errors:
                    error_message += self.make_sync_error_message(errors)

            elif u'clean_all' in self.request.POST:
                ids_to_clean = self.request.POST.get('ids_to_clean').split(";")
                for id_ in ids_to_clean:
                    self.delete_resource(id_)
            else:
                return HTTPBadRequest(detail="Invalid POST request.")

        # display resources permissions per service type tab
        try:
            res_perm_names, res_perms = self.get_user_or_group_resources_permissions_dict(group_name, services,
                                                                                          cur_svc_type, is_user=False)
        except Exception as e:
            raise HTTPBadRequest(detail=repr(e))

        sync_types = [s["service_sync_type"] for s in services.values()]
        sync_implemented = any(s in sync_resources.SYNC_SERVICES_TYPES for s in sync_types)

        info = self.get_remote_resources_info(res_perms, services, session)
        res_perms, ids_to_clean, last_sync_humanized, out_of_sync = info

        if out_of_sync:
            error_message = self.make_sync_error_message(out_of_sync)

        group_info[u'error_message'] = error_message
        group_info[u'ids_to_clean'] = ";".join(ids_to_clean)
        group_info[u'last_sync'] = last_sync_humanized
        group_info[u'sync_implemented'] = sync_implemented
        group_info[u'out_of_sync'] = out_of_sync
        group_info[u'group_name'] = group_name
        group_info[u'cur_svc_type'] = cur_svc_type
        group_info[u'users'] = self.get_user_names()
        group_info[u'members'] = self.get_group_users(group_name)
        group_info[u'svc_types'] = svc_types
        group_info[u'cur_svc_type'] = cur_svc_type
        group_info[u'resources'] = res_perms
        group_info[u'permissions'] = res_perm_names
        return add_template_data(self.request, data=group_info)

    def make_sync_error_message(self, service_names):
        this = "this service" if len(service_names) == 1 else "these services"
        error_message = ("There seems to be an issue synchronizing resources from "
                         "{}: {}".format(this, ", ".join(service_names)))
        return error_message

    def get_remote_resources_info(self, res_perms, services, session):
        last_sync_humanized = "Never"
        ids_to_clean, out_of_sync = [], []
        now = datetime.datetime.now()

        service_ids = [s["resource_id"] for s in services.values()]
        last_sync_datetimes = self.get_last_sync_datetimes(service_ids, session)

        if any(last_sync_datetimes):
            last_sync_datetime = min(filter(bool, last_sync_datetimes))
            last_sync_humanized = humanize.naturaltime(now - last_sync_datetime)
            res_perms = self.merge_remote_resources(res_perms, services, session)

        for last_sync, service_name in zip(last_sync_datetimes, services):
            if last_sync:
                ids_to_clean += self.get_ids_to_clean(res_perms[service_name]["children"])
                if now - last_sync > OUT_OF_SYNC:
                    out_of_sync.append(service_name)
        return res_perms, ids_to_clean, last_sync_humanized, out_of_sync

    def merge_remote_resources(self, res_perms, services, session):
        merged_resources = {}
        for service_name, service_values in services.items():
            service_id = service_values["resource_id"]
            merge = sync_resources.merge_local_and_remote_resources
            resources_for_service = merge(res_perms, service_values["service_sync_type"], service_id, session)
            merged_resources[service_name] = resources_for_service[service_name]
        return merged_resources

    def get_last_sync_datetimes(self, service_ids, session):
        return [sync_resources.get_last_sync(s, session) for s in service_ids]

    def delete_resource(self, res_id):
        url = '{url}/resources/{resource_id}'.format(url=self.magpie_url, resource_id=res_id)
        try:
            check_response(requests.delete(url, cookies=self.request.cookies))
        except HTTPNotFound:
            # Some resource ids are already deleted because they were a child
            # of another just deleted parent resource.
            # We just skip them.
            pass

    def get_ids_to_clean(self, resources):
        ids = []
        for resource_name, values in resources.items():
            if "matches_remote" in values and not values["matches_remote"]:
                ids.append(values['id'])
            ids += self.get_ids_to_clean(values['children'])
        return ids

    def add_remote_resource(self, service_type, services_names, user_or_group, remote_id, is_user=False):
        try:
            res_perm_names, res_perms = self.get_user_or_group_resources_permissions_dict(user_or_group,
                                                                                          services=services_names,
                                                                                          service_type=service_type,
                                                                                          is_user=is_user)
        except Exception as e:
            raise HTTPBadRequest(detail=repr(e))

        # Todo:
        # Until the api is modified to make it possible to request from the RemoteResource table,
        # we have to access the database directly here
        session = self.request.db

        # get the parent resources for this remote_id
        parents = remote_resource_tree_service.path_upper(remote_id, db_session=session)
        parents = list(reversed(list(parents)))

        parent_id = None
        current_resources = res_perms
        for remote_resource in parents:
            name = remote_resource.resource_name
            if name in current_resources:
                parent_id = current_resources[name]['id']
                current_resources = current_resources[name]['children']
            else:
                data = {
                    'resource_name': name,
                    'resource_type': remote_resource.resource_type,
                    'parent_id': parent_id,
                }
                resources_url = '{url}/resources'.format(url=self.magpie_url)
                response = check_response(requests.post(resources_url, data=data, cookies=self.request.cookies))
                parent_id = response.json()['resource']['resource_id']

        return parent_id

    @view_config(route_name='view_services', renderer='templates/view_services.mako')
    def view_services(self):
        if 'delete' in self.request.POST:
            service_name = self.request.POST.get('service_name')
            service_data = {u'service_push': self.request.POST.get('service_push')}
            check_response(requests.delete(self.magpie_url + '/services/' + service_name,
                                           data=json.dumps(service_data), cookies=self.request.cookies))

        cur_svc_type = self.request.matchdict['cur_svc_type']
        svc_types, cur_svc_type, services = self.get_services(cur_svc_type)
        service_names = services.keys()

        success_sync = None
        if 'phoenix_push' in self.request.POST:
            if cur_svc_type in register.SERVICES_PHOENIX_ALLOWED:
                success_sync = register.sync_services_phoenix(services, services_as_dicts=True)

        if 'edit' in self.request.POST:
            service_name = self.request.POST.get('service_name')
            return HTTPFound(self.request.route_url('edit_service',
                                                    service_name=service_name,
                                                    cur_svc_type=cur_svc_type))

        return add_template_data(self.request,
                                 {u'cur_svc_type': cur_svc_type,
                                  u'svc_types': svc_types,
                                  u'service_names': service_names,
                                  u'service_push_show': cur_svc_type in register.SERVICES_PHOENIX_ALLOWED,
                                  u'service_push_success': success_sync})

    @view_config(route_name='add_service', renderer='templates/add_service.mako')
    def add_service(self):
        cur_svc_type = self.request.matchdict['cur_svc_type']
        svc_types, cur_svc_type, services = self.get_services(cur_svc_type)

        if 'register' in self.request.POST:
            service_name = self.request.POST.get('service_name')
            service_url = self.request.POST.get('service_url')
            service_type = self.request.POST.get('service_type')
            service_push = self.request.POST.get('service_push')
            data = {u'service_name': service_name,
                    u'service_url': service_url,
                    u'service_type': service_type,
                    u'service_push': service_push}
            check_response(requests.post(self.magpie_url + '/services', data=data, cookies=self.request.cookies))
            return HTTPFound(self.request.route_url('view_services', cur_svc_type=service_type))

        services_keys_sorted = sorted(service_type_dict)
        services_phoenix_indices = [(1 if services_keys_sorted[i] in register.SERVICES_PHOENIX_ALLOWED else 0)
                                    for i in range(len(services_keys_sorted))]
        return add_template_data(self.request,
                                 {u'cur_svc_type': cur_svc_type,
                                  u'service_types': svc_types,
                                  u'services_phoenix': register.SERVICES_PHOENIX_ALLOWED,
                                  u'services_phoenix_indices': services_phoenix_indices})

    @view_config(route_name='edit_service', renderer='templates/edit_service.mako')
    def edit_service(self):
        cur_svc_type = self.request.matchdict['cur_svc_type']
        service_name = self.request.matchdict['service_name']
        service_data = self.get_service_data(service_name)
        service_url = service_data['service_url']
        service_perm = service_data['permission_names']
        service_id = service_data['resource_id']
        # apply default state if arriving on the page for the first time
        # future editions on the page will transfer the last saved state
        service_push_show = cur_svc_type in register.SERVICES_PHOENIX_ALLOWED
        service_push = str2bool(self.request.POST.get('service_push', service_push_show))

        service_info = {u'edit_mode': u'no_edit', u'service_name': service_name, u'service_url': service_url,
                        u'public_url': register.get_twitcher_protected_service_url(service_name),
                        u'service_perm': service_perm, u'service_id': service_id, u'service_push': service_push,
                        u'service_push_show': service_push_show, u'cur_svc_type': cur_svc_type}

        if 'edit_name' in self.request.POST:
            service_info['edit_mode'] = u'edit_name'

        if 'save_name' in self.request.POST:
            new_svc_name = self.request.POST.get('new_svc_name')
            if service_name != new_svc_name and new_svc_name != "":
                self.update_service_name(service_name, new_svc_name, service_push)
                service_info['service_name'] = new_svc_name
                service_info['public_url'] = register.get_twitcher_protected_service_url(new_svc_name),
            service_info['edit_mode'] = u'no_edit'
            # return directly to 'regenerate' the URL with the modified name
            return HTTPFound(self.request.route_url('edit_service', **service_info))

        if 'edit_url' in self.request.POST:
            service_info['edit_mode'] = u'edit_url'

        if 'save_url' in self.request.POST:
            new_svc_url = self.request.POST.get('new_svc_url')
            if service_url != new_svc_url and new_svc_url != "":
                self.update_service_url(service_name, new_svc_url, service_push)
                service_info['service_url'] = new_svc_url
            service_info['edit_mode'] = u'no_edit'

        if 'delete' in self.request.POST:
            service_data = json.dumps({u'service_push': service_push})
            check_response(requests.delete('{url}/services/{svc}'.format(url=self.magpie_url, svc=service_name),
                                           data=service_data, cookies=self.request.cookies))
            return HTTPFound(self.request.route_url('view_services', **service_info))

        if 'delete_child' in self.request.POST:
            resource_id = self.request.POST.get('resource_id')
            check_response(requests.delete('{url}/resources/{res_id}'.format(url=self.magpie_url, res_id=resource_id),
                                           cookies=self.request.cookies))

        if 'add_child' in self.request.POST:
            service_info['resource_id'] = self.request.POST.get('resource_id')
            return HTTPFound(self.request.route_url('add_resource', **service_info))

        try:
            resources = {}
            url_resources = '{url}/services/{svc}/resources'.format(url=self.magpie_url, svc=service_name)
            res_resources = check_response(requests.get(url_resources, cookies=self.request.cookies))
            raw_resources = res_resources.json()[service_name]
            resources[service_name] = dict(
                id=raw_resources['resource_id'],
                permission_names=[],
                children=self.resource_tree_parser(raw_resources['resources'], {}))
            raw_resources_id_type = self.get_resource_types()
        except Exception as e:
            raise HTTPBadRequest(detail='Bad Json response [Exception: ' + repr(e) + ']')

        service_info['resources'] = resources
        service_info['resources_id_type'] = raw_resources_id_type
        service_info['resources_no_child'] = [res for res in resource_type_dict
                                              if not resource_type_dict[res].child_resource_allowed]
        service_info['service_no_child'] = not service_type_dict[cur_svc_type].child_resource_allowed
        return add_template_data(self.request, service_info)

    @view_config(route_name='add_resource', renderer='templates/add_resource.mako')
    def add_resource(self):
        cur_svc_type = self.request.matchdict['cur_svc_type']
        service_name = self.request.matchdict['service_name']
        resource_id = self.request.matchdict['resource_id']

        if 'add_child' in self.request.POST:
            resource_name = self.request.POST.get('resource_name')
            resource_type = self.request.POST.get('resource_type')

            data = {u'resource_name': resource_name,
                    u'resource_type': resource_type,
                    u'parent_id': resource_id}

            check_response(requests.post('{url}/resources'.format(url=self.magpie_url),
                                         data=data, cookies=self.request.cookies))

            return HTTPFound(self.request.route_url('edit_service', service_name=service_name,
                                                    cur_svc_type=cur_svc_type))

        res_types_url = '{url}/services/types/{type}/resources/types'.format(url=self.magpie_url, type=cur_svc_type)
        cur_svc_res = check_response(requests.get(res_types_url, cookies=self.request.cookies))
        raw_svc_res = cur_svc_res.json()['resource_types']

        return add_template_data(self.request,
                                 {u'service_name': service_name,
                                  u'cur_svc_type': cur_svc_type,
                                  u'resource_id': resource_id,
                                  u'cur_svc_res': raw_svc_res})
