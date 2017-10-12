import requests
from pyramid.view import view_config
from pyramid.httpexceptions import exception_response
from pyramid.httpexceptions import (
    HTTPFound,
    HTTPOk,
    HTTPTemporaryRedirect,
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPNotFound
)
from ui.management import check_res
from ui.home import add_template_data


class ManagementViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = self.request.registry.settings['magpie.url']

    def create_group(self, group_name):
        data = {u'group_name': group_name}
        check_res(requests.post(self.magpie_url + '/groups', data))

    def get_groups(self):
        res_groups = requests.get(self.magpie_url + '/groups')
        try:
            return res_groups.json()['group_names']
        except Exception:
            raise HTTPBadRequest(detail='Bad Json response')

    def get_group_users(self, group_name):
        try:
            res_group_users = requests.get(self.magpie_url + '/groups/' + group_name + '/users')
            check_res(res_group_users)
            return res_group_users.json()['user_names']
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def get_user_groups(self, user_name):
        try:
            res_user_groups = requests.get(self.magpie_url + '/users/' + user_name + '/groups')
            check_res(res_user_groups)
            return res_user_groups.json()['group_names']
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def get_users(self):
        res_users = requests.get(self.magpie_url + '/users')
        try:
            return res_users.json()['user_names']
        except Exception as e:
            raise HTTPBadRequest(detail=e.message)

    def get_resource_types(self):
        """
        :return: dictionary of all resources as {id: 'resource_type'}
        :rtype: dict
        """
        all_res = requests.get(self.magpie_url + '/resources')
        check_res(all_res)
        res_dic = self.default_get(all_res.json(), 'resources', dict())
        res_ids = dict()
        self.flatten_tree_resource(res_dic, res_ids)
        return res_ids

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
        if 'create' in self.request.POST:
            groups = self.get_groups()
            user_name = self.request.POST.get('user_name')
            group_name = self.request.POST.get('group_name')
            if group_name not in groups:
                self.create_group(group_name)

            data = {u'user_name': user_name,
                    u'email': self.request.POST.get('email'),
                    u'password': self.request.POST.get('password'),
                    u'group_name': group_name}
            check_res(requests.post(self.magpie_url+'/users', data))

        if 'delete' in self.request.POST:
            user_name = self.request.POST.get('user_name')
            #TODO: Magpie needs to remove the group automatically created with the user_name
            check_res(requests.delete(self.magpie_url + '/users/' + user_name))

        if 'edit' in self.request.POST:
            user_name = self.request.POST.get('user_name')
            return HTTPFound(self.request.route_url('edit_user', user_name=user_name))

        return add_template_data(self.request, {'users': self.get_users()})

    @view_config(route_name='add_user', renderer='templates/add_user.mako')
    def add_user(self):
        if 'create' in self.request.POST:
            groups = self.get_groups()
            user_name = self.request.POST.get('user_name')
            group_name = self.request.POST.get('group_name')
            if group_name not in groups:
                self.create_group(group_name)

            data = {u'user_name': user_name,
                    u'email': self.request.POST.get('email'),
                    u'password': self.request.POST.get('password'),
                    u'group_name': group_name}
            check_res(requests.post(self.magpie_url + '/users', data))
            return HTTPFound(self.request.route_url('view_users'))

        return add_template_data(self.request,
                                 {u'user_groups': self.get_groups()})

    @view_config(route_name='edit_user', renderer='templates/edit_user.mako')
    def edit_user(self):
        user_name = self.request.matchdict['user_name']
        own_groups = self.get_user_groups(user_name)

        if self.request.method == 'POST':
            groups = self.request.POST.getall('member')

            removed_groups = list(set(own_groups) - set(groups))
            new_groups = list(set(groups) - set(own_groups))

            for group in removed_groups:
                check_res(requests.delete(self.magpie_url + '/users/' + user_name + '/groups/' + group))

            for group in new_groups:
                check_res(requests.post(self.magpie_url+'/users/' + user_name + '/groups/' + group))

            own_groups = self.get_user_groups(user_name)

        return add_template_data(self.request,
                                 {u'user_name': user_name,
                                  u'own_groups': own_groups,
                                  u'groups': self.get_groups()})

    @view_config(route_name='view_groups', renderer='templates/view_groups.mako')
    def view_groups(self):
        if 'delete' in self.request.POST:
            group_name = self.request.POST.get('group_name')
            check_res(requests.delete(self.magpie_url+'/groups/'+group_name))

        if 'edit' in self.request.POST:
            group_name = self.request.POST.get('group_name')
            return HTTPFound(self.request.route_url('edit_group', group_name=group_name, cur_svc_type='default'))

        groups_info = {}
        groups = self.get_groups()
        for group in groups:
            groups_info[group] = {u'members': len(self.get_group_users(group))}

        return add_template_data(self.request, {'group_names': groups_info})

    @view_config(route_name='add_group', renderer='templates/add_group.mako')
    def add_group(self):
        if 'create' in self.request.POST:
            group_name = self.request.POST.get('group_name')

            self.create_group(group_name)
            return HTTPFound(self.request.route_url('view_groups'))

        return add_template_data(self.request)

    def res_tree_parser(self, raw_resources_tree, permission):
        resources_tree = {}
        for r_id, resource in raw_resources_tree.items():
            resources_tree[resource['resource_name']] = dict(id=r_id,
                                                             permission_names=self.default_get(permission, r_id, []),
                                                             children=self.res_tree_parser(resource['children'], permission))
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

    @view_config(route_name='edit_group', renderer='templates/edit_group.mako')
    def edit_group(self):
        group_name = self.request.matchdict['group_name']
        cur_svc_type = self.request.matchdict['cur_svc_type']
        members = self.get_group_users(group_name)

        if self.request.method == 'POST':
            #self.request.session['edit_group_offset'] = window.pageYOffset

            if 'resource_id' in self.request.POST:
                res_id = self.request.POST.get('resource_id')

                try:
                    res_perms = requests.get(self.magpie_url + '/groups/' + group_name + '/resources/{resource_id}/permissions'.format(resource_id=res_id))
                    perms = res_perms.json()['permission_names']
                except:
                    raise HTTPBadRequest(detail='Bad Json response')

                new_perms_set = self.request.POST.getall('permission')

                removed_perms = list(set(perms) - set(new_perms_set))
                new_perms = list(set(new_perms_set) - set(perms))

                url = '{host}/groups/{group}/resources/{res_id}/permissions'.format(
                    host=self.magpie_url,
                    group=group_name,
                    res_id=res_id)
                for perm in removed_perms:
                    check_res(requests.delete(url + '/' + perm))

                for perm in new_perms:
                    data = {u'permission_name': perm}
                    check_res(requests.post(url, data=data))

                members = self.get_group_users(group_name)
            else:
                new_members_set = self.request.POST.getall('member')

                removed_members = list(set(members) - set(new_members_set))
                new_members = list(set(new_members_set) - set(members))

                for user in removed_members:
                    check_res(requests.delete(self.magpie_url + '/users/' + user + '/groups/' + group_name))

                for user in new_members:
                    check_res(requests.post(self.magpie_url+'/users/' + user + '/groups/' + group_name))

                members = self.get_group_users(group_name)
        #elif 'edit_group_offset' in self.request.session:
        #    #window.scrollTo(0, self.request.session['edit_group_offset']);
        #    self.request.session['edit_group_offset'] = 0

        try:
            svc_types, cur_svc_type, services = self.get_services(cur_svc_type)
            perms = set()
            resources = {}
            for service in services:
                if not service:
                    continue

                res_svc = check_res(requests.get(self.magpie_url + '/services/' + service + '/permissions'))
                perms.update(set(res_svc.json()['permission_names']))

                res_group_perms = check_res(requests.get(self.magpie_url + '/groups/' + group_name + '/resources'))
                permission = {}
                try:
                    raw_perms = res_group_perms.json()['resources'][cur_svc_type][service]
                    permission[raw_perms['resource_id']] = raw_perms['permission_names']
                    permission.update(self.perm_tree_parser(raw_perms['resources']))
                except KeyError:
                    pass

                res_resources = check_res(requests.get(self.magpie_url + '/services/' + service + '/resources'))
                raw_resources = res_resources.json()[service]
                resources[service] = dict(id=raw_resources['resource_id'],
                                          permission_names=self.default_get(permission, raw_resources['resource_id'], []),
                                          children=self.res_tree_parser(raw_resources['resources'], permission))
        except Exception as e:
            raise HTTPBadRequest(detail='Bad Json response')

        return add_template_data(self.request,
                                 {u'group_name': group_name,
                                  u'users': self.get_users(),
                                  u'members': members,
                                  u'svc_types': svc_types,
                                  u'cur_svc_type': cur_svc_type,
                                  u'resources': resources,
                                  u'permissions': list(perms)})

    @view_config(route_name='view_services', renderer='templates/view_services.mako')
    def view_services(self):
        if 'delete' in self.request.POST:
            service_name = self.request.POST.get('service_name')
            check_res(requests.delete(self.magpie_url + '/services/' + service_name))

        cur_svc_type = self.request.matchdict['cur_svc_type']
        svc_types, cur_svc_type, services = self.get_services(cur_svc_type)
        service_names = services.keys()

        if 'edit' in self.request.POST:
            service_name = self.request.POST.get('service_name')
            return HTTPFound(self.request.route_url('edit_service', service_name=service_name, cur_svc_type=cur_svc_type))

        return add_template_data(self.request,
                                 {'cur_svc_type': cur_svc_type,
                                  'svc_types': svc_types,
                                  'service_names': service_names})

    @view_config(route_name='add_service', renderer='templates/add_service.mako')
    def add_service(self):
        cur_svc_type = self.request.matchdict['cur_svc_type']
        svc_types, cur_svc_type, services = self.get_services(cur_svc_type)
        if 'register' in self.request.POST:
            service_name = self.request.POST.get('service_name')
            service_url = self.request.POST.get('service_url')
            service_type = self.request.POST.get('service_type')

            data = {'service_name': service_name,
                    'service_url': service_url,
                    'service_type': service_type}

            check_res(requests.post(self.magpie_url+'/services', data=data))

            return HTTPFound(self.request.route_url('view_services', cur_svc_type=service_type))

        return add_template_data(self.request,
                                 {'cur_svc_type': cur_svc_type,
                                  'service_types': svc_types})

    @view_config(route_name='edit_service', renderer='templates/edit_service.mako')
    def edit_service(self):
        cur_svc_type = self.request.matchdict['cur_svc_type']
        service_name = self.request.matchdict['service_name']

        if 'delete' in self.request.POST:
            resource_id = self.request.POST.get('resource_id')
            check_res(requests.delete(self.magpie_url + '/resources/' + resource_id))

        if 'add_child' in self.request.POST:
            resource_id = self.request.POST.get('resource_id')
            return HTTPFound(self.request.route_url('add_resource',
                                                    service_name=service_name,
                                                    cur_svc_type=cur_svc_type,
                                                    resource_id=resource_id))

        try:
            resources = {}
            res_resources = check_res(requests.get(self.magpie_url + '/services/' + service_name + '/resources'))
            raw_resources = res_resources.json()[service_name]
            resources[service_name] = dict(
                id=raw_resources['resource_id'],
                permission_names=[],
                children=self.res_tree_parser(raw_resources['resources'], {}))
            res_resources_types = check_res(requests.get(self.magpie_url + '/services/types/' +
                                                         cur_svc_type + '/resources/types'))
            raw_resources_types = res_resources_types.json()['resource_types']
            raw_resources_id_type = self.get_resource_types()
        except Exception as e:
            raise HTTPBadRequest(detail='Bad Json response [Exception: ' + e.message + ']')

        return add_template_data(self.request,
                                 {u'edit_mode': edit_mode,
                                  u'service_name': service_name,
                                  u'service_url': service_url,
                                  u'service_perm': service_perm,
                                  u'service_id': service_id,
                                  u'cur_svc_type': cur_svc_type,
                                  u'resources': resources,
                                  u'resources_types': raw_resources_types,
                                  u'resources_id_type': raw_resources_id_type,
                                  u'resources_no_child': {u'file'}})

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

            check_res(requests.post(self.magpie_url + '/resources', data=data))

            return HTTPFound(self.request.route_url('edit_service', service_name=service_name, cur_svc_type=cur_svc_type))

        cur_svc_res = check_res(requests.get(self.magpie_url + '/services/types/' + cur_svc_type + '/resources/types'))
        raw_svc_res = cur_svc_res.json()['resource_types']

        return add_template_data(self.request,
                                 {u'service_name': service_name,
                                  u'cur_svc_type': cur_svc_type,
                                  u'resource_id': resource_id,
                                  u'cur_svc_res': raw_svc_res})
