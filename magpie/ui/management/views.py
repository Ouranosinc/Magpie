import requests
from pyramid.view import view_config
from management import check_res
from home import add_template_data
from pyramid.httpexceptions import (
    HTTPFound,
    HTTPOk,
    HTTPTemporaryRedirect,
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPNotFound
)


class ManagementViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = self.request.registry.settings['magpie.url']

    def create_group(self, group_name):
        data = {'group_name': group_name}
        check_res(requests.post(self.magpie_url + '/groups', data))

    def get_groups(self):
        res_groups = requests.get(self.magpie_url + '/groups')
        try:
            return res_groups.json()['group_names']
        except:
            raise HTTPBadRequest(detail='Bad Json response')
        return []

    def get_user_groups(self, user_name):
        try:
            res_user_groups = requests.get(self.magpie_url + '/users/' + user_name + '/groups')
            check_res(res_user_groups)
            return res_user_groups.json()['group_names']
        except:
            raise HTTPBadRequest(detail='Bad Json response')
        return []

    def get_users(self):
        res_users = requests.get(self.magpie_url + '/users')
        try:
            return res_users.json()['user_names']
        except:
            raise HTTPBadRequest(detail='Bad Json response')
        return []

    @view_config(route_name='view_users', renderer='templates/view_users.mako')
    def view_users(self):
        if 'create' in self.request.POST:
            groups = self.get_groups()
            user_name = self.request.POST.get('user_name')
            group_name = self.request.POST.get('group_name')
            if group_name not in groups:
                self.create_group(group_name)

            data = {'user_name': user_name,
                    'email': self.request.POST.get('email'),
                    'password': self.request.POST.get('password'),
                    'group_name': group_name}
            check_res(requests.post(self.magpie_url+'/users', data))

        if 'delete' in self.request.POST:
            user_name = self.request.POST.get('user_name')
            #TODO: Magpie needs to remove the group automatically created with the user_name
            check_res(requests.delete(self.magpie_url+'/users/'+ user_name))

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

            data = {'user_name': user_name,
                    'email': self.request.POST.get('email'),
                    'password': self.request.POST.get('password'),
                    'group_name': group_name}
            check_res(requests.post(self.magpie_url + '/users', data))
            return HTTPFound(self.request.route_url('view_users'))

        return add_template_data(self.request)

    @view_config(route_name='edit_user', renderer='templates/edit_user.mako')
    def edit_user(self):
        user_name = self.request.matchdict['user_name']
        own_groups = self.get_user_groups(user_name)

        if 'member' in self.request.POST:
            groups = self.request.POST.getall('member')

            removed_groups = list(set(own_groups) - set(groups))
            new_groups = list(set(groups) - set(own_groups))

            for group in removed_groups:
                check_res(requests.delete(self.magpie_url + '/users/' + user_name + '/groups/' + group))

            for group in new_groups:
                check_res(requests.post(self.magpie_url+'/users/'+user_name+'/groups/'+group))

            own_groups = self.get_user_groups(user_name)

        return add_template_data(self.request,
                                 {'user_name': user_name,
                                  'own_groups': own_groups,
                                  'groups': self.get_groups()})

    @view_config(route_name='view_groups', renderer='templates/view_groups.mako')
    def view_groups(self):
        if 'delete' in self.request.POST:
            group_name = self.request.POST.get('group_name')
            check_res(requests.delete(self.magpie_url+'/groups/'+group_name))

        if 'edit' in self.request.POST:
            group_name = self.request.POST.get('group_name')
            return HTTPFound(self.request.route_url('edit_group', group_name=group_name, cur_svc_type='default'))

        return add_template_data(self.request, {'group_names': self.get_groups()})

    @view_config(route_name='add_group', renderer='templates/add_group.mako')
    def add_group(self):
        if 'create' in self.request.POST:
            group_name = self.request.POST.get('group_name')
            self.create_group(group_name)
            return HTTPFound(self.request.route_url('view_groups'))

        return add_template_data(self.request)

    @view_config(route_name='edit_group', renderer='templates/edit_group.mako')
    def edit_group(self):
        group_name = self.request.matchdict['group_name']
        cur_svc_type = self.request.matchdict['cur_svc_type']

        members = []
        try:
            res_group_users = requests.get(self.magpie_url + '/groups/' + group_name + '/users')
            check_res(res_group_users)
            members = res_group_users.json()['user_names']

            res_svcs = requests.get(self.magpie_url + '/services')
            check_res(res_svcs)
            svc_types = res_svcs.json()['services'].keys()
            if cur_svc_type not in svc_types:
                cur_svc_type = svc_types[0]
        except:
            raise HTTPBadRequest(detail='Bad Json response')

        resources= dict(thredds1=dict(birdhouse=dict(nrcan={'toto.nc': {}})),
                        thredds2=dict(birdhouse=dict(ouranos={'tata.nc': {}},
                                                     cmip5={'pr_daily.nc': {}})),
                        )

        return add_template_data(self.request,
                                 {'group_name': group_name,
                                  'users': self.get_users(),
                                  'members': members,
                                  'svc_types': svc_types,
                                  'cur_svc_type': cur_svc_type,
                                  'resources': resources,
                                  'permissions': ['permission3', 'permission2', 'permission1']})

    @view_config(route_name='view_services', renderer='templates/view_services.mako')
    def view_services(self):

        if 'register' in self.request.POST:
            data = {'service_name': self.request.POST.get('service_name'),
                    'service_url': self.request.POST.get('service_url'),
                    'service_type': self.request.POST.get('service_type')}

            check_res(requests.post(self.magpie_url+'/services', data=data))

        if 'unregister' in self.request.POST:
            service_names = self.request.POST.getall('service_names')
            for service_name in service_names:
                check_res(requests.delete(self.magpie_url+'/services/'+service_name))

        res = requests.get(self.magpie_url + '/services')
        check_res(res)
        service_names = res.json()['services']

        return add_template_data(self.request,
                                 {'service_info_list': service_names,
                                  'service_types': ['wps', 'wms', 'thredds']})

