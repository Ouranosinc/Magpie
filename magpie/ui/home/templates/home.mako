<%inherit file="home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
</%block>

<div class="admin_links">
    <a href="${request.route_url('view_users')}"><img src="${request.static_url('home:static/users.png')}"><br>Edit Users</a>
    <a href="${request.route_url('view_groups')}"><img src="${request.static_url('home:static/groups.png')}"><br>Edit Groups</a>
    <a href="${request.route_url('view_services', cur_svc_type='default')}"><img src="${request.static_url('home:static/services.png')}"><br>Edit Services</a>
</div>

