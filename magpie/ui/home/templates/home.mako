<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
</%block>

<div class="admin-content">
    <a href="${request.route_url('view_users')}" class="admin-button theme">
        <img src="${request.static_url('magpie.ui.home:static/users.png')}" alt="">
        <br>Edit Users
    </a>
    <a href="${request.route_url('view_groups')}" class="admin-button theme">
        <img src="${request.static_url('magpie.ui.home:static/groups.png')}" alt="">
        <br>Edit Groups
    </a>
    <a href="${request.route_url('view_services', cur_svc_type='default')}" class="admin-button theme">
        <img src="${request.static_url('magpie.ui.home:static/services.png')}" alt="">
        <br>Edit Services
    </a>
</div>

