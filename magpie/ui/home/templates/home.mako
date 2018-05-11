<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
</%block>

<div class="admin_content">
    <a href="${request.route_url('view_users')}" class="admin_button">
        <img src="${request.static_url('ui.home:static/users.png')}">
        <br>Edit Users
    </a>
    <a href="${request.route_url('view_groups')}" class="admin_button">
        <img src="${request.static_url('ui.home:static/groups.png')}">
        <br>Edit Groups
    </a>
    <a href="${request.route_url('view_services', cur_svc_type='default')}" class="admin_button">
        <img src="${request.static_url('ui.home:static/services.png')}">
        <br>Edit Services
    </a>
</div>

