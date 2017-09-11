<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
<li><a href="${request.route_url('edit_service', service_name=service_name, cur_svc_type=cur_svc_type)}">Service ${service_name}</a></li>
<li><a href="${request.route_url('add_resource', service_name=service_name, cur_svc_type=cur_svc_type, resource_id=resource_id)}">Add Resource</a></li>
</%block>

<h1>New Resource</h1>


<form action="${request.path}" method="post">
    resource name: <input type="text" value="" name="resource_name">
    </br>
    resource type: <input type="text" value="" name="resource_type">
    </br>
    <input type="submit" value="Add" name="add_child">
</form>

