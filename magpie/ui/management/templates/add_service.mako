<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
<li><a href="${request.route_url('add_service', cur_svc_type=cur_svc_type)}">Add Service</a></li>
</%block>

<h1>Add Service</h1>

<form class="new_item_form" action="${request.path}" method="post">
    <table class="fields_table">
        <tr>
            <td>Service name (unique):</td>
            <td><input type="text" value="" name="service_name" placeholder="emu"></td>
        </tr>
        <tr>
            <td>Service url:</td>
            <td><input type="text" value="" name="service_url" placeholder="http://localhost:8093"></td>
        </tr>
        <tr><td>Service type:</td></tr>
        <tr><td class="centered" colspan="2">
            %for service_type in service_types:
                <input type="radio" name="service_type" value="${service_type}"> ${service_type}
            %endfor
        </td></tr>
        <tr><td class="centered" colspan="2"><input type="submit" value="Register" name="register"></td></tr>
    </table>
</form>
