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
            <div class="input_container">
                <td><input type="text" value="" name="service_name" class="equal_width" placeholder="emu"></td>
            </div>
        </tr>
        <tr>
            <td>Service url:</td>
            <div class="input_container">
                <td><input type="text" value="" name="service_url" class="equal_width" placeholder="http://localhost:8093"></td>
            </div>
        </tr>
        <tr><td>Service type:</td>
            <div class="input_container">
                <td><select name="service_type" class="equal_width">
                    %for service_type in service_types:
                        <option value="${service_type}">${service_type}</option>
                    %endfor
                </td>
            </div>
        </tr>
        <tr>
            <td>Push to Phoenix:</td>
            <div class="input_container">
                <td><input type="checkbox" name="service_push" checked></td>
            </div>
        </tr>
        <tr><td class="centered" colspan="2"><input type="submit" value="Register" name="register"></td></tr>
    </table>
</form>
