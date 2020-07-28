<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
<li><a href="${request.route_url('add_service', cur_svc_type=cur_svc_type)}">Add Service</a></li>
</%block>

<h1>Add Service</h1>

<script>
    function updatePushPhoenixOption() {
        let arrayServicesPhoenix = ${services_phoenix_indices};
        let selectedIndex = $("select[id='service_type_select'] option:selected").index();
        let selectedEnable = (arrayServicesPhoenix[selectedIndex] == 1);
        document.getElementById("service_push_phoenix_section").hidden = !selectedEnable;
    }
    $( document ).ready(function() {
        updatePushPhoenixOption();
    });
</script>

<form class="new-item-form" id="add_service_form" action="${request.path}" method="post">
    <table class="fields-table">
        <tr>
            <td>Service name (unique):</td>
            <td>
                <div class="input-container"><label>
                <input type="text" value="" name="service_name" class="equal-width" placeholder="emu">
                </label></div>
            </td>
        </tr>
        <tr>
            <td>Service url:</td>
            <td>
                <div class="input-container"><label>
                    <input type="text" value="" name="service_url" class="equal-width"
                           placeholder="http://localhost:8093">
                </label></div>
            </td>
        </tr>
        <tr><td>Service type:</td>
            <td>
                <div class="input-container">
                <label>
                <select name="service_type" class="equal-width" id="service_type_select"
                            onchange="updatePushPhoenixOption()">
                    %for service_type in service_types:
                        <option value="${service_type}">${service_type}</option>
                    %endfor
                 </select>
                </label>
                </div>
            </td>
        </tr>
        <tr id="service_push_phoenix_section">
            <td>Push to Phoenix:</td>
            <td>
                <div class="input-container"><label>
                    <input type="checkbox" name="service_push" checked id="service_push_phoenix_checkbox">
                </label></div>
            </td>
        </tr>
        <tr>
            <td class="centered" colspan="2">
                <input type="submit" value="Add Service" name="register" class="button theme">
            </td>
        </tr>
    </table>
</form>
