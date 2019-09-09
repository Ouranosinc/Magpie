<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
<li><a href="${request.route_url('add_service', cur_svc_type=cur_svc_type)}">Add Service</a></li>
</%block>

<h1>Add Service</h1>

<script>
    function updatePushPhoenixOption() {
        var arraySevicesPhoenix = ${services_phoenix_indices};
        var selectedIndex = $("select[id='service_type_select'] option:selected").index();
        var selectedEnable = (arraySevicesPhoenix[selectedIndex] == 1);
        document.getElementById("service_push_phoenix_section").hidden = !selectedEnable;
    }
    $( document ).ready(function() {
        updatePushPhoenixOption();
    });
</script>

<form class="new_item_form" id="add_service_form" action="${request.path}" method="post">
    <table class="fields_table">
        <tr>
            <td>Service name (unique):</td>
            <div class="input_container">
                <td><input type="text" name="service_name" value="${form_service_name}" class="equal_width" placeholder="emu"></td>
            </div>
            %if invalid_service_name:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" /> Invalid </p>
                </td>
            %endif
        </tr>
        <tr>
            <td>Service url:</td>
            <div class="input_container">
                <td><input type="text" name="service_url" value="${form_service_url}" class="equal_width" placeholder="http://localhost:8093"></td>
            </div>
            %if invalid_service_url:
                <td><p class="alert_form_error">
                    <img src="${request.static_url('magpie.ui.home:static/warning_exclamation.png')}" /> Invalid </p>
                </td>
            %endif
        </tr>
        <tr><td>Service type:</td>
            <div class="input_container">
                <td><select name="service_type" class="equal_width" id="service_type_select"
                            onchange="updatePushPhoenixOption()">
                    %for service_type in service_types:
                        <option value="${service_type}">${service_type}</option>
                    %endfor
                </td>
            </div>
        </tr>
        <tr id="service_push_phoenix_section">
            <td>Push to Phoenix:</td>
            <div class="input_container">
                <td><input type="checkbox" name="service_push" checked id="service_push_phoenix_checkbox"></td>
            </div>
        </tr>
        <tr><td class="centered" colspan="2"><input type="submit" value="Register" name="register"></td></tr>
    </table>
</form>
