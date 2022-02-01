<%inherit file="magpie.ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
<li><a href="${request.route_url('add_service', cur_svc_type=cur_svc_type)}">Add Service</a></li>
</%block>

<h1>Add Service</h1>

<script>
    function updateActiveServiceOptions() {
        let arrayServicesPhoenix = ${services_phoenix_enabled};
        let arrayServicesConfig = ${services_config_enabled};
        let selectedIndex = $("select[id='service_type_select'] option:selected").index();
        let selectedPhoenixEnabled = (arrayServicesPhoenix[selectedIndex] == 1);
        let selectedConfigEnabled = (arrayServicesConfig[selectedIndex] == 1);
        document.getElementById("service_push_phoenix_section").hidden = !selectedPhoenixEnabled;
        document.getElementById("service_configurable_section").hidden = !selectedConfigEnabled;
    }
    $(document).ready(function() {
        updateActiveServiceOptions();
    });
</script>

<form class="new-item-form" id="add_service_form" action="${request.path}" method="post">
    <table class="fields-table">
        <tr>
            <td>Service name:</td>
            <td>
                <div class="input-container">
                    <label>
                        <input type="text" value="${service_name}"
                               name="service_name" class="equal-width" placeholder="service">
                    </label>
                </div>
            </td>
            <td>
                (unique)
            </td>
        </tr>
        <tr>
            <td>Service url:</td>
            <td>
                <div class="input-container">
                    <label>
                        <input type="url" value="${service_url}"
                               name="service_url" class="equal-width"
                               placeholder="http://localhost:8093">
                    </label>
                </div>
            </td>
            <td></td>
        </tr>
        <tr><td>Service type:</td>
            <td>
                <div class="input-container">
                    <label>
                        <select name="service_type" class="equal-width" id="service_type_select"
                                onchange="updateActiveServiceOptions()" required>
                            %for svc_type in service_types:
                                <option value="${svc_type}"
                                %if (service_type or cur_svc_type) == svc_type:
                                    selected
                                %endif
                                >${svc_type}
                                </option>
                            %endfor
                        </select>
                    </label>
                </div>
            </td>
            <td></td>
        </tr>
    </table>
    <table class="fields-table">  <!-- separate table to avoid moving contents in other cells above on resize -->
        <tr id="service_configurable_section">
            <td class="top-align">Configuration:</td>
            <td>
                <div class="input-container input-configuration">
                    <label>
                        <textarea rows="5" cols="1" value="" name="service_config" class="equal-width" placeholder="{}"
                        >${service_config}</textarea>  <!-- spacing is important -->
                    </label>
                </div>
            </td>
            <td class="top-align">
                <div>
                    (JSON)
                </div>
                %if invalid_config:
                    <div class="service-config-error">
                        <img src="${request.static_url('magpie.ui.home:static/exclamation-circle.png')}"
                             alt="ERROR" class="icon-error" />
                        <div class="alert-form-text alert-form-text-error">
                            Invalid
                        </div>
                    </div>
                %endif
            </td>
        </tr>
    </table>
    <table class="fields-table">
        <tr id="service_push_phoenix_section">
            <td>Push to Phoenix:</td>
            <td>
                <div class="input-container">
                    <label>
                        <input type="checkbox" name="service_push" checked id="service_push_phoenix_checkbox">
                    </label>
                </div>
            </td>
            <td></td>
        </tr>
    </table>
    <div class="service-button">
        <input type="submit" value="Add Service" name="register" class="button theme">
    </div>
</form>
