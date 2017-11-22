<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
<li><a href="${request.route_url('view_services', cur_svc_type=cur_svc_type)}">Services</a></li>
</%block>

%for service in service_names:
    <div class="alert danger" id="ViewService_DeleteAlert_${service}">
        <h3 class="alert_title danger">Danger!</h3>
        <p>
            Delete: [${service}]
        </p>
        <p>
            This operation will remove the service and all its sub-resources.
            This operation is not reversible.
        </p>
        <p>Continue?</p>
        <form action="${request.path}" method="post">
            <input type="hidden" value=${service} name="service_name">
            <div class="checkbox_align">
                <label for="push_phoenix_checkbox">
                    <input type="checkbox" name="service_push" checked="true" id="push_phoenix_checkbox"/>
                    <span>Push to Phoenix?</span>
                </label>
            </div>
            <div>
                <input type="submit" class="button delete" name="delete" value="Delete"
                       onclick="this.parentElement.style.display='none';" >
                <input type="submit" class="button cancel" name="cancel" value="Cancel"
                       onclick="this.parentElement.style.display='none';" >
            </div>
        </form>
    </div>

    <script>
        function display_DeleteAlert_${service}() {
            %for sub_service in service_names:
                %if service == sub_service:
                    document.getElementById("ViewService_DeleteAlert_${sub_service}").style.display = "block";
                %else:
                    document.getElementById("ViewService_DeleteAlert_${sub_service}").style.display = "none";
                %endif
            %endfor
        }
    </script>
%endfor

<h1>Services</h1>

<button class="img_button" type="button" onclick="location.href='${request.route_url('add_service', cur_svc_type=cur_svc_type)}'">
    <img src="${request.static_url('ui.home:static/add.png')}">
    Add Service
</button>

<div class="tabs_panel">

    %for svc_type in svc_types:
        % if cur_svc_type == svc_type:
            <a class="current_tab" href="${request.route_url('view_services', cur_svc_type=svc_type)}">${svc_type}</a>
        % else:
            <a class="tab" href="${request.route_url('view_services', cur_svc_type=svc_type)}">${svc_type}</a>
        % endif
    %endfor

    <div class="current_tab_panel">
        <table class="simple_list_table">

            <tr>
                <th>Services</th>
                <th>Action</th>
            </tr>
            %for service in service_names:
                <form action="${request.path}" method="post">
                    <tr>
                        <td>
                            <input type="hidden" value=${service} name="service_name">${service}
                        </td>
                        <td style="white-space: nowrap">
                            <input type="submit" value="Edit" name="edit">
                            <input type="button" value="Delete" onclick="display_DeleteAlert_${service}()" class="button delete">
                        </td>
                    </tr>
                </form>
            %endfor
        </table>
    </div>
</div>



